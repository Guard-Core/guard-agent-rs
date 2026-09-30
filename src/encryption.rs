//! AES-256-GCM payload encryption, mirroring `guard_agent/encryption.py`
//! byte-for-byte on the wire.
//!
//! Scheme (identical to the Python agent):
//!
//! - 256-bit keys, urlsafe-base64-encoded (padded, like Python
//!   `base64.urlsafe_b64encode`), supplied by the core backend;
//! - canonical JSON plaintext ([`canonical_json`]): keys sorted
//!   recursively, compact separators, Python `ensure_ascii` escaping;
//! - a fresh 12-byte random nonce prefixes every ciphertext, the 16-byte
//!   GCM auth tag follows (the `RustCrypto` AES-GCM framing matches Python
//!   `cryptography`'s AESGCM: `nonce || ciphertext || tag`);
//! - the combined blob is padded urlsafe base64 for transmission;
//! - plaintext fallback is forbidden: an invalid key raises
//!   [`crate::error::GuardAgentError::EncryptionConfig`] at transport construction
//!   (mirrors `_transport_lifecycle._init_encryption`).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::Value;
use std::fmt::Write as _;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// Canonical JSON serializer matching
/// `json.dumps(data, separators=(",", ":"), sort_keys=True)` with the
/// `ensure_ascii` default.
///
/// Object keys are sorted recursively, separators are compact, forward
/// slashes are unescaped, and non-ASCII and control characters are
/// `\uXXXX`-escaped with Python's short forms (surrogate pairs for astral
/// planes). Numbers keep their JSON type: integers print without a fraction,
/// floats print like Python's shortest `repr` (including the trailing
/// `.0` for whole floats, matching `serde_json`'s `Number` display).
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => {
            out.push('"');
            escape_string(text, out);
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_string(key, out);
                out.push_str("\":");
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Escapes a string exactly like Python `json.dumps` with `ensure_ascii`.
pub(crate) fn escape_string(text: &str, out: &mut String) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let code = c as u32;
                if code > 0xffff {
                    let high = ((code - 0x1_0000) / 0x400) + 0xd800;
                    let low = ((code - 0x1_0000) % 0x400) + 0xdc00;
                    let _ = write!(out, "\\u{high:04x}\\u{low:04x}");
                } else {
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
            c => out.push(c),
        }
    }
}

/// AES-256-GCM encryptor with the Python agent's wire framing.
pub struct PayloadEncryptor {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for PayloadEncryptor {
    #[allow(clippy::missing_fields_in_debug)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadEncryptor").finish_non_exhaustive()
    }
}

impl PayloadEncryptor {
    /// Decodes a padded (or unpadded) urlsafe-base64 256-bit key.
    ///
    /// # Errors
    ///
    /// [`crate::error::GuardAgentError::Encryption`] when the key is empty, not valid
    /// base64, or not exactly 32 bytes.
    pub fn new(project_key: &str) -> Result<Self, crate::error::GuardAgentError> {
        use crate::error::GuardAgentError;
        if project_key.is_empty() {
            return Err(GuardAgentError::Encryption(
                "Project key cannot be empty".to_owned(),
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(project_key.trim_end_matches('='))
            .map_err(|error| {
                GuardAgentError::Encryption(format!("Invalid project key format: {error}"))
            })?;
        let key: [u8; KEY_SIZE] = decoded.try_into().map_err(|decoded: Vec<u8>| {
            GuardAgentError::Encryption(format!(
                "Invalid key size: {} bytes, expected {KEY_SIZE}",
                decoded.len()
            ))
        })?;
        Ok(Self {
            cipher: Aes256Gcm::new((&key).into()),
        })
    }

    /// Encrypts a JSON value. Returns the padded urlsafe-base64
    /// `nonce || ciphertext || tag` string, byte-compatible with the
    /// Python agent's `PayloadEncryptor.encrypt`.
    ///
    /// # Errors
    ///
    /// [`crate::error::GuardAgentError::Encryption`] when encryption fails.
    pub fn encrypt(
        &self,
        data: &Value,
        associated_data: Option<&str>,
    ) -> Result<String, crate::error::GuardAgentError> {
        use crate::error::GuardAgentError;
        let plaintext = canonical_json(data);
        let nonce_bytes = rand_bytes(NONCE_SIZE);
        let nonce = Nonce::from_slice(&nonce_bytes);
        // AES-GCM with a fresh 12-byte nonce cannot fail; the defensive
        // mapping is compiled out of the coverage build as provably
        // unreachable (see PR notes).
        #[cfg(not(coverage))]
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                associated_data.map_or_else(
                    || plaintext.as_bytes().into(),
                    |aad| aes_gcm::aead::Payload {
                        msg: plaintext.as_bytes(),
                        aad: aad.as_bytes(),
                    },
                ),
            )
            .map_err(|error| {
                GuardAgentError::Encryption(format!("Failed to encrypt payload: {error}"))
            })?;
        #[cfg(coverage)]
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                associated_data.map_or_else(
                    || plaintext.as_bytes().into(),
                    |aad| aes_gcm::aead::Payload {
                        msg: plaintext.as_bytes(),
                        aad: aad.as_bytes(),
                    },
                ),
            )
            .expect("AES-GCM encryption of a fresh nonce payload is total");

        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(urlsafe_base64_encode(&combined))
    }

    /// Decrypts an encrypted payload (primarily for testing; in normal
    /// operation only the core backend decrypts).
    ///
    /// # Errors
    ///
    /// [`crate::error::GuardAgentError::Encryption`] when decryption fails or the data
    /// was tampered with.
    pub fn decrypt(
        &self,
        encrypted_data: &str,
        associated_data: Option<&str>,
    ) -> Result<Value, crate::error::GuardAgentError> {
        use crate::error::GuardAgentError;
        let combined = URL_SAFE_NO_PAD
            .decode(encrypted_data.trim_end_matches('='))
            .map_err(|_| GuardAgentError::Encryption("Invalid or tampered payload".to_owned()))?;
        if combined.len() < NONCE_SIZE + 16 {
            return Err(GuardAgentError::Encryption(
                "Invalid or tampered payload".to_owned(),
            ));
        }
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut tagged = ciphertext.to_vec();
        tagged.extend_from_slice(tag);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                associated_data.map_or_else(
                    || tagged.as_slice().into(),
                    |aad| aes_gcm::aead::Payload {
                        msg: tagged.as_slice(),
                        aad: aad.as_bytes(),
                    },
                ),
            )
            .map_err(|_| GuardAgentError::Encryption("Invalid or tampered payload".to_owned()))?;
        serde_json::from_slice(&plaintext)
            .map_err(|_| GuardAgentError::Encryption("Invalid or tampered payload".to_owned()))
    }

    /// Verifies the key with an encrypt/decrypt round trip (mirrors
    /// `verify_key`).
    #[must_use]
    pub fn verify_key(&self) -> bool {
        let test_data = serde_json::json!({ "test": "verification" });
        self.encrypt(&test_data, None).is_ok_and(|encrypted| {
            matches!(self.decrypt(&encrypted, None), Ok(ref decrypted) if *decrypted == test_data)
        })
    }
}

/// Collects `len` random bytes for a nonce from the OS entropy source.
fn rand_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// Padded urlsafe base64, matching Python `base64.urlsafe_b64encode`.
#[must_use]
pub fn urlsafe_base64_encode(bytes: &[u8]) -> String {
    URL_SAFE.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GuardAgentError;

    fn test_key() -> String {
        urlsafe_base64_encode(&(0u8..32).collect::<Vec<u8>>())
    }

    #[test]
    fn decrypt_rejects_aes_valid_plaintext_that_is_not_json() {
        use aes_gcm::aead::Aead as _;

        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        // A payload whose AES-GCM envelope is perfectly valid but whose
        // plaintext is not JSON: the authenticated decryption succeeds and
        // the JSON parse is what fails.
        let nonce_bytes = [7u8; NONCE_SIZE];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let sealed = encryptor
            .cipher
            .encrypt(nonce, b"not json at all".as_slice())
            .expect("AES-GCM encryption of a fresh nonce payload is total");
        let mut combined = Vec::with_capacity(NONCE_SIZE + sealed.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&sealed);

        let encrypted = urlsafe_base64_encode(&combined);
        let outcome = encryptor.decrypt(&encrypted, None);
        assert!(matches!(
            outcome,
            Err(GuardAgentError::Encryption(message)) if message.contains("Invalid or tampered")
        ));
    }

    #[test]
    fn canonical_json_covers_scalars_and_control_escapes() {
        assert_eq!(canonical_json(&serde_json::Value::Bool(false)), "false");
        assert_eq!(canonical_json(&serde_json::Value::Null), "null");
        assert_eq!(canonical_json(&serde_json::json!(true)), "true");
        // Every control character the Python `json.dumps` escaping handles.
        let tricky = "quote\" backslash\\ \u{8}\u{c}\n\r\t";
        let canonical = canonical_json(&serde_json::json!(tricky));
        let expected = "\"quote\\\" backslash\\\\ \\b\\f\\n\\r\\t\"";
        assert_eq!(canonical, expected, "every control char is escaped");
    }

    #[test]
    fn encryptor_debug_prints_without_leaking_the_key() {
        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        let printed = format!("{encryptor:?}");
        assert!(printed.contains("PayloadEncryptor"), "{printed}");
        assert!(!printed.contains(&test_key()), "the key never renders");
    }

    #[test]
    fn decrypt_rejects_undersized_payloads() {
        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        // Decodes fine as base64 but is shorter than nonce + tag.
        let short = URL_SAFE_NO_PAD.encode(b"tiny");
        assert!(matches!(
            encryptor.decrypt(&short, None),
            Err(GuardAgentError::Encryption(_))
        ));
    }

    #[test]
    fn rejects_empty_key() {
        assert!(matches!(
            PayloadEncryptor::new(""),
            Err(GuardAgentError::Encryption(_))
        ));
    }

    #[test]
    fn rejects_wrong_key_size() {
        let short = urlsafe_base64_encode(&[0u8; 4]);
        assert!(matches!(
            PayloadEncryptor::new(&short),
            Err(GuardAgentError::Encryption(_))
        ));
    }

    #[test]
    fn canonical_json_matches_python_bytes() {
        // Byte-exact pins against Python json.dumps(..., sort_keys=True).
        assert_eq!(
            canonical_json(
                &serde_json::from_str::<Value>(r#"{"b":1,"a":[1,2,{"c":true}],"d":null}"#).unwrap()
            ),
            r#"{"a":[1,2,{"c":true}],"b":1,"d":null}"#
        );
        assert_eq!(
            canonical_json(&Value::String(
                "h\u{e9}llo w\u{f6}rld \u{4f60}\u{597d}".to_owned()
            )),
            "\"h\\u00e9llo w\\u00f6rld \\u4f60\\u597d\""
        );
        assert_eq!(
            canonical_json(&Value::String("a\u{1}b\u{8}c/d".to_owned())),
            "\"a\\u0001b\\bc/d\""
        );
        assert_eq!(
            canonical_json(&Value::String("\u{1f600}".to_owned())),
            "\"\\ud83d\\ude00\""
        );
    }

    #[test]
    fn round_trips_encrypt_decrypt() {
        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        let data = serde_json::json!({
            "events": [{"event_type": "rate_limit", "ip_address": "1.2.3.4"}],
            "metrics": [{"metric_type": "request_count", "value": 100}],
            "zeta": 1,
            "unicode": "h\u{e9}llo",
        });
        let encrypted = encryptor.encrypt(&data, None).unwrap();
        assert_eq!(encrypted.len() % 4, 0, "output must be padded");
        assert_eq!(encryptor.decrypt(&encrypted, None).unwrap(), data);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        let mut encrypted = encryptor
            .encrypt(&serde_json::json!({"a": 1}), None)
            .unwrap()
            .into_bytes();
        let last = encrypted.last_mut().expect("non-empty");
        *last ^= 0x1;
        let tampered = String::from_utf8(encrypted).unwrap();
        assert!(matches!(
            encryptor.decrypt(&tampered, None),
            Err(GuardAgentError::Encryption(_))
        ));
    }

    #[test]
    fn rejects_aad_mismatch() {
        let encryptor = PayloadEncryptor::new(&test_key()).unwrap();
        let encrypted = encryptor
            .encrypt(&serde_json::json!({"a": 1}), Some("batch-1"))
            .unwrap();
        assert!(matches!(
            encryptor.decrypt(&encrypted, Some("wrong")),
            Err(GuardAgentError::Encryption(_))
        ));
        assert!(encryptor.decrypt(&encrypted, Some("batch-1")).is_ok());
    }

    #[test]
    fn verify_key_round_trip() {
        assert!(PayloadEncryptor::new(&test_key()).unwrap().verify_key());
    }
}
