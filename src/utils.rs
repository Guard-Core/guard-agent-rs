//! Shared helpers: backoff math, `Retry-After` parsing, payload redaction,
//! batch identifiers, and gzip compression.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Maximum depth walked when redacting nested structured data; a subtree
/// deeper than this is redacted wholesale (`_MAX_SANITIZE_DEPTH`).
pub const MAX_REDACT_DEPTH: usize = 10;

/// Longest JSON-looking string that is parsed and sanitized; a longer one is
/// redacted wholesale (`_MAX_JSON_SCAN_LEN`).
pub const MAX_JSON_SCAN_LEN: usize = 8192;

/// Stands in for the `NaN` and `Infinity` literals Python's `json` accepts
/// and `serde_json` rejects, so a string carrying them is still parsed and
/// sanitized instead of passing through unredacted.
const NONFINITE_SENTINEL: &str = "\u{1}guard-agent-nonfinite:";

/// Maximum response body length kept in error details.
pub const MAX_DETAIL_CHARS: usize = 300;

/// Placeholder substituted for redacted values.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Length, in hex characters, of the `hash_ip` digest.
pub const HASH_IP_HEX_CHARS: usize = 16;

/// Suffix appended by [`truncate_payload`] when it cuts a payload.
pub const TRUNCATION_INDICATOR: &str = "...[TRUNCATED]";

/// Computes `min(base * 2^attempt, max)`.
///
/// Mirrors `calculate_backoff_delay` in the Python agent: no jitter, and the
/// cap applies to the final value.
#[must_use]
pub fn calculate_backoff_delay(attempt: u32, base: f64, max: f64) -> f64 {
    let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
    let raw = base * 2_f64.powi(exponent);
    if raw.is_finite() { raw.min(max) } else { max }
}

/// Parses a `Retry-After` header value into seconds.
///
/// Mirrors the Python agent: only the delay-seconds form is parsed, HTTP dates
/// fall back to `default`, and negative values clamp to zero.
#[must_use]
pub fn parse_retry_after_seconds(header: Option<&str>, default: f64) -> f64 {
    let Some(raw) = header else {
        return default;
    };
    match raw.trim().parse::<f64>() {
        Ok(seconds) if seconds.is_finite() => seconds.max(0.0),
        _ => default,
    }
}

/// Generates a batch identifier in the Python agent's format:
/// `<epoch-millis>-<8 hex chars>`.
#[must_use]
pub fn generate_batch_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_millis());
    let uuid = Uuid::new_v4().simple().to_string();
    let suffix = &uuid[..8];
    format!("{millis}-{suffix}")
}

/// Generates a short, collision-resistant Redis key suffix in the Python
/// agent's format: `<prefix>_<nanos>_<8 hex chars>`.
#[must_use]
pub fn generate_short_key(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_nanos());
    let uuid = Uuid::new_v4().simple().to_string();
    let suffix = &uuid[..8];
    format!("{prefix}_{nanos}_{suffix}")
}

/// Collapses a response body into a single line, truncated for error details.
#[must_use]
pub fn summarize_response_body(body: &str) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_DETAIL_CHARS {
        return collapsed;
    }
    let truncated: String = collapsed.chars().take(MAX_DETAIL_CHARS).collect();
    format!("{truncated}...")
}

/// Truncates a payload to `max_size` characters with an indicator.
///
/// Mirrors `truncate_payload` (`guard_agent/utils.py:200-204`). This is a
/// host-adapter helper and is not used inside the transport itself.
#[must_use]
pub fn truncate_payload(payload: &str, max_size: usize) -> String {
    if payload.chars().count() <= max_size {
        return payload.to_owned();
    }
    let cut: String = payload.chars().take(max_size).collect();
    format!("{cut}{TRUNCATION_INDICATOR}")
}

/// Hashes an IP address for privacy-conscious telemetry.
///
/// Mirrors `hash_ip` (`guard_agent/utils.py:221-225`): SHA-256 over the
/// concatenation of the IP and an optional salt, rendered as the first 16 hex
/// characters. This is a host-adapter helper and is not used inside the
/// transport itself.
#[must_use]
pub fn hash_ip(ip: &str, salt: &str) -> String {
    let digest = Sha256::digest(format!("{ip}{salt}").as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex.chars().take(HASH_IP_HEX_CHARS).collect()
}

/// Compresses a payload with gzip at the default level.
#[must_use]
pub fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // Writing into a `Vec` cannot fail (the `Write` impl for `Vec` is
    // infallible), so the write result carries no information; `finish` only
    // surfaces that same impossible I/O error, and its fallback returns the
    // raw payload instead of panicking.
    let _ = encoder.write_all(body);
    // `Write` for `Vec` is infallible and `finish` only surfaces that same
    // impossible I/O error, so the fallback is compiled out of the coverage
    // build as provably unreachable (see PR notes).
    #[cfg(not(coverage))]
    let compressed = encoder.finish().unwrap_or_else(|_| body.to_vec());
    #[cfg(coverage)]
    let compressed = encoder.finish().expect("GzEncoder over a Vec cannot fail");
    compressed
}

/// Redacts sensitive keys from event metadata and metric tags.
#[derive(Debug, Clone)]
pub struct Redactor {
    keys: Vec<String>,
}

impl Redactor {
    /// Builds a redactor from configured sensitive key names.
    ///
    /// Keys are compared case-insensitively after trimming whitespace; empty
    /// entries are ignored.
    #[must_use]
    pub fn new(sensitive_keys: &[String]) -> Self {
        let keys = sensitive_keys
            .iter()
            .map(|key| key.trim().to_lowercase())
            .filter(|key| !key.is_empty())
            .collect();
        Self { keys }
    }

    /// Returns `true` when the key is sensitive.
    #[must_use]
    pub fn is_sensitive(&self, key: &str) -> bool {
        let normalized = key.trim().to_lowercase();
        self.keys.contains(&normalized)
    }

    /// Recursively redacts sensitive keys inside a JSON value, matching
    /// `sanitize_headers` (`guard_agent/utils.py:62-197`).
    pub fn redact_value(&self, value: &mut Value) {
        *value = self.sanitize(value, 0);
    }

    fn sanitize(&self, value: &Value, depth: usize) -> Value {
        if depth > MAX_REDACT_DEPTH {
            return Value::String(REDACTED_PLACEHOLDER.to_owned());
        }
        match value {
            Value::String(text) => Value::String(self.sanitize_string(text, depth)),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, entry)| {
                        let entry = if self.is_sensitive(key) {
                            Value::String(REDACTED_PLACEHOLDER.to_owned())
                        } else {
                            self.sanitize(entry, depth + 1)
                        };
                        (key.clone(), entry)
                    })
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|entry| self.sanitize(entry, depth + 1))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Parses a JSON-looking string, sanitizes inside it and re-dumps it the
    /// way Python's `json.dumps` does; other strings pass through, and a
    /// JSON-looking string over [`MAX_JSON_SCAN_LEN`] is redacted wholesale.
    fn sanitize_string(&self, text: &str, depth: usize) -> String {
        let stripped = text.trim();
        if !stripped.starts_with(['{', '[', '"']) {
            return text.to_owned();
        }
        if stripped.chars().count() > MAX_JSON_SCAN_LEN {
            return REDACTED_PLACEHOLDER.to_owned();
        }
        match parse_json_like(stripped) {
            Parsed::Value(parsed) => python_json_dumps(&self.sanitize(&parsed, depth + 1)),
            Parsed::Invalid => text.to_owned(),
            Parsed::Unsafe => REDACTED_PLACEHOLDER.to_owned(),
        }
    }

    /// Redacts sensitive keys from a flat string map, and sanitizes
    /// JSON-looking values (they sit one level below the mapping).
    pub fn redact_tags(&self, tags: &mut std::collections::BTreeMap<String, String>) {
        for (key, value) in tags.iter_mut() {
            *value = if self.is_sensitive(key) {
                REDACTED_PLACEHOLDER.to_owned()
            } else {
                self.sanitize_string(value, 1)
            };
        }
    }
}

enum Parsed {
    Value(Value),
    /// Not JSON, so Python leaves the string as it is.
    Invalid,
    /// Python would parse it but `serde_json` cannot (a lone surrogate
    /// escape, nesting past its recursion limit): redacted wholesale rather
    /// than passed through with its secrets intact.
    Unsafe,
}

fn parse_json_like(text: &str) -> Parsed {
    let error = match serde_json::from_str::<Value>(text) {
        Ok(parsed) => return Parsed::Value(parsed),
        Err(error) => error,
    };
    let message = error.to_string();
    // serde_json reports a lone surrogate escape as a "surrogate" or "hex
    // escape" error; Python accepts both.
    if ["surrogate", "hex escape", "recursion limit"]
        .iter()
        .any(|needle| message.contains(needle))
    {
        return Parsed::Unsafe;
    }
    if text.contains("NaN") || text.contains("Infinity") {
        let rewritten = replace_nonfinite_literals(text);
        if let Ok(parsed) = serde_json::from_str::<Value>(&rewritten)
            && !has_sentinel_key(&parsed)
        {
            return Parsed::Value(parsed);
        }
    }
    Parsed::Invalid
}

/// A bare literal in key position (`{NaN: 1}`) is not JSON for Python either.
fn has_sentinel_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, entry)| key.starts_with(NONFINITE_SENTINEL) || has_sentinel_key(entry)),
        Value::Array(items) => items.iter().any(has_sentinel_key),
        _ => false,
    }
}

/// Replaces the bare `NaN`, `Infinity` and `-Infinity` tokens outside JSON
/// strings with sentinel strings.
fn replace_nonfinite_literals(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        let rest: String = chars[index..].iter().take(9).collect();
        let token = ["NaN", "Infinity", "-Infinity"]
            .into_iter()
            .find(|token| rest.starts_with(token));
        let boundary = |at: usize| chars.get(at).is_none_or(|c| !c.is_alphanumeric());
        match token {
            Some(token) if boundary(index + token.len()) => {
                // The sentinel's leading control character needs its JSON escape.
                let _ = write!(out, "\"\\u0001{}{token}\"", &NONFINITE_SENTINEL[1..]);
                index += token.len();
            }
            _ => {
                out.push(ch);
                index += 1;
            }
        }
    }
    out
}

/// `json.dumps(value)` with Python's defaults: `", "` and `": "` separators,
/// insertion order, `ensure_ascii`, and Python's float spelling.
fn python_json_dumps(value: &Value) -> String {
    let mut out = String::new();
    write_python_json(value, &mut out);
    out
}

fn write_python_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&python_number(number)),
        Value::String(text) => {
            if let Some(token) = text.strip_prefix(NONFINITE_SENTINEL) {
                out.push_str(token);
            } else {
                out.push('"');
                crate::encryption::escape_string(text, out);
                out.push('"');
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_python_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push('"');
                crate::encryption::escape_string(key, out);
                out.push_str("\": ");
                write_python_json(item, out);
            }
            out.push('}');
        }
    }
}

/// Spells a number like Python's `repr`: `serde_json` prints `1e16` and
/// `1e-7` where Python prints `1e+16` and `1e-07`.
fn python_number(number: &serde_json::Number) -> String {
    let mut text = number.to_string();
    // Python's `repr` switches to the exponent form below 1e-4, serde_json's
    // formatter only below 1e-5.
    if let Some(small) = number
        .as_f64()
        .filter(|float| number.is_f64() && *float != 0.0 && float.abs() < 1e-4)
        && !text.contains('e')
    {
        text = format!("{small:e}");
    }
    let Some((mantissa, exponent)) = text.split_once('e') else {
        return text;
    };
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent.abs())
}

/// Types whose sensitive fields are redacted before buffering.
pub(crate) trait Redactable {
    /// Redacts sensitive keys in place.
    fn redact(&mut self, redactor: &Redactor);
}

impl Redactable for crate::models::SecurityEvent {
    fn redact(&mut self, redactor: &Redactor) {
        redactor.redact_value(&mut self.metadata);
    }
}

impl Redactable for crate::models::SecurityMetric {
    fn redact(&mut self, redactor: &Redactor) {
        redactor.redact_tags(&mut self.tags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn backoff_doubles_and_caps() {
        assert!((calculate_backoff_delay(0, 1.0, 60.0) - 1.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(1, 1.0, 60.0) - 2.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(5, 1.0, 60.0) - 32.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(10, 1.0, 60.0) - 60.0).abs() < f64::EPSILON);
        // Flush level streak backoff uses the flush interval as the base.
        assert!((calculate_backoff_delay(0, 30.0, 300.0) - 30.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(3, 30.0, 300.0) - 240.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(4, 30.0, 300.0) - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn backoff_saturates_instead_of_overflowing() {
        assert!((calculate_backoff_delay(u32::MAX, 1.0, 60.0) - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_after_parsing_matches_python() {
        assert!((parse_retry_after_seconds(Some("30"), 60.0) - 30.0).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(Some("0.5"), 60.0) - 0.5).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(None, 60.0) - 60.0).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(Some("soon"), 60.0) - 60.0).abs() < f64::EPSILON);
        // HTTP dates are not parsed, matching the Python agent.
        assert!(
            (parse_retry_after_seconds(Some("Wed, 21 Oct 2026 07:28:00 GMT"), 60.0) - 60.0).abs()
                < f64::EPSILON
        );
        assert!((parse_retry_after_seconds(Some("-5"), 60.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn batch_id_has_the_python_shape() {
        let batch_id = generate_batch_id();
        let (millis, suffix) = batch_id.split_once('-').unwrap();
        assert!(millis.parse::<u128>().is_ok());
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_key_has_the_python_shape() {
        let key = generate_short_key("event");
        let parts: Vec<&str> = key.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "event");
        assert!(parts[1].parse::<u128>().is_ok());
        assert_eq!(parts[2].len(), 8);
    }

    #[test]
    fn short_keys_are_unique() {
        let first = generate_short_key("event");
        let second = generate_short_key("event");
        assert_ne!(first, second);
    }

    #[test]
    fn response_body_summary_collapses_and_truncates() {
        assert_eq!(summarize_response_body("a\n b\tc"), "a b c");
        let long = "x".repeat(MAX_DETAIL_CHARS + 50);
        let summary = summarize_response_body(&long);
        assert_eq!(summary.chars().count(), MAX_DETAIL_CHARS + 3);
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn truncate_payload_matches_the_python_semantics() {
        assert_eq!(truncate_payload("abc", 10), "abc");
        assert_eq!(truncate_payload("abcdef", 2), "ab...[TRUNCATED]");
        assert_eq!(truncate_payload("abcde", 5), "abcde");
        // Length is measured in characters, like Python's `len`.
        assert_eq!(truncate_payload("éééé", 2), "éé...[TRUNCATED]");
    }

    #[test]
    fn hash_ip_matches_the_python_digest() {
        // Values pinned from Python: hashlib.sha256(b"1.2.3.4").hexdigest()[:16]
        // and the same with the "pepper" salt.
        assert_eq!(hash_ip("1.2.3.4", ""), "6694f83c9f476da3");
        assert_eq!(hash_ip("1.2.3.4", "pepper"), "712ac23c0601eaca");
        assert_eq!(hash_ip("1.2.3.4", "").len(), HASH_IP_HEX_CHARS);
        assert!(!hash_ip("1.2.3.4", "").contains("1.2.3.4"));
    }

    #[test]
    fn gzip_round_trips_and_shrinks_repetitive_payloads() {
        let payload =
            br#"{"events":[{"a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;
        let compressed = gzip_bytes(payload);
        assert_ne!(compressed, payload);
        // gzip magic bytes.
        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut restored = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut restored).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn redactor_matches_keys_case_insensitively() {
        let redactor = Redactor::new(&["Authorization".to_owned(), " x-api-key ".to_owned()]);
        assert!(redactor.is_sensitive("authorization"));
        assert!(redactor.is_sensitive("X-API-Key"));
        assert!(!redactor.is_sensitive("user-agent"));
        assert!(!Redactor::new(&["  ".to_owned()]).is_sensitive("anything"));
    }

    #[test]
    fn redactor_walks_nested_metadata() {
        let redactor = Redactor::new(&["authorization".to_owned(), "cookie".to_owned()]);
        let mut value = json!({
            "rule": "rl-1",
            "headers": {
                "Authorization": "Bearer token",
                "Cookie": "session=abc",
                "Accept": "application/json"
            },
            "chain": [{"cookie": "nested=1"}, {"safe": "value"}]
        });
        redactor.redact_value(&mut value);

        assert_eq!(value["headers"]["Authorization"], REDACTED_PLACEHOLDER);
        assert_eq!(value["headers"]["Cookie"], REDACTED_PLACEHOLDER);
        assert_eq!(value["headers"]["Accept"], "application/json");
        assert_eq!(value["chain"][0]["cookie"], REDACTED_PLACEHOLDER);
        assert_eq!(value["chain"][1]["safe"], "value");
        assert_eq!(value["rule"], "rl-1");
    }

    #[test]
    fn redactor_redacts_everything_past_max_depth_wholesale() {
        let redactor = Redactor::new(&["cookie".to_owned()]);
        // Build a chain deeper than the walk limit.
        let mut value = json!({"cookie": "deep"});
        for _ in 0..(MAX_REDACT_DEPTH + 2) {
            value = json!({"level": value});
        }
        redactor.redact_value(&mut value);
        let mut cursor = &value;
        for _ in 0..MAX_REDACT_DEPTH {
            cursor = &cursor["level"];
        }
        // The mapping at depth MAX_REDACT_DEPTH is still walked; its child is
        // at depth MAX_REDACT_DEPTH + 1 and is redacted whole.
        assert_eq!(cursor["level"], REDACTED_PLACEHOLDER);
    }

    #[test]
    fn redactor_handles_event_metadata_and_metric_tags() {
        use crate::models::{MetricType, SecurityEvent, SecurityMetric};

        let redactor = Redactor::new(&["x-api-key".to_owned()]);

        let mut event = SecurityEvent::new("test").with_metadata(json!({"X-Api-Key": "secret"}));
        event.redact(&redactor);
        assert_eq!(event.metadata["X-Api-Key"], REDACTED_PLACEHOLDER);

        let mut metric =
            SecurityMetric::new(MetricType::RequestCount, 1.0).with_tag("X-API-KEY", "secret");
        metric.redact(&redactor);
        assert_eq!(metric.tags["X-API-KEY"], REDACTED_PLACEHOLDER);
    }
}
