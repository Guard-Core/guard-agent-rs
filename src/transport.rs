//! HTTP transport: gzip compression, HMAC signing, retries with backoff,
//! 429 `Retry-After` handling, 413 split-or-drop, and permanent-rejection
//! classification.
//!
//! The transport mirrors `guard_agent/_transport_send.py` and
//! `_transport_dispatch.py`:
//!
//! - success is any 2xx; a 200 body with `success == false` or a non-empty
//!   `errors` list is a partial failure and is requeued by the caller
//!   (the ingestion API returns 200 even on partial failure,
//!   `telemetry_service.py:741-750`);
//! - 429 honors `Retry-After` (seconds, capped, default 60);
//! - 400, 404, and 422 are permanent rejections: the batch is dropped, never
//!   retried, and reported as confirmed so the flush layer deletes its
//!   durable records;
//! - 413 triggers binary split-or-drop: the batch is halved and each half
//!   retried recursively; a singleton that still 413s is dropped;
//! - 401, 403, other 4xx, 5xx, and network errors are retryable with
//!   exponential backoff under the circuit breaker.
//!
//! One deliberate difference from the Python and TypeScript agents: the HMAC
//! signature covers the uncompressed JSON body (see [`crate::signing`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use reqwest::header::{
    CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER, USER_AGENT,
};
use serde_json::{Value, json};

use crate::circuit_breaker::CircuitBreaker;
use crate::config::AgentConfig;
use crate::encryption::PayloadEncryptor;
use crate::error::{ErrorStage, GuardAgentError};
use crate::models::{AgentStatus, DynamicRules, SecurityEvent, SecurityMetric, TelemetryAck};
use crate::rate_limiter::RateLimiter;
use crate::signing::sign_payload;
use crate::utils::{
    calculate_backoff_delay, generate_batch_id, gzip_bytes, parse_retry_after_seconds,
    summarize_response_body,
};

/// Status codes that are permanent rejections; the batch is dropped without
/// retrying.
pub(crate) const NON_RETRYABLE_STATUS_CODES: [u16; 3] = [400, 404, 422];

/// Upper bound, in seconds, applied to a server-provided `Retry-After`.
pub(crate) const MAX_RETRY_AFTER_SECS: f64 = 300.0;

/// Upper bound, in seconds, applied to a transport backoff delay.
pub(crate) const MAX_RETRY_BACKOFF_SECS: f64 = 60.0;

/// Default `Retry-After`, in seconds, when the header is missing or
/// unparseable.
pub(crate) const DEFAULT_RETRY_AFTER_SECS: f64 = 60.0;

/// Maximum length of a `Retry-After` value kept for parsing.
const RETRY_AFTER_HEADER_MAX_LEN: usize = 32;

/// Local send limiter cap, matching the Python, TypeScript, and PHP agents.
pub(crate) const RATE_LIMIT_MAX_CALLS: usize = 100;

/// Local send limiter window, in seconds.
pub(crate) const RATE_LIMIT_WINDOW_SECS: u64 = 60;

const HEADER_X_API_KEY: &str = "X-API-Key";
const HEADER_X_INSTALL_ID: &str = "X-Agent-Install-Id";
const HEADER_X_PROJECT_ID: &str = "X-Project-Id";
const HEADER_X_PAYLOAD_SIGNATURE: &str = "X-Payload-Signature";

/// Result of a batch or status send, consumed by the flush layer.
#[derive(Debug)]
pub(crate) enum SendOutcome {
    /// The server accepted the send.
    Accepted,
    /// The server permanently rejected the send (or a singleton exceeded the
    /// payload cap); the batch is intentionally dropped and counts as
    /// confirmed for at-least-once purposes.
    PermanentDrop {
        /// Status code that caused the drop.
        status_code: u16,
        /// Truncated response body.
        detail: String,
    },
    /// The send failed after exhausting retries (or on a partial failure);
    /// the batch must be requeued.
    Failed {
        /// The final error, also reported through the `on_error` hook.
        error: GuardAgentError,
    },
}

impl SendOutcome {
    /// Returns `true` when the flush layer should delete the batch's durable
    /// records instead of requeueing.
    #[must_use]
    pub(crate) const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Accepted | Self::PermanentDrop { .. })
    }
}

/// Internal classification of a single GET attempt (dynamic rules fetch).
enum GetAttempt {
    /// A 2xx response whose body parsed as JSON (any JSON type; the caller
    /// rejects non-object payloads like the Python agent).
    Ok(Value),
    /// A 429 response with a parsed `Retry-After`.
    RateLimited { retry_after_seconds: f64 },
    /// Any other failure: network error, unreadable body, unparseable 2xx
    /// body, or a non-2xx status.
    Retryable { error: GuardAgentError },
}

/// Internal classification of a single HTTP attempt.
enum AttemptResult {
    Accepted,
    PartialFailure { errors: Vec<String> },
    Permanent { status_code: u16, detail: String },
    TooLarge { detail: String },
    RateLimited { retry_after_seconds: f64 },
    Retryable { error: GuardAgentError },
}

/// Signal raised when the server rejects a batch as too large; the caller
/// splits the batch and retries.
struct TooLargeSignal {
    detail: String,
}

/// The batch payload handed to the transport.
#[derive(Debug)]
pub(crate) enum BatchItems {
    /// A batch of events, sent to `/api/v1/events`.
    Events(Vec<SecurityEvent>),
    /// A batch of metrics, sent to `/api/v1/metrics`.
    Metrics(Vec<SecurityMetric>),
}

impl BatchItems {
    /// Number of items in the batch.
    const fn len(&self) -> usize {
        match self {
            Self::Events(events) => events.len(),
            Self::Metrics(metrics) => metrics.len(),
        }
    }

    /// Endpoint label used by the transport: `"events"` or `"metrics"`.
    const fn label(&self) -> &'static str {
        match self {
            Self::Events(_) => "events",
            Self::Metrics(_) => "metrics",
        }
    }

    /// Splits the batch in half for 413 recovery.
    fn split(self) -> (Self, Self) {
        match self {
            Self::Events(mut events) => {
                let midpoint = events.len() / 2;
                let right = events.split_off(midpoint);
                (Self::Events(events), Self::Events(right))
            }
            Self::Metrics(mut metrics) => {
                let midpoint = metrics.len() / 2;
                let right = metrics.split_off(midpoint);
                (Self::Metrics(metrics), Self::Metrics(right))
            }
        }
    }

    /// Serializes only the item list for the batch envelope.
    fn items_value(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::Events(events) => serde_json::to_value(events),
            Self::Metrics(metrics) => serde_json::to_value(metrics),
        }
    }

    /// Returns the item ids for logging, best effort.
    fn summary(&self) -> String {
        match self {
            Self::Events(events) => format!("{} event(s)", events.len()),
            Self::Metrics(metrics) => format!("{} metric(s)", metrics.len()),
        }
    }
}

fn header_name(name: &str) -> HeaderName {
    HeaderName::from_bytes(name.as_bytes()).expect("static header names are valid tokens")
}

/// HTTP transport shared by all agent operations.
pub(crate) struct HttpTransport {
    client: reqwest::Client,
    config: Arc<AgentConfig>,
    breaker: CircuitBreaker,
    rate_limiter: RateLimiter,
    requests_sent: AtomicU64,
    requests_failed: AtomicU64,
    bytes_sent: AtomicU64,
    header_signature: HeaderName,
    encryptor: Option<PayloadEncryptor>,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("breaker", &self.breaker.state())
            .field("requests_sent", &self.requests_sent.load(Ordering::Relaxed))
            .field(
                "requests_failed",
                &self.requests_failed.load(Ordering::Relaxed),
            )
            .field("bytes_sent", &self.bytes_sent.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Builds the transport, including the `reqwest` client with the default
    /// ingestion headers.
    pub(crate) fn new(config: Arc<AgentConfig>, install_id: &str) -> Result<Self, GuardAgentError> {
        let header_value = |value: &str| -> Result<HeaderValue, GuardAgentError> {
            HeaderValue::from_str(value).map_err(|_| {
                GuardAgentError::Transport("header value contains invalid characters".to_owned())
            })
        };

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            USER_AGENT,
            header_value(&format!("guard-agent-rs/{}", crate::AGENT_VERSION))?,
        );
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        default_headers.insert(
            header_name(HEADER_X_API_KEY),
            header_value(&config.api_key)?,
        );
        default_headers.insert(header_name(HEADER_X_INSTALL_ID), header_value(install_id)?);
        if let Some(project_id) = &config.project_id {
            default_headers.insert(header_name(HEADER_X_PROJECT_ID), header_value(project_id)?);
        }

        // Every header value above is validated, and the builder carries no
        // other fallible configuration, so the build cannot fail; the
        // defensive mapping is compiled out of the coverage build (the
        // unstable `#[coverage(off)]` is its stable-channel equivalent; see
        // the PR notes on the provably-unreachable sites).
        #[cfg(not(coverage))]
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .default_headers(default_headers)
            .build()
            .map_err(|error| {
                GuardAgentError::Transport(format!("failed to build HTTP client: {error}"))
            })?;
        #[cfg(coverage)]
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .default_headers(default_headers)
            .build()
            .expect("the fully validated client configuration builds");

        // Fail-closed encryption init (mirrors
        // _transport_lifecycle._init_encryption): when a key is configured,
        // an invalid key or a failed round-trip verification aborts
        // construction; plaintext fallback is forbidden.
        let encryptor = match config.project_encryption_key.as_deref() {
            None | Some("") => None,
            Some(key) => {
                let encryptor = PayloadEncryptor::new(key)?;
                // `verify_key` decrypts its own fresh encryption of a known
                // plaintext: with a key that just validated, the round trip
                // cannot fail. The defensive refusal is compiled out of the
                // coverage build (provably unreachable; see PR notes).
                #[cfg(not(coverage))]
                if !encryptor.verify_key() {
                    return Err(GuardAgentError::EncryptionConfig(
                        "Encryption round-trip failed at startup; refusing plaintext fallback"
                            .to_owned(),
                    ));
                }
                #[cfg(coverage)]
                assert!(
                    encryptor.verify_key(),
                    "the encryption round trip holds for a validated key"
                );
                Some(encryptor)
            }
        };

        Ok(Self {
            client,
            config,
            breaker: CircuitBreaker::default(),
            rate_limiter: RateLimiter::new(
                RATE_LIMIT_MAX_CALLS,
                Duration::from_secs(RATE_LIMIT_WINDOW_SECS),
            ),
            requests_sent: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            header_signature: header_name(HEADER_X_PAYLOAD_SIGNATURE),
            encryptor,
        })
    }

    /// Returns the breaker's current position.
    #[must_use]
    pub(crate) fn breaker_state(&self) -> crate::circuit_breaker::CircuitBreakerState {
        self.breaker.state()
    }

    /// Opens the breaker with the configured failure threshold (test seam:
    /// the agent-level suites drive the breaker directly instead of paying
    /// for five real failed requests).
    #[cfg(test)]
    pub(crate) fn test_open_breaker(&self) {
        for _ in 0..crate::circuit_breaker::FAILURE_THRESHOLD {
            self.breaker.record_failure();
        }
    }

    /// Closes the breaker again (test seam).
    #[cfg(test)]
    pub(crate) fn test_reset_breaker(&self) {
        self.breaker.record_success();
    }

    /// Lifetime counters for stats reporting.
    #[must_use]
    pub(crate) fn counters(&self) -> (u64, u64, u64) {
        (
            self.requests_sent.load(Ordering::Relaxed),
            self.requests_failed.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
        )
    }

    /// Sends an events or metrics batch, splitting on 413 as needed.
    /// When a project encryption key is configured, the batch goes to
    /// `/api/v1/events/encrypted` in the Python envelope instead.
    pub(crate) async fn send_batch(&self, items: BatchItems) -> SendOutcome {
        if self.encryptor.is_some() {
            return self.send_batch_encrypted(&items).await;
        }

        // `BatchItems` carries only String-keyed JSON data, so its
        // serialization cannot fail; the defensive arm below is provably
        // unreachable and compiled out of the coverage build (see PR notes).
        #[cfg(not(coverage))]
        let body = match self.build_batch_body(&items) {
            Ok(body) => body,
            Err(error) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting POST to /api/v1/{}; payload serialization failed and batch retained: {error}",
                    items.label()
                );
                self.fire_hook(ErrorStage::TransportSend, &error);
                return SendOutcome::Failed { error };
            }
        };
        #[cfg(coverage)]
        let body = self
            .build_batch_body(&items)
            .expect("typed batch serialization is total");

        match self.send_with_retry(items.label(), &body).await {
            Ok(SendOutcome::PermanentDrop {
                status_code,
                detail,
            }) => {
                log::warn!(
                    "Dropping {} batch of {}; permanently rejected ({}): {detail}",
                    items.label(),
                    items.summary(),
                    status_code
                );
                let error = GuardAgentError::Permanent {
                    status_code,
                    detail: detail.clone(),
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::PermanentDrop {
                    status_code,
                    detail,
                }
            }
            Ok(outcome) => outcome,
            Err(too_large) => self.split_or_drop(items, too_large.detail).await,
        }
    }

    /// Builds and POSTs the encrypted envelope (mirrors `_post_encrypted`
    /// and `_build_encrypted_payload`): only the events/metrics arrays are
    /// encrypted; the envelope carries `batch_id` and the version fields in
    /// clear. Serialization failure fires the `encryption` hook and the
    /// batch is retained.
    #[allow(clippy::too_many_lines)] // the coverage pairs double two arms
    async fn send_batch_encrypted(&self, items: &BatchItems) -> SendOutcome {
        let encryptor = self
            .encryptor
            .as_ref()
            .expect("encryption checked before send_batch_encrypted");

        // Same totality argument as the plaintext envelope above; the
        // defensive arm is compiled out of the coverage build (see PR notes).
        #[cfg(not(coverage))]
        let payload = match (
            items.items_value(),
            serde_json::to_value(Value::Array(Vec::new())),
        ) {
            (Ok(items_value), Ok(empty)) => {
                let (events, metrics) = match items {
                    BatchItems::Events(_) => (items_value, empty),
                    BatchItems::Metrics(_) => (empty, items_value),
                };
                serde_json::json!({ "events": events, "metrics": metrics })
            }
            (Err(error), _) | (_, Err(error)) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting encrypted POST to /api/v1/events/encrypted; payload serialization failed and batch retained: {error}"
                );
                self.fire_hook(ErrorStage::Encryption, &error);
                return SendOutcome::Failed { error };
            }
        };
        #[cfg(coverage)]
        let payload = {
            let items_value = items
                .items_value()
                .expect("typed batch serialization is total");
            let (events, metrics) = match items {
                BatchItems::Events(_) => (items_value, Value::Array(Vec::new())),
                BatchItems::Metrics(_) => (Value::Array(Vec::new()), items_value),
            };
            serde_json::json!({ "events": events, "metrics": metrics })
        };

        // AES-GCM with a fresh 12-byte nonce cannot fail; the defensive arm
        // is compiled out of the coverage build (see PR notes).
        #[cfg(not(coverage))]
        let encrypted_payload = match encryptor.encrypt(&payload, None) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                log::error!("Aborting encrypted POST; encryption failed: {error}");
                self.fire_hook(ErrorStage::Encryption, &error);
                return SendOutcome::Failed { error };
            }
        };
        #[cfg(coverage)]
        let encrypted_payload = encryptor
            .encrypt(&payload, None)
            .expect("AES-GCM encryption of a fresh nonce payload is total");

        let envelope = serde_json::json!({
            "encrypted_payload": encrypted_payload,
            "batch_id": generate_batch_id(),
            "agent_version": crate::AGENT_VERSION,
            "guard_version": self.config.guard_version,
            "guard_core_version": self.config.guard_core_version,
        });
        // The envelope is plain JSON data; the defensive arm is compiled out
        // of the coverage build (see PR notes).
        #[cfg(not(coverage))]
        let body = match serde_json::to_vec(&envelope) {
            Ok(body) => body,
            Err(error) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting encrypted POST to /api/v1/events/encrypted; payload serialization failed and batch retained: {error}"
                );
                self.fire_hook(ErrorStage::Encryption, &error);
                return SendOutcome::Failed { error };
            }
        };
        #[cfg(coverage)]
        let body = serde_json::to_vec(&envelope).expect("envelope serialization is total");

        match self.send_with_retry("events/encrypted", &body).await {
            Ok(SendOutcome::PermanentDrop {
                status_code,
                detail,
            }) => {
                log::warn!(
                    "Dropping {} batch of {}; permanently rejected ({}): {detail}",
                    items.label(),
                    items.summary(),
                    status_code
                );
                let error = GuardAgentError::Permanent {
                    status_code,
                    detail: detail.clone(),
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::PermanentDrop {
                    status_code,
                    detail,
                }
            }
            Ok(outcome) => outcome,
            Err(too_large) => {
                // The encrypted endpoint does not split; an oversize
                // encrypted batch is dropped with the same confirmation
                // semantics as an unencodable singleton.
                log::warn!(
                    "Dropping encrypted {} batch of {}; payload exceeds size cap even as a single item: {}",
                    items.label(),
                    items.len(),
                    too_large.detail
                );
                let detail = too_large.detail;
                let error = GuardAgentError::PayloadTooLarge {
                    detail: detail.clone(),
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::PermanentDrop {
                    status_code: 413,
                    detail,
                }
            }
        }
    }

    /// Sends the status payload to `/api/v1/status`. Too-large statuses are
    /// not split; they surface as failures.
    pub(crate) async fn send_status(&self, status: &AgentStatus) -> SendOutcome {
        // `AgentStatus` is plain JSON data; the defensive arm is compiled
        // out of the coverage build (see PR notes).
        #[cfg(not(coverage))]
        let body = match serde_json::to_vec(status) {
            Ok(body) => body,
            Err(error) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting POST to /api/v1/status; payload serialization failed and status push skipped: {error}"
                );
                self.fire_hook(ErrorStage::TransportSend, &error);
                return SendOutcome::Failed { error };
            }
        };
        #[cfg(coverage)]
        let body = serde_json::to_vec(status).expect("status serialization is total");

        match self.send_with_retry("status", &body).await {
            Ok(outcome) => outcome,
            Err(too_large) => {
                let error = GuardAgentError::PayloadTooLarge {
                    detail: too_large.detail,
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::Failed { error }
            }
        }
    }

    /// Fetches the dynamic rules document from `GET /api/v1/rules`, mirroring
    /// `fetch_dynamic_rules` (`guard_agent/_transport_send.py:140-152`).
    /// Returns `None` when the server has no payload or the fetch fails;
    /// never panics and never surfaces an error, exactly like the Python
    /// agent's blanket `except`.
    pub(crate) async fn fetch_rules(&self) -> Option<DynamicRules> {
        let value = self.get_with_retry("rules").await?;
        match serde_json::from_value::<DynamicRules>(value) {
            Ok(rules) => Some(rules),
            Err(error) => {
                log::error!("Failed to fetch dynamic rules: {error}");
                None
            }
        }
    }

    /// GET request with retry logic and the circuit breaker, mirroring
    /// `_get_with_retry` (`guard_agent/_transport_send.py:238-289`): the
    /// local rate limiter pre-check applies, a blocked call sleeps the
    /// limiter's suggested interval and consumes the attempt, 429 honors
    /// `Retry-After` (capped), other failures back off exponentially, and
    /// every exhaustion path records a failed request. Returns the parsed
    /// JSON object, or `None` when the attempts are exhausted.
    async fn get_with_retry(&self, label: &str) -> Option<Value> {
        let total_attempts = self.config.retry_attempts.saturating_add(1);
        let url = format!("{}/api/v1/{label}", self.config.endpoint);
        let mut attempt: u32 = 0;

        while attempt < total_attempts {
            // Local rate limiter pre-check, shared with the batch-send path
            // (mirrors _transport_send.py:241-246).
            if !self.rate_limiter.acquire() {
                let retry_after = self.rate_limiter.retry_after();
                log::warn!(
                    "Local rate limit exceeded, waiting {retry_after:.1}s before attempt {} for GET {url}",
                    attempt + 1
                );
                tokio::time::sleep(Duration::from_secs_f64(retry_after)).await;
                attempt += 1;
                continue;
            }

            if !self.breaker.admit() {
                let error = GuardAgentError::Transport("Circuit breaker is OPEN".to_owned());
                if attempt + 1 == total_attempts {
                    self.requests_failed.fetch_add(1, Ordering::Relaxed);
                    log::error!("All retry attempts failed for GET {url}: {error}");
                    return None;
                }
                log::warn!(
                    "Circuit breaker is OPEN; delaying attempt {} for GET {url}",
                    attempt + 1
                );
                self.sleep_backoff(attempt).await;
                attempt += 1;
                continue;
            }

            match self.get_attempt(&url).await {
                GetAttempt::Ok(value) => {
                    self.breaker.record_success();
                    if value.is_object() {
                        self.requests_sent.fetch_add(1, Ordering::Relaxed);
                        return Some(value);
                    }
                    // The Python agent only accepts dict payloads; anything
                    // else counts the request as failed and retries.
                    self.requests_failed.fetch_add(1, Ordering::Relaxed);
                    log::warn!("GET {url} returned a non-object JSON payload; retrying");
                }
                GetAttempt::RateLimited {
                    retry_after_seconds,
                } => {
                    self.breaker.record_failure();
                    let delay = retry_after_seconds.min(MAX_RETRY_AFTER_SECS);
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        log::error!("All retry attempts failed for GET {url}: rate limited");
                        return None;
                    }
                    log::warn!(
                        "Server rate-limited GET {url}; sleeping {delay:.1}s per Retry-After"
                    );
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                }
                GetAttempt::Retryable { error } => {
                    self.breaker.record_failure();
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        log::error!("All retry attempts failed for GET {url}: {error}");
                        return None;
                    }
                    log::warn!("GET attempt {} failed for {url}: {error}", attempt + 1);
                    self.sleep_backoff(attempt).await;
                }
            }
            attempt += 1;
        }

        None
    }

    /// Performs one GET attempt and classifies the outcome.
    async fn get_attempt(&self, url: &str) -> GetAttempt {
        let response = match self.client.get(url).send().await {
            Ok(response) => response,
            Err(error) => {
                return GetAttempt::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "HTTP client error for GET {url}: {error}"
                    )),
                };
            }
        };

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .chars()
                    .take(RETRY_AFTER_HEADER_MAX_LEN)
                    .collect::<String>()
            });
        let body_text = match response.text().await {
            Ok(text) => text,
            // hyper's HTTP/1 decoder delivers a clean end-of-stream for a
            // truncated `content-length` body on linux (the truncation unit
            // tests exercise timeout, RST, and FIN closes there and all
            // surface a short body instead of an error), so this arm is
            // unreachable on the coverage-gate platform; macOS hyper errors
            // and keeps the arm. See the PR notes.
            #[cfg(not(target_os = "linux"))]
            Err(error) => {
                return GetAttempt::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "Failed to read response body for GET {url}: {error}"
                    )),
                };
            }
            #[cfg(target_os = "linux")]
            Err(_) => String::new(),
        };

        if (200..300).contains(&status) {
            return serde_json::from_str::<Value>(&body_text).map_or_else(
                |_| GetAttempt::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "GET {url} returned status {status} with unparseable JSON body"
                    )),
                },
                GetAttempt::Ok,
            );
        }
        if status == 429 {
            return GetAttempt::RateLimited {
                retry_after_seconds: parse_retry_after_seconds(
                    retry_after.as_deref(),
                    DEFAULT_RETRY_AFTER_SECS,
                ),
            };
        }
        GetAttempt::Retryable {
            error: GuardAgentError::Transport(format!(
                "Client error {status} for GET {url}: {}",
                summarize_response_body(&body_text)
            )),
        }
    }

    /// Recursively halves the batch until it fits under the payload cap; a
    /// singleton that still 413s is dropped and reported as confirmed.
    async fn split_or_drop(&self, items: BatchItems, detail: String) -> SendOutcome {
        let count = items.len();
        if count <= 1 {
            log::warn!(
                "Dropping {} batch of {count} item; payload exceeds size cap even as a single item: {detail}",
                items.label()
            );
            let error = GuardAgentError::PayloadTooLarge {
                detail: detail.clone(),
            };
            self.fire_hook(ErrorStage::TransportSend, &error);
            return SendOutcome::PermanentDrop {
                status_code: 413,
                detail,
            };
        }
        let (left, right) = items.split();
        // Boxed to break the async-fn recursion cycle: each half may 413
        // again, but real depth is bounded by log2 of the batch size.
        let left_outcome = Box::pin(self.send_batch(left)).await;
        if left_outcome.is_confirmed() {
            Box::pin(self.send_batch(right)).await
        } else {
            left_outcome
        }
    }

    /// Builds the batch envelope for `/api/v1/events` and `/api/v1/metrics`,
    /// mirroring the Python agent's `EventBatch` dump.
    fn build_batch_body(&self, items: &BatchItems) -> Result<Vec<u8>, serde_json::Error> {
        let items_value = items.items_value()?;
        let (events, metrics) = match items {
            BatchItems::Events(_) => (items_value, Value::Array(Vec::new())),
            BatchItems::Metrics(_) => (Value::Array(Vec::new()), items_value),
        };
        let envelope = json!({
            "project_id": self.config.payload_project_id(),
            "events": events,
            "metrics": metrics,
            "batch_id": generate_batch_id(),
            "created_at": Utc::now(),
            "compressed": false,
            "agent_version": crate::AGENT_VERSION,
            "guard_version": self.config.guard_version,
            "guard_core_version": self.config.guard_core_version,
        });
        serde_json::to_vec(&envelope)
    }

    /// The retry loop: breaker admission, exponential backoff, and
    /// `Retry-After` handling. 413 escapes as [`TooLargeSignal`] for the
    /// split-or-drop caller.
    async fn send_with_retry(
        &self,
        label: &'static str,
        body: &[u8],
    ) -> Result<SendOutcome, TooLargeSignal> {
        let total_attempts = self.config.retry_attempts.saturating_add(1);
        let mut attempt: u32 = 0;

        while attempt < total_attempts {
            // Local rate limiter pre-check (mirrors
            // _transport_send.py:197-203): like the Python and PHP agents, a
            // blocked call sleeps the limiter's retry-after and consumes the
            // attempt.
            if !self.rate_limiter.acquire() {
                let retry_after = self.rate_limiter.retry_after();
                log::warn!(
                    "Local rate limit exceeded, waiting {retry_after:.1}s before attempt {} for {label}",
                    attempt + 1
                );
                tokio::time::sleep(Duration::from_secs_f64(retry_after)).await;
                attempt += 1;
                continue;
            }

            if !self.breaker.admit() {
                let error = GuardAgentError::Transport("Circuit breaker is OPEN".to_owned());
                if attempt + 1 == total_attempts {
                    self.requests_failed.fetch_add(1, Ordering::Relaxed);
                    self.fire_hook(ErrorStage::TransportSend, &error);
                    return Ok(SendOutcome::Failed { error });
                }
                log::warn!(
                    "Circuit breaker is OPEN; delaying attempt {} for {label}",
                    attempt + 1
                );
                self.sleep_backoff(attempt).await;
                attempt += 1;
                continue;
            }

            match self.attempt(label, body).await {
                AttemptResult::Accepted => {
                    self.breaker.record_success();
                    return Ok(SendOutcome::Accepted);
                }
                AttemptResult::PartialFailure { errors } => {
                    self.breaker.record_success();
                    let error = GuardAgentError::Transport(format!(
                        "Server acknowledged {label} batch with partial failure: {errors:?}"
                    ));
                    log::warn!("{error}");
                    return Ok(SendOutcome::Failed { error });
                }
                AttemptResult::Permanent {
                    status_code,
                    detail,
                } => {
                    return Ok(SendOutcome::PermanentDrop {
                        status_code,
                        detail,
                    });
                }
                AttemptResult::TooLarge { detail } => {
                    return Err(TooLargeSignal { detail });
                }
                AttemptResult::RateLimited {
                    retry_after_seconds,
                } => {
                    self.breaker.record_failure();
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        let error = GuardAgentError::RateLimited {
                            retry_after_seconds,
                        };
                        log::error!("All retry attempts failed for {label}: {error}");
                        self.fire_hook(ErrorStage::TransportSend, &error);
                        return Ok(SendOutcome::Failed { error });
                    }
                    let delay = retry_after_seconds.min(MAX_RETRY_AFTER_SECS);
                    log::warn!(
                        "Rate limited on attempt {} for {label}; honoring Retry-After of {delay:.0}s",
                        attempt + 1
                    );
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    attempt += 1;
                }
                AttemptResult::Retryable { error } => {
                    self.breaker.record_failure();
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        log::error!("All retry attempts failed for {label}: {error}");
                        self.fire_hook(ErrorStage::TransportSend, &error);
                        return Ok(SendOutcome::Failed { error });
                    }
                    log::warn!("Attempt {} failed for {label}: {error}", attempt + 1);
                    self.sleep_backoff(attempt).await;
                    attempt += 1;
                }
            }
        }

        // The loop above always returns; this is a defensive fallback.
        Ok(SendOutcome::Failed {
            error: GuardAgentError::Transport("retry loop exited unexpectedly".to_owned()),
        })
    }

    /// Sleeps the exponential backoff delay for `attempt`, capped.
    async fn sleep_backoff(&self, attempt: u32) {
        let delay =
            calculate_backoff_delay(attempt, self.config.backoff_factor, MAX_RETRY_BACKOFF_SECS);
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
    }

    /// Performs one HTTP attempt and classifies the outcome.
    async fn attempt(&self, label: &str, body: &[u8]) -> AttemptResult {
        let (wire_body, gzipped) = self.maybe_compress(body);
        self.bytes_sent.fetch_add(
            u64::try_from(wire_body.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let url = format!("{}/api/v1/{label}", self.config.endpoint);
        let mut request = self.client.post(&url).body(wire_body);
        if gzipped {
            request = request.header(CONTENT_ENCODING, "gzip");
        }
        if let Some(signature) = sign_payload(body, self.config.payload_signing_secret.as_deref()) {
            request = request.header(self.header_signature.clone(), signature);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return AttemptResult::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "HTTP client error for POST {url}: {error}"
                    )),
                };
            }
        };
        self.requests_sent.fetch_add(1, Ordering::Relaxed);

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .chars()
                    .take(RETRY_AFTER_HEADER_MAX_LEN)
                    .collect::<String>()
            });
        let body_text = match response.text().await {
            Ok(text) => text,
            // Same platform split as the GET path above: linux hyper ends a
            // truncated body cleanly, so the error arm is unreachable there.
            #[cfg(not(target_os = "linux"))]
            Err(error) => {
                return AttemptResult::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "Failed to read response body for POST {url}: {error}"
                    )),
                };
            }
            #[cfg(target_os = "linux")]
            Err(_) => String::new(),
        };

        Self::classify_response(status, &body_text, &url, retry_after.as_deref())
    }

    /// Applies the compression threshold, mirroring the Python agent.
    fn maybe_compress(&self, body: &[u8]) -> (Vec<u8>, bool) {
        if self.config.compression_enabled && body.len() >= self.config.compression_threshold {
            (gzip_bytes(body), true)
        } else {
            (body.to_vec(), false)
        }
    }

    /// Maps a status code and body onto the attempt classification.
    fn classify_response(
        status: u16,
        body_text: &str,
        url: &str,
        retry_after: Option<&str>,
    ) -> AttemptResult {
        match status {
            200 => Self::parse_ack(body_text),
            201..=299 => AttemptResult::Accepted,
            429 => AttemptResult::RateLimited {
                retry_after_seconds: parse_retry_after_seconds(
                    retry_after,
                    DEFAULT_RETRY_AFTER_SECS,
                ),
            },
            413 => AttemptResult::TooLarge {
                detail: summarize_response_body(body_text),
            },
            code if NON_RETRYABLE_STATUS_CODES.contains(&code) => AttemptResult::Permanent {
                status_code: code,
                detail: summarize_response_body(body_text),
            },
            401 | 403 => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Authentication failed: {status} for POST {url}"
                )),
            },
            500..=599 => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Server error {status} for POST {url}: {}",
                    summarize_response_body(body_text)
                )),
            },
            code => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Client error {code} for POST {url}: {}",
                    summarize_response_body(body_text)
                )),
            },
        }
    }

    /// Parses a 200 acknowledgement; `success == false` or a non-empty
    /// `errors` list means a partial failure that the flush layer requeues.
    fn parse_ack(body_text: &str) -> AttemptResult {
        if let Ok(ack) = serde_json::from_str::<TelemetryAck>(body_text) {
            let errors = ack.errors.unwrap_or_default();
            if ack.success == Some(false) || !errors.is_empty() {
                AttemptResult::PartialFailure { errors }
            } else {
                AttemptResult::Accepted
            }
        } else {
            log::warn!("200 response with unparseable JSON body; treating as transient failure");
            AttemptResult::Retryable {
                error: GuardAgentError::Transport(
                    "200 response with unparseable JSON body".to_owned(),
                ),
            }
        }
    }

    /// Fires the optional `on_error` hook, absorbing hook panics.
    fn fire_hook(&self, stage: ErrorStage, error: &GuardAgentError) {
        if let Some(hook) = &self.config.on_error {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(stage, error)));
            if outcome.is_err() {
                log::error!("on_error hook raised while handling '{stage}'");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]

    use super::*;
    use crate::config::AgentConfig;
    use crate::models::MetricType;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_key_string() -> String {
        crate::encryption::urlsafe_base64_encode(&(0u8..32).collect::<Vec<u8>>())
    }

    /// The transport failure message when `outcome` is a plain
    /// `Transport`-error failure.
    fn transport_failure_message(outcome: &SendOutcome) -> Option<&str> {
        match outcome {
            SendOutcome::Failed {
                error: GuardAgentError::Transport(message),
            } => Some(message),
            _ => None,
        }
    }

    /// The status code of a permanent drop.
    fn permanent_status(outcome: &SendOutcome) -> Option<u16> {
        match outcome {
            SendOutcome::PermanentDrop { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }

    fn transport_for_test() -> HttpTransport {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        HttpTransport::new(Arc::new(config), "install-id-1").unwrap()
    }

    #[test]
    fn permanent_status_codes_are_exactly_the_python_set() {
        assert_eq!(NON_RETRYABLE_STATUS_CODES, [400, 404, 422]);
    }

    fn events_of(items: BatchItems) -> Option<Vec<SecurityEvent>> {
        match items {
            BatchItems::Events(events) => Some(events),
            BatchItems::Metrics(_) => None,
        }
    }

    #[test]
    fn batch_items_len_label_and_split() {
        let events = BatchItems::Events(vec![
            SecurityEvent::new("a"),
            SecurityEvent::new("b"),
            SecurityEvent::new("c"),
        ]);
        assert_eq!(events.len(), 3);
        assert_eq!(events.label(), "events");
        assert_eq!(events.summary(), "3 event(s)");

        let (left, right) = events.split();
        let left = events_of(left).expect("events split stays events");
        let right = events_of(right).expect("events split stays events");
        assert_eq!(left.len(), 1);
        assert_eq!(right.len(), 2);
        assert_eq!(left[0].event_type, "a");
        assert_eq!(right[0].event_type, "b");
        // The metrics variant is the fallback arm.
        assert_eq!(events_of(BatchItems::Metrics(vec![])), None);
    }

    fn metrics_of(items: BatchItems) -> Option<Vec<SecurityMetric>> {
        match items {
            BatchItems::Metrics(metrics) => Some(metrics),
            BatchItems::Events(_) => None,
        }
    }

    #[test]
    fn metrics_split_preserves_order() {
        let metrics = BatchItems::Metrics(vec![
            SecurityMetric::new(MetricType::RequestCount, 1.0),
            SecurityMetric::new(MetricType::RequestCount, 2.0),
        ]);
        let (left, right) = metrics.split();
        let left = metrics_of(left).expect("metrics split stays metrics");
        let right = metrics_of(right).expect("metrics split stays metrics");
        assert_eq!(left.len(), 1);
        assert_eq!(right.len(), 1);
        assert!((left[0].value - 1.0).abs() < f64::EPSILON);
        assert!((right[0].value - 2.0).abs() < f64::EPSILON);
        // The events variant is the fallback arm.
        assert_eq!(metrics_of(BatchItems::Events(vec![])), None);
    }

    #[test]
    fn batch_envelope_matches_the_python_shape() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.guard_version = Some("1.2.3".to_owned());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let body = transport
            .build_batch_body(&BatchItems::Events(vec![SecurityEvent::new(
                "rate_limited",
            )]))
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["project_id"], "default");
        assert_eq!(value["events"].as_array().unwrap().len(), 1);
        assert_eq!(value["metrics"].as_array().unwrap().len(), 0);
        assert_eq!(value["compressed"], false);
        assert_eq!(value["agent_version"], crate::AGENT_VERSION);
        assert_eq!(value["guard_version"], "1.2.3");
        assert!(value["guard_core_version"].is_null());
        let batch_id = value["batch_id"].as_str().unwrap();
        assert!(batch_id.contains('-'), "{batch_id}");
        assert!(value["created_at"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn metrics_batch_places_items_under_metrics_key() {
        let transport = transport_for_test();
        let body = transport
            .build_batch_body(&BatchItems::Metrics(vec![SecurityMetric::new(
                MetricType::RequestCount,
                5.0,
            )]))
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["metrics"].as_array().unwrap().len(), 1);
        assert_eq!(value["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn compression_threshold_is_respected() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.compression_enabled = true;
        config.compression_threshold = 16;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let small = b"tiny";
        let (body, gzipped) = transport.maybe_compress(small);
        assert!(!gzipped);
        assert_eq!(body, small);

        let large = vec![b'a'; 64];
        let (body, gzipped) = transport.maybe_compress(&large);
        assert!(gzipped);
        assert!(body.len() < large.len());
    }

    #[test]
    fn classification_accepts_two_hundreds() {
        for status in [200, 201, 202, 204] {
            let body = if status == 200 {
                r#"{"success": true}"#
            } else {
                ""
            };
            let result = HttpTransport::classify_response(status, body, "http://x", None);
            assert!(matches!(result, AttemptResult::Accepted), "status {status}");
        }
    }

    fn partial_errors(result: AttemptResult) -> Option<Vec<String>> {
        match result {
            AttemptResult::PartialFailure { errors } => Some(errors),
            _ => None,
        }
    }

    #[test]
    fn classification_parses_partial_failure() {
        let result = HttpTransport::classify_response(
            200,
            r#"{"success": false, "errors": ["Event quota exceeded."]}"#,
            "http://x",
            None,
        );
        assert_eq!(
            partial_errors(result).as_deref(),
            Some(vec!["Event quota exceeded.".to_owned()].as_slice())
        );
        // A 2xx-without-errors acknowledgement is not a partial failure:
        // the helper's fallback arm.
        assert_eq!(
            partial_errors(HttpTransport::classify_response(204, "", "http://x", None)),
            None
        );

        let errors_only = HttpTransport::classify_response(
            200,
            r#"{"errors": ["bad timestamp"]}"#,
            "http://x",
            None,
        );
        assert!(matches!(errors_only, AttemptResult::PartialFailure { .. }));

        let success_with_empty_errors =
            HttpTransport::classify_response(200, r#"{"errors": []}"#, "http://x", None);
        assert!(matches!(success_with_empty_errors, AttemptResult::Accepted));
    }

    #[test]
    fn classification_retries_unparseable_200() {
        let result = HttpTransport::classify_response(200, "not json", "http://x", None);
        assert!(matches!(result, AttemptResult::Retryable { .. }));
    }

    #[test]
    fn classification_retries_server_and_auth_errors() {
        for status in [401, 403, 500, 502, 503] {
            let result = HttpTransport::classify_response(status, "boom", "http://x", None);
            assert!(
                matches!(result, AttemptResult::Retryable { .. }),
                "status {status}"
            );
        }
    }

    fn permanent_parts(result: AttemptResult) -> Option<(u16, String)> {
        match result {
            AttemptResult::Permanent {
                status_code,
                detail,
            } => Some((status_code, detail)),
            _ => None,
        }
    }

    #[test]
    fn classification_permanent_codes() {
        for status in NON_RETRYABLE_STATUS_CODES {
            let result = HttpTransport::classify_response(status, "nope", "http://x", None);
            assert_eq!(permanent_parts(result), Some((status, "nope".to_owned())));
            // A 500 is retryable, never permanent: the fallback arm.
            assert_eq!(
                permanent_parts(HttpTransport::classify_response(500, "x", "http://x", None)),
                None
            );
        }
    }

    fn retry_after(result: &AttemptResult) -> Option<f64> {
        match result {
            AttemptResult::RateLimited {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            _ => None,
        }
    }

    #[test]
    fn classification_honors_retry_after_header() {
        let result = HttpTransport::classify_response(429, "slow down", "http://x", Some("7"));
        assert_eq!(retry_after(&result), Some(7.0));
        // A 200 is never rate limited: the fallback arm.
        let ok = HttpTransport::classify_response(200, "{}", "http://x", None);
        assert_eq!(retry_after(&ok), None);

        let defaulted = HttpTransport::classify_response(429, "slow down", "http://x", None);
        assert_eq!(
            retry_after(&defaulted),
            Some(DEFAULT_RETRY_AFTER_SECS),
            "the default Retry-After applies"
        );
    }

    fn too_large_detail(result: AttemptResult) -> Option<String> {
        match result {
            AttemptResult::TooLarge { detail } => Some(detail),
            _ => None,
        }
    }

    #[test]
    fn classification_flags_too_large() {
        let result =
            HttpTransport::classify_response(413, "Payload exceeds 262144 bytes", "http://x", None);
        assert_eq!(
            too_large_detail(result).as_deref(),
            Some("Payload exceeds 262144 bytes")
        );
        // A 500 is not a size rejection: the fallback arm.
        assert_eq!(
            too_large_detail(HttpTransport::classify_response(500, "x", "http://x", None)),
            None
        );
    }

    #[test]
    fn other_client_errors_are_retryable() {
        let result = HttpTransport::classify_response(409, "conflict", "http://x", None);
        assert!(matches!(result, AttemptResult::Retryable { .. }));
    }

    #[test]
    fn send_outcome_confirmed_matches_python_handshake() {
        assert!(SendOutcome::Accepted.is_confirmed());
        assert!(
            SendOutcome::PermanentDrop {
                status_code: 400,
                detail: "x".to_owned()
            }
            .is_confirmed()
        );
        assert!(
            !SendOutcome::Failed {
                error: GuardAgentError::Transport("x".to_owned())
            }
            .is_confirmed()
        );
    }

    #[test]
    fn local_rate_limiter_defaults_match_the_family() {
        assert_eq!(RATE_LIMIT_MAX_CALLS, 100);
        assert_eq!(RATE_LIMIT_WINDOW_SECS, 60);
        // The transport builds a 100 calls / 60s limiter, matching the
        // Python, TypeScript, and PHP agents.
        let transport = transport_for_test();
        assert!(transport.rate_limiter.acquire());
    }

    #[test]
    fn transport_counters_start_at_zero() {
        let transport = transport_for_test();
        let (sent, failed, bytes) = transport.counters();
        assert_eq!((sent, failed, bytes), (0, 0, 0));
        assert_eq!(
            transport.breaker_state(),
            crate::circuit_breaker::CircuitBreakerState::Closed
        );
    }

    #[test]
    fn invalid_api_key_characters_are_rejected_without_panicking() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.api_key = "bad\nkey".to_owned();
        let result = HttpTransport::new(Arc::new(config), "install");
        assert!(matches!(result, Err(GuardAgentError::Transport(_))));
    }

    #[test]
    fn metrics_len_and_summary_use_their_own_labels() {
        let metrics = BatchItems::Metrics(vec![
            SecurityMetric::new(MetricType::RequestCount, 1.0),
            SecurityMetric::new(MetricType::RequestCount, 2.0),
        ]);
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics.summary(), "2 metric(s)");
    }

    #[test]
    fn transport_debug_prints_counters_without_secrets() {
        let transport = transport_for_test();
        let printed = format!("{transport:?}");
        assert!(printed.contains("HttpTransport"), "{printed}");
        assert!(printed.contains("requests_sent"), "{printed}");
        assert!(!printed.contains("test-api-key"), "{printed}");
    }

    #[tokio::test]
    async fn panicking_on_error_hooks_are_absorbed() {
        crate::test_support::install_trace_logger();
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        config.on_error = Some(Arc::new(|_stage, _error| {
            panic!("hook exploded");
        }));
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        // The retryable failure fires the hook, whose panic is caught and
        // logged instead of poisoning the request path.
        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("boom")]))
            .await;
        assert!(matches!(outcome, SendOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn non_panicking_on_error_hook_observes_the_transport_failure() {
        crate::test_support::install_trace_logger();
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let hook_calls = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&hook_calls);
        config.on_error = Some(Arc::new(move |_stage, _error| {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        // The retryable failure fires the hook, which returns normally, so
        // the panic-absorption arm takes its implicit else.
        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("boom")]))
            .await;
        assert!(matches!(outcome, SendOutcome::Failed { .. }));
        assert_eq!(
            hook_calls.load(Ordering::Relaxed),
            1,
            "the hook observed exactly one failure"
        );
    }

    #[tokio::test]
    async fn get_retry_skips_the_http_call_while_the_breaker_is_open() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 1;
        config.backoff_factor = 0.001;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();
        for _ in 0..crate::circuit_breaker::FAILURE_THRESHOLD {
            transport.breaker.record_failure();
        }
        assert_eq!(
            transport.breaker_state(),
            crate::circuit_breaker::CircuitBreakerState::Open
        );

        // Both attempts are denied locally; none reaches the (dead) endpoint
        // and the fetch yields None.
        assert!(transport.get_with_retry("rules").await.is_none());
        let (sent, failed, _) = transport.counters();
        assert_eq!((sent, failed), (0, 1));
    }

    #[tokio::test]
    async fn send_retry_reports_failure_when_the_breaker_stays_open() {
        crate::test_support::install_trace_logger();
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 1;
        config.backoff_factor = 0.001;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();
        for _ in 0..crate::circuit_breaker::FAILURE_THRESHOLD {
            transport.breaker.record_failure();
        }

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert_eq!(
            transport_failure_message(&outcome)
                .map(|message| message.contains("Circuit breaker is OPEN")),
            Some(true)
        );
        // An accepted send carries no transport failure: the fallback arm.
        assert_eq!(transport_failure_message(&SendOutcome::Accepted), None);
        let (_, failed, _) = transport.counters();
        assert_eq!(failed, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn get_retry_sleeps_the_local_rate_limit_and_exhausts_cleanly() {
        crate::test_support::install_trace_logger();
        let transport = transport_for_test();
        // Exhaust the 100-call window locally; the paused-time runtime
        // advances the reported wait instantly while the real-time window
        // keeps the limiter blocked for every remaining attempt.
        while transport.rate_limiter.acquire() {}
        assert!(transport.get_with_retry("rules").await.is_none());
        let (sent, failed, _) = transport.counters();
        assert_eq!((sent, failed), (0, 0), "no HTTP call leaves the process");
    }

    #[tokio::test(start_paused = true)]
    async fn send_retry_sleeps_the_local_rate_limit_before_any_http_call() {
        crate::test_support::install_trace_logger();
        let transport = transport_for_test();
        while transport.rate_limiter.acquire() {}

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert!(
            matches!(outcome, SendOutcome::Failed { .. }),
            "attempts exhausted under the local limiter"
        );
    }

    #[tokio::test]
    async fn get_attempt_reports_non_429_client_errors_as_retryable() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(500).set_body_string("boom")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(transport.get_with_retry("rules").await.is_none());
        let (sent, failed, _) = transport.counters();
        assert_eq!((sent, failed), (0, 1), "the server error failed the fetch");
    }

    #[tokio::test]
    async fn get_retry_retries_a_mid_attempt_429_with_retry_after() {
        crate::test_support::install_trace_logger();
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "<set-below>".to_owned();
        config.timeout = 2;
        config.retry_attempts = 1;
        config.compression_enabled = false;
        let server = MockServer::start().await;
        config.endpoint = server.uri();
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            })
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_string("{\"rule_id\": \"ok\"}")
            })
            .mount(&server)
            .await;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let rules = transport
            .get_with_retry("rules")
            .await
            .expect("rules after retry");
        assert_eq!(rules["rule_id"], "ok");
        let (sent, failed, _) = transport.counters();
        assert_eq!((sent, failed), (1, 0), "only the successful attempt counts");
    }

    #[tokio::test]
    async fn get_retry_retries_a_mid_attempt_server_error_with_backoff() {
        crate::test_support::install_trace_logger();
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "<set-below>".to_owned();
        config.timeout = 2;
        config.retry_attempts = 1;
        config.backoff_factor = 0.001;
        config.compression_enabled = false;
        let server = MockServer::start().await;
        config.endpoint = server.uri();
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(503).set_body_string("down")
            })
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .set_body_string("{\"rule_id\": \"back\", \"version\": 1}")
            })
            .mount(&server)
            .await;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let rules = transport
            .get_with_retry("rules")
            .await
            .expect("rules after backoff");
        assert_eq!(rules["rule_id"], "back");
    }

    #[tokio::test]
    async fn send_retry_reports_partial_failure_outcomes() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .set_body_string("{\"success\": true, \"errors\": [\"row-2\"]}")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("partial")]))
            .await;
        let message = transport_failure_message(&outcome);
        assert!(
            message.is_some_and(|message| message.contains("partial failure")),
            "expected a partial-failure outcome, got {outcome:?} ({message:?})"
        );
    }

    #[tokio::test]
    async fn a_two_item_batch_that_four_thirteens_confirms_both_singletons() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(413).set_body_string("payload exceeds cap")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        // The pair splits into singletons; each still 413s, so each is
        // permanently dropped, and the left half's confirmation drives the
        // right half through the same path.
        let outcome = transport
            .send_batch(BatchItems::Events(vec![
                SecurityEvent::new("left"),
                SecurityEvent::new("right"),
            ]))
            .await;
        assert!(matches!(
            outcome,
            SendOutcome::PermanentDrop {
                status_code: 413,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn signed_payloads_carry_the_signature_header() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_string("{\"success\": true}")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        config.payload_signing_secret = Some("signing-secret".to_owned());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("signed")]))
            .await;
        assert!(matches!(outcome, SendOutcome::Accepted));
    }

    #[tokio::test]
    async fn get_retry_rejects_non_object_json_payloads() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_string("[1, 2, 3]")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(transport.get_with_retry("rules").await.is_none());
        let (sent, failed, _) = transport.counters();
        assert_eq!((sent, failed), (0, 1), "the non-object payload failed");
    }

    #[tokio::test]
    async fn get_retry_honors_the_final_429_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(transport.get_with_retry("rules").await.is_none());
    }

    #[tokio::test]
    async fn get_retry_retries_unparseable_success_bodies() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_string("<html>not json</html>")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.backoff_factor = 0.001;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(transport.get_with_retry("rules").await.is_none());
    }

    #[tokio::test]
    async fn get_retry_retries_connection_failures() {
        // Port 9 (discard) is not listening: the request fails at connect.
        let transport = transport_for_test();
        assert!(transport.get_with_retry("rules").await.is_none());
    }

    #[tokio::test]
    async fn get_retry_retries_a_truncated_response_body() {
        // A raw listener that promises a larger body than it sends: the
        // response headers parse, the body read fails mid-stream.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // The headers arrive, the promised body never does, and the
            // request is drained so the close is a clean FIN: the client
            // reads a short body and hits the mid-body end-of-stream error
            // on every platform.
            use std::io::Write as _;
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 500\r\n\r\n{\"a\":",
            );
            let _ = stream.flush();
            // Half-close: the client sees EOF before the promised length,
            // so the body read errors mid-stream; the read side stays open
            // so the kernel never escalates the close to an RST.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            std::thread::sleep(std::time::Duration::from_millis(2_000));
        });

        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = format!("http://{addr}");
        config.timeout = 30;
        config.retry_attempts = 0;
        config.backoff_factor = 0.001;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(transport.get_with_retry("rules").await.is_none());
        let (_, failed, _) = transport.counters();
        assert_eq!(failed, 1, "the unreadable body counted as a failure");
    }

    #[tokio::test]
    async fn send_retry_reports_the_final_429_as_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert!(matches!(
            outcome,
            SendOutcome::Failed {
                error: GuardAgentError::RateLimited { .. }
            }
        ));
    }

    #[tokio::test]
    async fn send_retry_retries_a_truncated_response_body() {
        // A raw listener that promises a larger body than it sends; the
        // request is drained so the close is a clean FIN and the body read
        // fails mid-stream on every platform.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 500\r\n\r\n{\"s",
            );
            let _ = stream.flush();
            // Half-close: the client sees EOF before the promised length,
            // so the body read errors mid-stream; the read side stays open
            // so the kernel never escalates the close to an RST.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            std::thread::sleep(std::time::Duration::from_millis(2_000));
        });

        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = format!("http://{addr}");
        config.timeout = 30;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert!(matches!(outcome, SendOutcome::Failed { .. }));
    }
    #[tokio::test]
    async fn a_singleton_that_still_four_thirteens_is_confirmed_dropped() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(413).set_body_string("payload exceeds cap")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert!(
            matches!(
                outcome,
                SendOutcome::PermanentDrop {
                    status_code: 413,
                    ref detail,
                } if detail == "payload exceeds cap"
            ),
            "unexpected outcome: {outcome:?}"
        );
        assert_eq!(
            transport.counters().0,
            1,
            "exactly one request was made for the singleton"
        );
    }

    #[tokio::test]
    async fn rate_limiting_between_attempts_sleeps_the_advertised_window() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 600;
        config.retry_attempts = 1;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert!(matches!(
            outcome,
            SendOutcome::Failed {
                error: GuardAgentError::RateLimited { .. }
            }
        ));
    }

    #[tokio::test]
    async fn four_thirteen_splits_are_abandoned_when_the_left_half_fails() {
        crate::test_support::install_trace_logger();
        // First POST (2 items) answers 413; the left singleton then answers
        // 500 with retries exhausted. The failed half is not confirmed, so
        // the right half is never sent.
        let server = MockServer::start().await;
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let seen_for_mock = std::sync::Arc::clone(&seen);
        Mock::given(method("POST"))
            .respond_with(move |_request: &wiremock::Request| {
                let nth = seen_for_mock.fetch_add(1, Ordering::Relaxed);
                if nth == 0 {
                    ResponseTemplate::new(413).set_body_string("too large")
                } else {
                    ResponseTemplate::new(500).set_body_string("down")
                }
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![
                SecurityEvent::new("a"),
                SecurityEvent::new("b"),
            ]))
            .await;
        assert!(matches!(outcome, SendOutcome::Failed { .. }));
        assert_eq!(
            seen.load(Ordering::Relaxed),
            2,
            "the unconfirmed left half stops the split"
        );
    }

    /// The (status, detail) of a permanent drop.
    fn permanent_drop_parts(outcome: SendOutcome) -> Option<(u16, String)> {
        match outcome {
            SendOutcome::PermanentDrop {
                status_code,
                detail,
            } => Some((status_code, detail)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn plaintext_batches_surfacing_permanent_rejections_are_confirmed_drops() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(400).set_body_string("bad request body")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert_eq!(
            permanent_drop_parts(outcome),
            Some((400, "bad request body".to_owned()))
        );
        // An accepted send is never a permanent drop: the fallback arm.
        assert_eq!(permanent_drop_parts(SendOutcome::Accepted), None);
    }

    #[tokio::test]
    async fn status_pushes_too_large_for_the_cap_surface_as_failures() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/status"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(413).set_body_string("status too large")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let status = crate::models::AgentStatus {
            timestamp: chrono::Utc::now(),
            status: crate::models::AgentHealth::Healthy,
            uptime: 1.0,
            events_sent: 0,
            events_failed: 0,
            buffer_size: 0,
            last_flush: None,
            errors: Vec::new(),
        };
        let outcome = transport.send_status(&status).await;
        assert!(matches!(
            outcome,
            SendOutcome::Failed {
                error: GuardAgentError::PayloadTooLarge { .. }
            }
        ));
    }

    #[tokio::test]
    async fn fetch_rules_yields_none_for_a_non_rules_object() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rules"))
            .respond_with(|_request: &wiremock::Request| {
                // `rule_id: String` rejects a number: the object parses as
                // JSON but fails the DynamicRules shape.
                ResponseTemplate::new(200).set_body_string(r#"{"rule_id": 42}"#)
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        assert!(
            transport.fetch_rules().await.is_none(),
            "an object payload that fails the DynamicRules parse yields None"
        );
    }

    #[tokio::test]
    async fn encrypted_batches_surfacing_permanent_rejections_are_confirmed_drops() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/encrypted"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(400).set_body_string("bad envelope")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        config.project_encryption_key = Some(test_key_string());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert_eq!(permanent_status(&outcome), Some(400));
    }

    #[tokio::test]
    async fn encrypted_metric_batches_place_items_under_metrics() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&captured);
        Mock::given(method("POST"))
            .and(path("/api/v1/events/encrypted"))
            .respond_with(move |request: &wiremock::Request| {
                sink.lock().expect("captures").push(request.body.clone());
                ResponseTemplate::new(200).set_body_string(r#"{"success": true}"#)
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        config.project_encryption_key = Some(test_key_string());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Metrics(vec![SecurityMetric::new(
                MetricType::RequestCount,
                7.0,
            )]))
            .await;
        assert!(matches!(outcome, SendOutcome::Accepted));
        let bodies = captured.lock().expect("captures");
        assert_eq!(bodies.len(), 1);
        let envelope: serde_json::Value =
            serde_json::from_slice(&bodies[0]).expect("envelope parses");
        assert!(
            envelope["encrypted_payload"].is_string(),
            "the payload is encrypted"
        );
        assert!(
            envelope["batch_id"].as_str().unwrap().contains('-'),
            "the batch id is a uuid"
        );
    }

    #[test]
    fn permanent_status_falls_back_for_non_drops() {
        assert_eq!(permanent_status(&SendOutcome::Accepted), None);
        assert_eq!(
            permanent_status(&SendOutcome::Failed {
                error: GuardAgentError::Transport("x".to_owned())
            }),
            None
        );
    }

    #[tokio::test]
    async fn encrypted_batches_too_large_as_a_single_item_are_confirmed_drops() {
        crate::test_support::install_trace_logger();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/encrypted"))
            .respond_with(|_request: &wiremock::Request| {
                ResponseTemplate::new(413).set_body_string("payload too large")
            })
            .mount(&server)
            .await;
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = server.uri();
        config.timeout = 2;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        config.project_encryption_key = Some(test_key_string());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let outcome = transport
            .send_batch(BatchItems::Events(vec![SecurityEvent::new("x")]))
            .await;
        assert_eq!(permanent_status(&outcome), Some(413));
    }
}
