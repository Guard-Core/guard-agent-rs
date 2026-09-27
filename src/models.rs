//! Wire models mirroring the Python agent's `SecurityEvent`, `SecurityMetric`,
//! and `AgentStatus` payloads.
//!
//! Serialization is snake case to match the ingestion API contract exactly.
//! Timestamps render as RFC 3339 (ISO 8601) strings, which the Pydantic-backed
//! server parses natively.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The event types the Guard ecosystem emits, mirroring the Python agent's
/// `KNOWN_EVENT_TYPES` (`guard_agent/models.py:20-55`).
///
/// Like the baseline, this list is documentation, not validation:
/// `SecurityEvent::event_type` stays a free `String` so engine-side renames
/// and additions can never break the consumer. The wave-1-6 rename entries
/// `user_agent_blocked` and `decorator_violation` and the trailing
/// `security_headers_applied` / `csp_violation` are part of the pinned
/// surface.
pub const KNOWN_EVENT_TYPES: [&str; 39] = [
    "ip_banned",
    "ip_unbanned",
    "ip_blocked",
    "ip_ban_failed",
    "rate_limited",
    "rate_limit_script_reloaded",
    "suspicious_request",
    "cloud_blocked",
    "country_blocked",
    "penetration_attempt",
    "behavioral_violation",
    "user_agent_blocked",
    "custom_request_check",
    "decorator_violation",
    "decoding_error",
    "detection_engine_callback_error",
    "geo_lookup_failed",
    "https_enforced",
    "pattern_anomaly_slow_execution",
    "pattern_anomaly_timeout",
    "pattern_anomaly_statistical_anomaly",
    "redis_connection",
    "redis_error",
    "dynamic_rule_applied",
    "dynamic_rule_updated",
    "path_excluded",
    "route_unresolved",
    "pattern_detected",
    "pattern_added",
    "pattern_removed",
    "access_denied",
    "authentication_failed",
    "content_filtered",
    "emergency_mode_activated",
    "emergency_mode_block",
    "dynamic_rule_violation",
    "security_bypass",
    "security_headers_applied",
    "csp_violation",
];

/// Metric types accepted by the ingestion API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    /// Requests observed over an interval.
    RequestCount,
    /// Latency samples.
    ResponseTime,
    /// Error ratio over an interval.
    ErrorRate,
    /// Bytes transferred over an interval.
    BandwidthUsage,
    /// Aggregate threat level.
    ThreatLevel,
    /// Ratio of blocked requests.
    BlockRate,
    /// Ratio of cache hits.
    CacheHitRate,
}

impl MetricType {
    /// Returns the snake case wire name of the metric type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestCount => "request_count",
            Self::ResponseTime => "response_time",
            Self::ErrorRate => "error_rate",
            Self::BandwidthUsage => "bandwidth_usage",
            Self::ThreatLevel => "threat_level",
            Self::BlockRate => "block_rate",
            Self::CacheHitRate => "cache_hit_rate",
        }
    }
}

impl std::fmt::Display for MetricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single security event.
///
/// Field names and defaults mirror the Python agent's `SecurityEvent`
/// (`guard_agent/models.py:208-229`), including the always-present
/// `idempotency_key` UUID used for server-side deduplication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Client-generated deduplication key.
    pub idempotency_key: Uuid,
    /// When the event happened.
    pub timestamp: DateTime<Utc>,
    /// Event type label, for example `rate_limited`.
    pub event_type: String,
    /// Client IP address when known, empty string otherwise.
    pub ip_address: String,
    /// Country code when known.
    pub country: Option<String>,
    /// Request user agent when known.
    pub user_agent: Option<String>,
    /// Request endpoint when known.
    pub endpoint: Option<String>,
    /// HTTP method when known.
    pub method: Option<String>,
    /// Guard decorator that produced the event, when known.
    pub decorator_type: Option<String>,
    /// Rule type that matched, when known.
    pub rule_type: Option<String>,
    /// Pattern that matched, when known.
    pub pattern_matched: Option<String>,
    /// Handler that produced the event, when known.
    pub handler_name: Option<String>,
    /// Action taken by the middleware, empty string when none.
    pub action_taken: String,
    /// Human readable reason, empty string when none.
    pub reason: String,
    /// Response status code when known.
    pub status_code: Option<u16>,
    /// Response time in seconds when known.
    pub response_time: Option<f64>,
    /// Arbitrary structured context. Sensitive keys are redacted at ingest.
    pub metadata: Value,
}

impl SecurityEvent {
    /// Creates an event stamped with the current time and a fresh
    /// idempotency key.
    #[must_use]
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            idempotency_key: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.into(),
            ip_address: String::new(),
            country: None,
            user_agent: None,
            endpoint: None,
            method: None,
            decorator_type: None,
            rule_type: None,
            pattern_matched: None,
            handler_name: None,
            action_taken: String::new(),
            reason: String::new(),
            status_code: None,
            response_time: None,
            metadata: Value::Object(serde_json::Map::new()),
        }
    }

    /// Sets the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = ip_address.into();
        self
    }

    /// Sets the country code.
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Sets the request endpoint.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the HTTP method.
    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets the guard decorator type.
    #[must_use]
    pub fn with_decorator_type(mut self, decorator_type: impl Into<String>) -> Self {
        self.decorator_type = Some(decorator_type.into());
        self
    }

    /// Sets the matched rule type.
    #[must_use]
    pub fn with_rule_type(mut self, rule_type: impl Into<String>) -> Self {
        self.rule_type = Some(rule_type.into());
        self
    }

    /// Sets the matched pattern.
    #[must_use]
    pub fn with_pattern_matched(mut self, pattern_matched: impl Into<String>) -> Self {
        self.pattern_matched = Some(pattern_matched.into());
        self
    }

    /// Sets the handler name.
    #[must_use]
    pub fn with_handler_name(mut self, handler_name: impl Into<String>) -> Self {
        self.handler_name = Some(handler_name.into());
        self
    }

    /// Sets the action taken.
    #[must_use]
    pub fn with_action_taken(mut self, action_taken: impl Into<String>) -> Self {
        self.action_taken = action_taken.into();
        self
    }

    /// Sets the reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Sets the response status code.
    #[must_use]
    pub const fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }

    /// Sets the response time in seconds.
    #[must_use]
    pub const fn with_response_time(mut self, response_time: f64) -> Self {
        self.response_time = Some(response_time);
        self
    }

    /// Replaces the metadata object.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Overrides the idempotency key.
    #[must_use]
    pub const fn with_idempotency_key(mut self, idempotency_key: Uuid) -> Self {
        self.idempotency_key = idempotency_key;
        self
    }

    /// Overrides the timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// A single security metric sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityMetric {
    /// When the sample was taken.
    pub timestamp: DateTime<Utc>,
    /// Metric kind.
    pub metric_type: MetricType,
    /// Sample value.
    pub value: f64,
    /// Endpoint the sample applies to, when scoped.
    pub endpoint: Option<String>,
    /// Free-form string tags. Sensitive keys are redacted at ingest.
    pub tags: BTreeMap<String, String>,
}

impl SecurityMetric {
    /// Creates a metric stamped with the current time.
    #[must_use]
    pub fn new(metric_type: MetricType, value: f64) -> Self {
        Self {
            timestamp: Utc::now(),
            metric_type,
            value,
            endpoint: None,
            tags: BTreeMap::new(),
        }
    }

    /// Scopes the metric to an endpoint.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Adds a string tag.
    #[must_use]
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Overrides the timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Reported health of the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentHealth {
    /// No degradation signals.
    Healthy,
    /// At least one degradation signal is active.
    Degraded,
    /// Reserved for parity with the Python wire model; never produced by
    /// status computation.
    Failed,
}

/// Agent status payload posted to `/api/v1/status`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentStatus {
    /// When the status was computed.
    pub timestamp: DateTime<Utc>,
    /// Computed health.
    pub status: AgentHealth,
    /// Seconds since agent construction.
    pub uptime: f64,
    /// Lifetime count of confirmed events.
    pub events_sent: u64,
    /// Lifetime count of events requeued after failed flushes.
    pub events_failed: u64,
    /// Events plus metrics currently buffered.
    pub buffer_size: u64,
    /// Last successful drain time, when any flush ran.
    pub last_flush: Option<DateTime<Utc>>,
    /// Degradation reasons, empty when healthy.
    pub errors: Vec<String>,
}

/// Acknowledgement body returned by the ingestion API for events, metrics,
/// and status posts (`telemetry_models.py:48-58`, `:107-111`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct TelemetryAck {
    /// Whether ingestion succeeded; absent on the status heartbeat response.
    pub success: Option<bool>,
    /// Per-item or batch level errors; a non-empty list marks a partial
    /// failure that must be requeued.
    pub errors: Option<Vec<String>>,
}

/// Returns the current UTC time, used as the default rule timestamp.
fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Dynamic rules received from the `SaaS` platform via `GET /api/v1/rules`,
/// mirroring the Python agent's `DynamicRules` model field for field
/// (`guard_agent/models.py:250-324`).
///
/// The server serializes the pydantic model, so the wire payload is
/// `snake_case` with ISO-8601 timestamps, `endpoint_rate_limits` as
/// `{endpoint: [requests, window]}` pairs, and `blocked_cloud_providers` as
/// an array (a Python set on the model). Deserialization applies the
/// pydantic defaults for missing fields; a wrong-typed known field fails the
/// parse, which the transport converts to a `None` result exactly like the
/// Python agent's blanket `except`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DynamicRules {
    /// Unique rule ID.
    pub rule_id: String,
    /// Rule version number.
    pub version: u64,
    /// Rule creation/update timestamp.
    #[serde(default = "now_utc")]
    pub timestamp: DateTime<Utc>,
    /// Rule expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Cache TTL in seconds (drives the client-side rules cache).
    pub ttl: u64,
    /// IPs to ban.
    pub ip_blacklist: Vec<String>,
    /// IPs to allow.
    pub ip_whitelist: Vec<String>,
    /// Ban duration in seconds.
    pub ip_ban_duration: u64,
    /// Countries to block.
    pub blocked_countries: Vec<String>,
    /// Countries to allow.
    pub whitelist_countries: Vec<String>,
    /// Global rate limit.
    pub global_rate_limit: Option<u64>,
    /// Global rate window in seconds.
    pub global_rate_window: Option<u64>,
    /// Per-endpoint rate limits: endpoint to `(requests, window)`.
    pub endpoint_rate_limits: BTreeMap<String, (u64, u64)>,
    /// Cloud providers to block.
    pub blocked_cloud_providers: BTreeSet<String>,
    /// User agents to block.
    pub blocked_user_agents: Vec<String>,
    /// Additional suspicious patterns.
    pub suspicious_patterns: Vec<String>,
    /// Override penetration detection setting.
    pub enable_penetration_detection: Option<bool>,
    /// Override IP banning setting.
    pub enable_ip_banning: Option<bool>,
    /// Override rate limiting setting.
    pub enable_rate_limiting: Option<bool>,
    /// Override auto-ban threshold setting.
    pub auto_ban_threshold: Option<u64>,
    /// Override auto-ban duration setting.
    pub auto_ban_duration: Option<u64>,
    /// Override rate-limit auto-ban setting.
    pub enable_rate_limit_auto_ban: Option<bool>,
    /// Emergency lockdown mode.
    pub emergency_mode: bool,
    /// Emergency whitelist IPs.
    pub emergency_whitelist: Vec<String>,
    /// Only allow emergency whitelist IPs.
    pub emergency_whitelist_only: bool,
    /// Optional rule message from the server.
    pub message: Option<String>,
}

impl Default for DynamicRules {
    fn default() -> Self {
        Self {
            rule_id: "default-rule".to_owned(),
            version: 1,
            timestamp: now_utc(),
            expires_at: None,
            ttl: 300,
            ip_blacklist: Vec::new(),
            ip_whitelist: Vec::new(),
            ip_ban_duration: 3600,
            blocked_countries: Vec::new(),
            whitelist_countries: Vec::new(),
            global_rate_limit: None,
            global_rate_window: None,
            endpoint_rate_limits: BTreeMap::new(),
            blocked_cloud_providers: BTreeSet::new(),
            blocked_user_agents: Vec::new(),
            suspicious_patterns: Vec::new(),
            enable_penetration_detection: None,
            enable_ip_banning: None,
            enable_rate_limiting: None,
            auto_ban_threshold: None,
            auto_ban_duration: None,
            enable_rate_limit_auto_ban: None,
            emergency_mode: false,
            emergency_whitelist: Vec::new(),
            emergency_whitelist_only: false,
            message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_serializes_to_the_python_wire_shape() {
        let event = SecurityEvent::new("rate_limited")
            .with_ip_address("10.0.0.1")
            .with_country("US")
            .with_endpoint("/api/users")
            .with_method("GET")
            .with_status_code(429)
            .with_response_time(0.25)
            .with_action_taken("blocked")
            .with_reason("rate limit exceeded")
            .with_metadata(json!({"rule": "rl-1"}));

        let value = serde_json::to_value(&event).unwrap();
        let obj = value.as_object().unwrap();

        for key in [
            "idempotency_key",
            "timestamp",
            "event_type",
            "ip_address",
            "country",
            "user_agent",
            "endpoint",
            "method",
            "decorator_type",
            "rule_type",
            "pattern_matched",
            "handler_name",
            "action_taken",
            "reason",
            "status_code",
            "response_time",
            "metadata",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }

        assert_eq!(obj["event_type"], "rate_limited");
        assert_eq!(obj["ip_address"], "10.0.0.1");
        assert_eq!(obj["status_code"], 429);
        assert_eq!(obj["metadata"]["rule"], "rl-1");
        assert!(obj["country"].is_string());
        assert!(obj["handler_name"].is_null());
        // UUID renders as a hyphenated lowercase string.
        assert_eq!(
            Uuid::parse_str(obj["idempotency_key"].as_str().unwrap()).unwrap(),
            event.idempotency_key
        );
        // Timestamp renders as RFC 3339 with a Z offset.
        let ts = obj["timestamp"].as_str().unwrap();
        assert!(ts.ends_with('Z') || ts.contains('+'), "{ts}");
    }

    #[test]
    fn metric_serializes_with_snake_case_type() {
        let metric = SecurityMetric::new(MetricType::BandwidthUsage, 1024.0)
            .with_endpoint("/api/files")
            .with_tag("region", "us-east");

        let value = serde_json::to_value(&metric).unwrap();
        assert_eq!(value["metric_type"], "bandwidth_usage");
        assert_eq!(value["value"], 1024.0);
        assert_eq!(value["tags"]["region"], "us-east");
        assert_eq!(value["endpoint"], "/api/files");
    }

    #[test]
    fn metric_type_round_trips_all_variants() {
        for metric_type in [
            MetricType::RequestCount,
            MetricType::ResponseTime,
            MetricType::ErrorRate,
            MetricType::BandwidthUsage,
            MetricType::ThreatLevel,
            MetricType::BlockRate,
            MetricType::CacheHitRate,
        ] {
            let rendered = serde_json::to_value(metric_type).unwrap();
            assert_eq!(rendered.as_str().unwrap(), metric_type.as_str());
        }
    }

    #[test]
    fn status_serializes_snake_case() {
        let status = AgentStatus {
            timestamp: Utc::now(),
            status: AgentHealth::Degraded,
            uptime: 12.5,
            events_sent: 3,
            events_failed: 1,
            buffer_size: 2,
            last_flush: None,
            errors: vec!["Buffer nearly full".to_owned()],
        };
        let value = serde_json::to_value(&status).unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["events_sent"], 3);
        assert_eq!(value["events_failed"], 1);
        assert_eq!(value["buffer_size"], 2);
        assert!(value["last_flush"].is_null());
        assert_eq!(value["errors"][0], "Buffer nearly full");
    }

    #[test]
    fn telemetry_ack_parses_partial_failure() {
        let ack: TelemetryAck =
            serde_json::from_str(r#"{"success": false, "errors": ["Event quota exceeded."]}"#)
                .unwrap();
        assert_eq!(ack.success, Some(false));
        assert_eq!(
            ack.errors.as_deref(),
            Some(&["Event quota exceeded.".to_owned()][..])
        );

        let status_ack: TelemetryAck =
            serde_json::from_str(r#"{"success": true, "message": "ok"}"#).unwrap();
        assert_eq!(status_ack.success, Some(true));
        assert!(status_ack.errors.is_none());
    }

    #[test]
    fn event_round_trips_through_wire_json() {
        let event = SecurityEvent::new("ip_banned")
            .with_ip_address("203.0.113.7")
            .with_timestamp(
                DateTime::parse_from_rfc3339("2026-09-20T10:00:00Z")
                    .unwrap()
                    .into(),
            );
        let json = serde_json::to_string(&event).unwrap();
        let parsed: SecurityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn known_event_types_match_the_python_surface() {
        // The Python baseline list has 39 entries.
        assert_eq!(KNOWN_EVENT_TYPES.len(), 39);
        // Wave renames and the trailing entries are part of the pinned
        // surface.
        for expected in [
            "user_agent_blocked",
            "decorator_violation",
            "security_headers_applied",
            "csp_violation",
        ] {
            assert!(KNOWN_EVENT_TYPES.contains(&expected), "missing {expected}");
        }
        // No duplicates.
        let mut seen = KNOWN_EVENT_TYPES.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), KNOWN_EVENT_TYPES.len());
    }

    #[test]
    fn dynamic_rules_defaults_match_the_python_model() {
        let rules = DynamicRules::default();
        assert_eq!(rules.rule_id, "default-rule");
        assert_eq!(rules.version, 1);
        assert_eq!(rules.ttl, 300);
        assert_eq!(rules.ip_ban_duration, 3600);
        assert!(rules.ip_blacklist.is_empty() && rules.ip_whitelist.is_empty());
        assert!(rules.blocked_countries.is_empty() && rules.whitelist_countries.is_empty());
        assert!(rules.global_rate_limit.is_none() && rules.global_rate_window.is_none());
        assert!(rules.endpoint_rate_limits.is_empty());
        assert!(rules.blocked_cloud_providers.is_empty());
        assert!(rules.blocked_user_agents.is_empty() && rules.suspicious_patterns.is_empty());
        assert!(rules.enable_penetration_detection.is_none());
        assert!(rules.enable_ip_banning.is_none());
        assert!(rules.enable_rate_limiting.is_none());
        assert!(rules.auto_ban_threshold.is_none() && rules.auto_ban_duration.is_none());
        assert!(rules.enable_rate_limit_auto_ban.is_none());
        assert!(!rules.emergency_mode && !rules.emergency_whitelist_only);
        assert!(rules.emergency_whitelist.is_empty());
        assert!(rules.message.is_none() && rules.expires_at.is_none());
    }

    #[test]
    fn dynamic_rules_parse_the_snake_case_wire_payload_with_defaults() {
        // Sparse payload: every omitted field takes the pydantic default,
        // exactly like `DynamicRules(**response_data)` in the Python agent.
        let value = json!({
            "rule_id": "rule-42",
            "version": 7,
            "ttl": 60,
            "ip_blacklist": ["9.9.9.9"],
            "blocked_countries": ["KP"],
            "global_rate_limit": 100,
            "global_rate_window": 60,
            "endpoint_rate_limits": {"/api/login": [5, 60]},
            "blocked_cloud_providers": ["AWS", "AWS", "GCP"],
            "enable_ip_banning": true,
            "auto_ban_threshold": 10,
            "emergency_mode": true,
            "emergency_whitelist": ["10.0.0.1"],
            "emergency_whitelist_only": true,
            "message": "lockdown",
            "expires_at": "2030-01-01T00:00:00Z",
            "timestamp": "2026-01-02T03:04:05Z"
        });
        let rules: DynamicRules = serde_json::from_value(value).unwrap();
        assert_eq!(rules.rule_id, "rule-42");
        assert_eq!(rules.version, 7);
        assert_eq!(rules.ttl, 60);
        assert_eq!(rules.ip_blacklist, vec!["9.9.9.9".to_owned()]);
        assert_eq!(rules.ip_ban_duration, 3600);
        assert_eq!(rules.blocked_countries, vec!["KP".to_owned()]);
        assert_eq!(rules.global_rate_limit, Some(100));
        assert_eq!(rules.global_rate_window, Some(60));
        assert_eq!(rules.endpoint_rate_limits.get("/api/login"), Some(&(5, 60)));
        assert_eq!(
            rules.blocked_cloud_providers.len(),
            2,
            "set semantics dedupe"
        );
        assert_eq!(rules.enable_ip_banning, Some(true));
        assert_eq!(rules.auto_ban_threshold, Some(10));
        assert!(rules.emergency_mode && rules.emergency_whitelist_only);
        assert_eq!(rules.emergency_whitelist, vec!["10.0.0.1".to_owned()]);
        assert_eq!(rules.message.as_deref(), Some("lockdown"));
        assert_eq!(
            rules.timestamp,
            DateTime::<Utc>::from(DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z").unwrap())
        );
        assert_eq!(
            rules.expires_at,
            Some(
                DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                    .unwrap()
                    .into()
            )
        );
        assert_eq!(rules.enable_penetration_detection, None);
    }

    #[test]
    fn dynamic_rules_round_trip_serialization_is_snake_case() {
        let mut endpoint_rate_limits = BTreeMap::new();
        endpoint_rate_limits.insert("/x".to_owned(), (3, 30));
        let mut blocked_cloud_providers = BTreeSet::new();
        blocked_cloud_providers.insert("AWS".to_owned());
        let rules = DynamicRules {
            ip_blacklist: vec!["1.2.3.4".to_owned()],
            endpoint_rate_limits,
            blocked_cloud_providers,
            ..DynamicRules::default()
        };

        let value = serde_json::to_value(&rules).unwrap();
        let obj = value.as_object().unwrap();
        for key in [
            "rule_id",
            "ip_blacklist",
            "ip_ban_duration",
            "endpoint_rate_limits",
            "blocked_cloud_providers",
            "emergency_whitelist_only",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        let parsed: DynamicRules = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, rules);
    }

    #[test]
    fn dynamic_rules_reject_wrong_typed_fields_like_pydantic() {
        let result = serde_json::from_value::<DynamicRules>(json!({"ttl": "soon"}));
        assert!(result.is_err(), "string ttl must fail the parse");

        let result = serde_json::from_value::<DynamicRules>(json!({
            "endpoint_rate_limits": {"/x": [5]}
        }));
        assert!(result.is_err(), "incomplete pair must fail the parse");

        let result = serde_json::from_value::<DynamicRules>(json!({
            "ip_blacklist": [1, 2]
        }));
        assert!(
            result.is_err(),
            "non-string list entries must fail the parse"
        );
    }
}
