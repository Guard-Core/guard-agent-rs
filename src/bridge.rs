//! The guard-core-rs engine seam: [`GuardAgentTelemetry`] implements the
//! facade's [`TelemetryHandler`] sink trait.
//!
//! The composite fan-out (`guard_core_rs::composite::CompositeAgentHandler`)
//! hands the agent every middleware-emitted event and metric - the Rust
//! counterpart of the reference
//! `agent_handler=GuardAgentHandler(...)` handoff (`guard_core`
//! constructs the agent `SecurityEvent` and awaits
//! `agent_handler.send_event`). The mapping is name for name (the
//! reference builds the agent model from the shared field names in
//! `_utils/agent_events.py`):
//! `event_type`, `ip_address`, `country`, `user_agent`, `endpoint`,
//! `method`, `decorator_type`, `rule_type`, `handler_name`,
//! `action_taken`, `reason`, and `response_time` transfer directly; the
//! facade carries `status_code` and `pattern_matched` in its free-form
//! `metadata` bag (the reference's per-site kwargs), and both surface as
//! the wire fields when present. The fresh idempotency key stamps on
//! construction. The `metadata` bag forwards as the wire `metadata`
//! object (the agent redacts sensitive keys at ingest).
//!
//! The threading contract: the facade's sink trait is synchronous (the
//! engine's I/O-free seam idiom) while the agent is async, so
//!
//! - the send paths (`send_event`, `send_metric`) `spawn` onto the
//!   wired runtime - fire-and-forget from any thread, exactly the
//!   reference's awaited-then-buffered posture (buffering cannot fail);
//! - the lifecycle paths (`start`, `stop`, `flush_buffer`,
//!   `health_check`, `get_dynamic_rules`) `block_on` the wired runtime -
//!   call them off the async request path (startup, shutdown, admin),
//!   the way the reference middleware drives the handler lifecycle
//!   outside the request hot path.
//!
//! `initialize_redis` rides the trait default (`Ok`): the agent attaches
//! its own persistence through
//! [`attach_redis_handler`](GuardAgent::attach_redis_handler), the
//! reference's `initialize_agent`/`initialize_redis` pairing.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use guard_agent_rs::bridge::GuardAgentTelemetry;
//! use guard_agent_rs::{AgentConfig, GuardAgent};
//! use guard_core_rs::composite::TelemetryHandler;
//!
//! let config = AgentConfig::new("your-api-key-at-least-10-chars");
//! let agent = Arc::new(GuardAgent::new(config).expect("valid config"));
//! let runtime = tokio::runtime::Builder::new_multi_thread()
//!     .enable_all()
//!     .build()
//!     .expect("runtime");
//! let telemetry = GuardAgentTelemetry::new(Arc::clone(&agent), runtime.handle().clone());
//!
//! assert_eq!(telemetry.handler_name(), "GuardAgent");
//! // A not-yet-started agent answers unhealthy through the sync seam.
//! assert!(!telemetry.health_check());
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use guard_core_rs::composite::{TelemetryError, TelemetryHandler};
use guard_core_rs::events::SecurityEvent as FacadeSecurityEvent;
use guard_core_rs::metrics::SecurityMetric as FacadeSecurityMetric;
use tokio::runtime::Handle;

use crate::agent::GuardAgent;
use crate::models::{MetricType, SecurityEvent, SecurityMetric};

/// The agent as a composite sink: the engine-to-agent seam. Cloneable
/// (both halves are handles).
#[derive(Clone)]
pub struct GuardAgentTelemetry {
    agent: Arc<GuardAgent>,
    runtime: Handle,
}

impl core::fmt::Debug for GuardAgentTelemetry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardAgentTelemetry")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl GuardAgentTelemetry {
    /// A bridge over the agent and the runtime that drives it.
    #[must_use]
    pub const fn new(agent: Arc<GuardAgent>, runtime: Handle) -> Self {
        Self { agent, runtime }
    }

    /// The reference constructor map: a fresh agent-model `SecurityEvent`
    /// from the facade's middleware record, name for name.
    #[must_use]
    pub fn to_agent_event(event: &FacadeSecurityEvent) -> SecurityEvent {
        SecurityEvent {
            timestamp: DateTime::<Utc>::from(event.timestamp),
            event_type: event.event_type.clone(),
            ip_address: event.ip_address.clone(),
            country: event.country.clone(),
            user_agent: event.user_agent.clone(),
            endpoint: event.endpoint.clone(),
            method: event.method.clone(),
            decorator_type: event.decorator_type.clone(),
            rule_type: event.rule_type.clone(),
            pattern_matched: string_kwarg(&event.metadata, "pattern_matched"),
            handler_name: event.handler_name.clone(),
            action_taken: event.action_taken.clone(),
            reason: event.reason.clone(),
            status_code: event
                .metadata
                .get("status_code")
                .and_then(serde_json::Value::as_i64)
                .and_then(|code| u16::try_from(code).ok()),
            response_time: event.response_time,
            metadata: serde_json::Value::Object(event.metadata.clone()),
            ..SecurityEvent::new(event.event_type.clone())
        }
    }

    /// The metric map: the seven wire types parse from the facade's
    /// `METRIC_*` strings; an unknown type is a sink error (the
    /// composite reports it, the reference logs-and-continues at the
    /// same layer).
    ///
    /// # Errors
    ///
    /// [`TelemetryError`] when the metric type is outside the seven the
    /// wire model accepts.
    pub fn to_agent_metric(
        metric: &FacadeSecurityMetric,
    ) -> Result<SecurityMetric, TelemetryError> {
        let metric_type = MetricType::from_str_name(&metric.metric_type).ok_or_else(|| {
            TelemetryError(format!(
                "unknown metric type '{}': the wire model accepts the seven METRIC_* types",
                metric.metric_type
            ))
        })?;
        Ok(SecurityMetric {
            timestamp: DateTime::<Utc>::from(metric.timestamp),
            metric_type,
            value: metric.value,
            endpoint: metric.endpoint.clone(),
            tags: metric.tags.clone(),
        })
    }

    /// The rules payload carrier: the wire model serializes into the
    /// trait's JSON value slot.
    ///
    /// # Errors
    ///
    /// [`TelemetryError`] when the serialization fails (the model is
    /// JSON-derived, so the arm is the defensive guard).
    pub fn serialize_rules(
        rules: crate::models::DynamicRules,
    ) -> Result<Option<serde_json::Value>, TelemetryError> {
        serde_json::to_value(rules)
            .map(Some)
            .map_err(|error| TelemetryError(format!("dynamic rules serialization: {error}")))
    }
}

fn string_kwarg(
    metadata: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

impl MetricType {
    /// The wire-name parse (the seven `METRIC_*` strings).
    #[must_use]
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "request_count" => Some(Self::RequestCount),
            "response_time" => Some(Self::ResponseTime),
            "error_rate" => Some(Self::ErrorRate),
            "bandwidth_usage" => Some(Self::BandwidthUsage),
            "threat_level" => Some(Self::ThreatLevel),
            "block_rate" => Some(Self::BlockRate),
            "cache_hit_rate" => Some(Self::CacheHitRate),
            _ => None,
        }
    }
}

impl TelemetryHandler for GuardAgentTelemetry {
    fn handler_name(&self) -> &'static str {
        "GuardAgent"
    }

    fn start(&self) -> Result<(), TelemetryError> {
        self.runtime.block_on(self.agent.start());
        Ok(())
    }

    fn stop(&self) -> Result<(), TelemetryError> {
        self.runtime.block_on(self.agent.stop());
        Ok(())
    }

    fn send_event(&self, event: &FacadeSecurityEvent) -> Result<(), TelemetryError> {
        let agent = Arc::clone(&self.agent);
        let agent_event = Self::to_agent_event(event);
        self.runtime.spawn(async move {
            agent.send_event(agent_event).await;
        });
        Ok(())
    }

    fn send_metric(&self, metric: &FacadeSecurityMetric) -> Result<(), TelemetryError> {
        let agent = Arc::clone(&self.agent);
        let agent_metric = Self::to_agent_metric(metric)?;
        self.runtime.spawn(async move {
            agent.send_metric(agent_metric).await;
        });
        Ok(())
    }

    fn flush_buffer(&self) -> Result<(), TelemetryError> {
        self.runtime.block_on(self.agent.flush_buffer());
        Ok(())
    }

    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        let rules = self.runtime.block_on(self.agent.get_dynamic_rules());
        rules.map_or(Ok(None), Self::serialize_rules)
    }

    fn health_check(&self) -> bool {
        self.runtime.block_on(self.agent.health_check())
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use crate::config::AgentConfig;
    use crate::models::SecurityEvent as AgentEvent;
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    fn facade_event() -> FacadeSecurityEvent {
        let mut event = FacadeSecurityEvent::new(
            "penetration_attempt",
            "192.0.2.1",
            "request_blocked",
            "sqli in ?q=",
            "middleware",
        );
        event.country = Some(String::from("US"));
        event.user_agent = Some(String::from("curl/8"));
        event.endpoint = Some(String::from("/login"));
        event.method = Some(String::from("POST"));
        event.response_time = Some(0.25);
        event.decorator_type = Some(String::from("authentication"));
        event.rule_type = Some(String::from("return_pattern"));
        event.metadata.insert(
            String::from("status_code"),
            serde_json::Value::Number(serde_json::Number::from(403_i64)),
        );
        event.metadata.insert(
            String::from("pattern_matched"),
            serde_json::Value::String(String::from("union select")),
        );
        event.metadata.insert(
            String::from("guard.service.name"),
            serde_json::Value::String(String::from("edge-svc")),
        );
        event
    }

    /// The bridge over a wiremock server: the rules endpoint answers
    /// `200` with the reference-shaped payload and every ingest endpoint
    /// answers `200`, so the lifecycle runs instantly and
    /// deterministically (the server must stay bound for the test's
    /// lifetime - hold the returned handle).
    fn bridge_with(
        rules_payload: Option<serde_json::Value>,
    ) -> (
        GuardAgentTelemetry,
        Arc<GuardAgent>,
        tokio::runtime::Runtime,
        wiremock::MockServer,
    ) {
        use wiremock::ResponseTemplate;

        crate::test_support::install_trace_logger();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let server = runtime.block_on(wiremock::MockServer::start());
        let rules_answer = ResponseTemplate::new(200).set_body_json(
            rules_payload.unwrap_or_else(|| serde_json::json!({"rule_id": "rule-1", "version": 1})),
        );
        runtime.block_on(async {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/rules"))
                .respond_with(rules_answer)
                .mount(&server)
                .await;
            for ingest in ["/api/v1/events", "/api/v1/metrics", "/api/v1/status"] {
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .and(wiremock::matchers::path(ingest))
                    .respond_with(ResponseTemplate::new(200))
                    .mount(&server)
                    .await;
            }
        });

        let mut config = AgentConfig::new("test-api-key-at-least-10-chars");
        config.endpoint = server.uri();
        let agent = Arc::new(GuardAgent::new(config).expect("valid config"));
        let telemetry = GuardAgentTelemetry::new(Arc::clone(&agent), runtime.handle().clone());
        (telemetry, agent, runtime, server)
    }

    fn bridge() -> (
        GuardAgentTelemetry,
        Arc<GuardAgent>,
        tokio::runtime::Runtime,
        wiremock::MockServer,
    ) {
        bridge_with(None)
    }

    fn wait_for(check: impl Fn() -> bool) {
        wait_for_deadline(check, Duration::from_secs(5));
    }

    fn wait_for_deadline(check: impl Fn() -> bool, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        while std::time::Instant::now() < deadline {
            if check() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the spawned send never landed");
    }

    #[test]
    fn the_event_map_is_name_for_name() {
        let converted = GuardAgentTelemetry::to_agent_event(&facade_event());
        assert_eq!(converted.event_type, "penetration_attempt");
        assert_eq!(converted.ip_address, "192.0.2.1");
        assert_eq!(converted.country.as_deref(), Some("US"));
        assert_eq!(converted.user_agent.as_deref(), Some("curl/8"));
        assert_eq!(converted.endpoint.as_deref(), Some("/login"));
        assert_eq!(converted.method.as_deref(), Some("POST"));
        assert_eq!(converted.decorator_type.as_deref(), Some("authentication"));
        assert_eq!(converted.rule_type.as_deref(), Some("return_pattern"));
        assert_eq!(converted.handler_name.as_deref(), Some("middleware"));
        assert_eq!(converted.action_taken, "request_blocked");
        assert_eq!(converted.reason, "sqli in ?q=");
        assert_eq!(converted.response_time, Some(0.25));
        assert_eq!(converted.status_code, Some(403));
        assert_eq!(converted.pattern_matched.as_deref(), Some("union select"));
        assert_eq!(
            converted.metadata["guard.service.name"],
            serde_json::json!("edge-svc")
        );
        assert_eq!(converted.idempotency_key.to_string().len(), 36);
    }

    #[test]
    fn the_absent_kwargs_surface_as_none() {
        let plain =
            FacadeSecurityEvent::new("ip_blocked", "10.0.0.9", "logged_only", "r", "ip_ban");
        let converted = GuardAgentTelemetry::to_agent_event(&plain);
        assert!(converted.status_code.is_none());
        assert!(converted.pattern_matched.is_none());
        assert!(converted.country.is_none());
        // An out-of-u16 status code maps to none (the wire field is u16).
        let mut event = plain;
        event.metadata.insert(
            String::from("status_code"),
            serde_json::Value::Number(serde_json::Number::from(70_000_i64)),
        );
        assert!(
            GuardAgentTelemetry::to_agent_event(&event)
                .status_code
                .is_none()
        );
    }

    #[test]
    fn the_metric_map_covers_the_seven_wire_types_and_rejects_unknowns() {
        let names = [
            "request_count",
            "response_time",
            "error_rate",
            "bandwidth_usage",
            "threat_level",
            "block_rate",
            "cache_hit_rate",
        ];
        for name in names {
            let metric = FacadeSecurityMetric {
                timestamp: SystemTime::now(),
                metric_type: name.to_owned(),
                value: 1.5,
                endpoint: Some(String::from("/api")),
                tags: BTreeMap::from([(String::from("method"), String::from("GET"))]),
            };
            let converted = GuardAgentTelemetry::to_agent_metric(&metric)
                .unwrap_or_else(|error| panic!("{name} converts: {error}"));
            assert_eq!(converted.metric_type.as_str(), name);
            assert!((converted.value - 1.5).abs() < 1e-12);
            assert_eq!(converted.endpoint.as_deref(), Some("/api"));
            assert_eq!(converted.tags["method"], "GET");
        }

        let unknown = FacadeSecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("mystery"),
            value: 1.0,
            endpoint: None,
            tags: BTreeMap::new(),
        };
        let error = GuardAgentTelemetry::to_agent_metric(&unknown)
            .expect_err("unknown types are sink errors");
        assert!(error.0.contains("unknown metric type 'mystery'"));
    }

    #[test]
    fn the_debug_shape_and_the_sink_name_render() {
        let (telemetry, _agent, _runtime, _server) = bridge();
        assert_eq!(telemetry.handler_name(), "GuardAgent");
        let debug = format!("{telemetry:?}");
        assert!(debug.contains("GuardAgentTelemetry"));
        assert!(debug.contains("runtime"));
    }

    #[test]
    fn the_rules_carrier_serializes_the_wire_model() {
        use crate::models::DynamicRules;
        let rules = DynamicRules {
            rule_id: String::from("rule-1"),
            version: 3,
            ttl: 300,
            ..serde_json::from_str::<DynamicRules>("{}").expect("the serde default shape")
        };
        let value = GuardAgentTelemetry::serialize_rules(rules).expect("serializes");
        let value = value.expect("some payload");
        assert_eq!(value["rule_id"], "rule-1");
        assert_eq!(value["version"], 3);
    }

    #[test]
    fn the_wait_helper_panics_when_the_condition_never_holds() {
        let missed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_for_deadline(|| false, Duration::from_millis(30));
        }));
        assert!(missed.is_err(), "a never-true check times out into a panic");
    }

    #[test]
    fn the_lifecycle_rides_the_sync_seam() {
        let (telemetry, agent, runtime, _server) = bridge();

        // A not-yet-started agent answers unhealthy.
        assert!(!telemetry.health_check());

        telemetry.start().expect("start");
        // The send paths buffer through the spawned tasks.
        telemetry.send_event(&facade_event()).expect("send event");
        let metric = FacadeSecurityMetric {
            timestamp: SystemTime::now(),
            metric_type: String::from("response_time"),
            value: 0.4,
            endpoint: Some(String::from("/api")),
            tags: BTreeMap::new(),
        };
        telemetry.send_metric(&metric).expect("send metric");

        wait_for(|| {
            let stats = runtime.block_on(agent.get_stats());
            stats.events_buffered == 1 && stats.metrics_buffered == 1
        });

        // The started, near-empty agent answers healthy.
        assert!(telemetry.health_check());

        // An empty-buffer flush returns without touching the transport.
        let (quiet, _quiet_agent, _quiet_runtime, _quiet_server) = bridge();
        quiet.flush_buffer().expect("empty-buffer flush");

        // The rules fetch rides the mock's payload through the trait's
        // serialization slot.
        let rules = telemetry.get_dynamic_rules().expect("rules");
        let rules = rules.expect("the mock answers a rules payload");
        assert_eq!(rules["rule_id"], "rule-1");

        // The started agent answers healthy; the stopped one does not.
        assert!(telemetry.health_check());
        telemetry.stop().expect("stop");
        assert!(!telemetry.health_check(), "stopped agents answer false");
    }

    #[test]
    fn the_composite_drives_the_agent_through_the_bus_adapter() {
        let (telemetry, agent, runtime, _server) = bridge();
        telemetry.start().expect("start");

        let composite = guard_core_rs::composite::CompositeAgentHandler::new(
            vec![Arc::new(telemetry)],
            guard_core_rs::events::EventFilter::default(),
            guard_core_rs::metrics::MetricFilter::new(Vec::<String>::new()),
            None,
        );
        let bus = guard_core_rs::events::SecurityEventBus::new(true).on_event({
            let composite = std::sync::Arc::new(composite);
            composite.event_handler()
        });
        bus.send_middleware_event("rate_limited", "192.0.2.7", "request_blocked", "limit");

        wait_for(|| {
            let stats = runtime.block_on(agent.get_stats());
            stats.events_buffered == 1
        });
        runtime.block_on(agent.stop());
    }

    #[test]
    fn an_agent_event_round_trip_keeps_the_shape() {
        // The wire model round trip: serde sees the same field names the
        // Python agent posts.
        let converted = GuardAgentTelemetry::to_agent_event(&facade_event());
        let json = serde_json::to_value(&converted).expect("serialize");
        for key in [
            "idempotency_key",
            "timestamp",
            "event_type",
            "ip_address",
            "status_code",
            "pattern_matched",
        ] {
            assert!(json.get(key).is_some(), "missing wire field {key}");
        }
        let _ = AgentEvent::new("unused");
    }
}
