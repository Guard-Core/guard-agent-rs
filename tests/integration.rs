//! End-to-end integration tests against a wiremock server that mirrors the
//! Guard ingestion API contract.

mod helpers;

use std::time::Duration;

use std::sync::Arc;

use guard_agent_rs::{
    AGENT_VERSION, AgentConfig, AgentHealth, BufferOverflowPolicy, GuardAgent, InMemoryRedisStore,
    MetricType, SecurityEvent, SecurityMetric,
};
use helpers::{Behavior, MockApi, expected_signature};

const API_KEY: &str = "test-api-key-1234";
const INSTALL_ID: &str = "install-test-0001";
const SIGNING_SECRET: &str = "test-signing-secret";

/// Base config pointed at a mock server with fast retries.
fn config_for(mock: &MockApi) -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = mock.uri();
    config.install_id = Some(INSTALL_ID.to_owned());
    config.timeout = 5;
    config.retry_attempts = 3;
    config.backoff_factor = 0.01;
    config.payload_signing_secret = Some(SIGNING_SECRET.to_owned());
    config
}

fn event(index: usize) -> SecurityEvent {
    SecurityEvent::new("rate_limited")
        .with_ip_address(format!("10.0.0.{index}"))
        .with_endpoint("/api/users")
        .with_method("GET")
        .with_action_taken("blocked")
}

/// Polls a condition until it holds or the deadline passes.
async fn wait_until<F>(mut condition: F, deadline: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

#[tokio::test]
async fn failed_flushes_requeue_then_recover_for_both_kinds() {
    let mock = MockApi::start(Behavior::FailThenSuccess {
        status: 500,
        // Exactly the first two batch requests fail: one per kind. The
        // shared request counter makes the recovery flush succeed.
        times: 2,
        body: "server down",
        retry_after: None,
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 0;
    config.flush_interval = 1;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 1.0))
        .await;
    agent.flush_buffer().await;
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 1);
    assert_eq!(stats.metrics_failed, 1);
    assert_eq!(stats.events_buffered, 1, "events requeued in order");
    assert_eq!(stats.metrics_buffered, 1, "metrics requeued in order");

    // An immediate second flush hits both closed retry gates and quietly
    // keeps everything buffered.
    agent.flush_buffer().await;
    let stats = agent.get_stats().await;
    assert_eq!(
        stats.events_buffered, 1,
        "the closed event gate kept the item"
    );
    assert_eq!(
        stats.metrics_buffered, 1,
        "the closed metric gate kept the item"
    );

    // The per-kind retry gates close for the backoff window; past it the
    // next flush succeeds and the failure streaks recover.
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    agent.flush_buffer().await;
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1, "events recovered");
    assert_eq!(stats.metrics_sent, 1, "metrics recovered");
    assert_eq!(stats.events_buffered, 0);
    assert_eq!(stats.metrics_buffered, 0);
}

#[tokio::test]
async fn permanent_rejections_confirm_batches_without_counting_sends() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 400,
        body: "bad request",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 1.0))
        .await;
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 0, "the 400 batch was confirmed");
    assert_eq!(stats.metrics_buffered, 0, "the 400 batch was confirmed");
    assert_eq!(stats.events_sent, 0, "a drop is not a send");
    assert_eq!(stats.metrics_sent, 0);
}

#[tokio::test]
async fn watermark_crossing_spawns_a_gated_flush() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.buffer_size = 4;
    config.high_watermark_ratio = 0.5;
    config.flush_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    // Two items cross the watermark of 2: the second enqueue spawns the
    // gated flush, which drains both without any explicit flush call.
    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;
    agent.stop().await;

    assert!(
        wait_until(|| !mock.event_requests().is_empty(), Duration::from_secs(5)).await,
        "the watermark flush reached the server"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 2, "the spawned flush sent both");
}

#[tokio::test(start_paused = true)]
async fn background_loops_push_status_and_count_rule_failures() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 500,
        body: "down",
    })
    .await;
    let mut config = config_for(&mock);
    config.status_interval = 60;
    config.dynamic_rule_interval = 60;
    // A request still in flight during a pump must not hit its deadline.
    config.timeout = 600;
    let agent = GuardAgent::new(config).unwrap();

    agent.start().await;
    // Four ticks (61 paused seconds each): the failing status pushes and
    // rules polls cross the three-failure log threshold.
    for _ in 0..40 {
        let stats = agent.get_stats().await;
        if stats.loop_failures.status >= 3 && stats.loop_failures.rules >= 3 {
            break;
        }
        pump_once().await;
    }
    let stats = agent.get_stats().await;
    assert!(
        stats.loop_failures.status >= 3,
        "the status loop saturated its counter: {:?}",
        stats.loop_failures
    );
    assert!(
        stats.loop_failures.rules >= 3,
        "the rules loop saturated its counter: {:?}",
        stats.loop_failures
    );
    agent.stop().await;
}

/// Yields once so in-flight paused-time work (loop ticks, HTTP calls)
/// progresses a step.
async fn pump_once() {
    tokio::time::advance(Duration::from_secs(61)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn delivers_events_with_ingestion_headers_and_snake_case_body() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    let sent = event(1);
    agent.send_event(sent.clone()).await;
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 1, "one batch request");
    let request = &requests[0];

    // Auth and identity headers from the verified contract.
    assert_eq!(request.header("x-api-key").as_deref(), Some(API_KEY));
    assert_eq!(
        request.header("x-agent-install-id").as_deref(),
        Some(INSTALL_ID)
    );
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        request.header("user-agent").as_deref(),
        Some(format!("guard-agent-rs/{AGENT_VERSION}").as_str())
    );
    assert!(request.header("x-project-id").is_none());

    // Signature covers the uncompressed body, which is what the server
    // verifies after its gzip middleware decompresses.
    assert_eq!(
        request.header("x-payload-signature").as_deref(),
        Some(expected_signature(SIGNING_SECRET, &request.decompressed_body).as_str())
    );

    let body = request.json();
    assert_eq!(body["project_id"], "default");
    assert_eq!(body["compressed"], false);
    assert_eq!(body["agent_version"], AGENT_VERSION);
    assert!(body["guard_version"].is_null());
    assert_eq!(body["metrics"].as_array().unwrap().len(), 0);

    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "rate_limited");
    assert_eq!(events[0]["ip_address"], "10.0.0.1");
    assert_eq!(events[0]["endpoint"], "/api/users");
    assert_eq!(events[0]["action_taken"], "blocked");
    assert_eq!(
        events[0]["idempotency_key"],
        sent.idempotency_key.to_string()
    );
    assert!(events[0]["timestamp"].as_str().unwrap().contains('T'));
    assert!(events[0]["country"].is_null());

    let batch_id = body["batch_id"].as_str().unwrap();
    assert!(batch_id.contains('-'), "{batch_id}");

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.events_buffered, 0);
    assert_eq!(stats.events_failed, 0);
    assert_eq!(stats.requests_sent, 1);
    assert!(stats.last_flush.is_some());
}

#[tokio::test]
async fn sends_project_header_and_payload_project_id_when_configured() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.project_id = Some("proj_abc123".to_owned());
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert_eq!(
        request.header("x-project-id").as_deref(),
        Some("proj_abc123")
    );
    assert_eq!(request.json()["project_id"], "proj_abc123");
}

#[tokio::test]
async fn gzip_compresses_large_batches_and_signs_the_plain_body() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    // Metadata above the 1024-byte compression threshold.
    let filler = "x".repeat(2_000);
    agent
        .send_event(
            SecurityEvent::new("suspicious_request")
                .with_metadata(serde_json::json!({ "payload": filler })),
        )
        .await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert_eq!(request.header("content-encoding").as_deref(), Some("gzip"));
    assert!(request.raw_body.len() < request.decompressed_body.len());
    assert_eq!(
        request.header("x-payload-signature").as_deref(),
        Some(expected_signature(SIGNING_SECRET, &request.decompressed_body).as_str())
    );
    assert_eq!(request.json()["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn small_batches_are_not_compressed_and_send_no_content_encoding() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert!(request.header("content-encoding").is_none());
    assert_eq!(request.raw_body, request.decompressed_body);
}

#[tokio::test]
async fn signature_header_is_omitted_without_a_secret() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.payload_signing_secret = None;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert!(
        mock.event_requests()[0]
            .header("x-payload-signature")
            .is_none()
    );
}

#[tokio::test]
async fn metrics_go_to_the_metrics_endpoint() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 12.0).with_tag("route", "/x"))
        .await;
    agent.flush_buffer().await;

    assert!(mock.event_requests().is_empty());
    let requests = mock.metric_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].json();
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
    let metrics = body["metrics"].as_array().unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0]["metric_type"], "request_count");
    assert_eq!(metrics[0]["value"], 12.0);
    assert_eq!(metrics[0]["tags"]["route"], "/x");

    let stats = agent.get_stats().await;
    assert_eq!(stats.metrics_sent, 1);
}

#[tokio::test]
async fn retries_server_errors_with_backoff_then_succeeds() {
    let mock = MockApi::start(Behavior::FailThenSuccess {
        status: 500,
        times: 2,
        body: "{\"detail\": \"boom\"}",
        retry_after: None,
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 3, "two failures plus one success");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.events_failed, 0);
    assert_eq!(stats.requests_sent, 3);
    assert_eq!(stats.events_buffered, 0);
}

#[tokio::test]
async fn honors_retry_after_on_429() {
    let mock = MockApi::start(Behavior::FailThenSuccess {
        status: 429,
        times: 1,
        body: "{\"detail\": \"Too many requests\"}",
        retry_after: Some("1"),
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    let started = std::time::Instant::now();
    agent.flush_buffer().await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(900),
        "waited for Retry-After, elapsed {elapsed:?}"
    );
    assert_eq!(mock.event_requests().len(), 2);
    assert_eq!(agent.get_stats().await.events_sent, 1);
}

#[tokio::test]
async fn requeues_after_exhausting_retries() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 503,
        body: "{\"detail\": \"unavailable\"}",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 2;
    config.flush_interval = 3_600; // no background pressure
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        3,
        "initial attempt plus 2 retries"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 1);
    assert_eq!(stats.events_buffered, 1, "requeued in memory");
    assert_eq!(stats.events_sent, 0);
    assert_eq!(stats.requests_failed, 1);

    // A second flush is gated by the per-kind backoff, so no new request.
    agent.flush_buffer().await;
    assert_eq!(mock.event_requests().len(), 3, "gated by streak backoff");
}

#[tokio::test]
async fn permanent_rejection_drops_the_batch_without_retrying() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 400,
        body: "{\"detail\": \"Malformed batch\"}",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1, "no retries on 400");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 0, "intentionally dropped");
    assert_eq!(stats.events_failed, 0, "drop is not a failed send");
    assert_eq!(stats.events_sent, 0);

    // Nothing left to send.
    agent.flush_buffer().await;
    assert_eq!(mock.event_requests().len(), 1);
}

#[tokio::test]
async fn treats_partial_failure_200_as_requeue() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 200,
        body: "{\"success\": false, \"errors\": [\"Event quota exceeded. Upgrade your plan.\"]}",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        1,
        "200 is terminal, no in-loop retry"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 1);
    assert_eq!(stats.events_buffered, 1);
}

#[tokio::test]
async fn partial_failure_warning_says_memory_only_without_redis() {
    helpers::init_log_capture();
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 200,
        body: "{\"success\": false, \"errors\": [\"Event quota exceeded. Upgrade your plan.\"]}",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let warnings = helpers::captured_warnings();
    let warning = warnings
        .iter()
        .find(|message| message.contains("Failed to send 1 events"))
        .expect("partial-failure warning captured");
    assert!(
        warning.contains("requeued in memory (events) for retry"),
        "warning must describe memory-only retention without Redis: {warning}"
    );
    assert!(
        !warnings
            .iter()
            .any(|message| message.contains("retained in Redis")),
        "no warning may claim Redis retention when no Redis handler is attached"
    );
}

#[tokio::test]
async fn splits_on_413_until_each_half_fits() {
    let mock = MockApi::start(Behavior::TooLargeAbove { threshold: 2 }).await;
    let mut config = config_for(&mock);
    config.buffer_size = 10;
    let agent = GuardAgent::new(config).unwrap();

    let mut keys = Vec::new();
    for index in 0..4 {
        let item = event(index);
        keys.push(item.idempotency_key.to_string());
        agent.send_event(item).await;
    }
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 3, "4 items rejected, then 2 + 2 accepted");
    assert_eq!(requests[0].json()["events"].as_array().unwrap().len(), 4);

    let mut received = mock.received_event_keys();
    received.sort();
    keys.sort();
    assert_eq!(received, keys, "every event delivered exactly once");
    assert_eq!(agent.get_stats().await.events_sent, 4);
    assert_eq!(agent.get_stats().await.events_buffered, 0);
}

#[tokio::test]
async fn drops_a_singleton_that_still_exceeds_the_cap() {
    let mock = MockApi::start(Behavior::AlwaysTooLarge).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1, "singleton is not split");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 0, "dropped, not requeued");
    assert_eq!(
        stats.events_failed, 0,
        "intentional drop counts as confirmed"
    );
}

#[tokio::test]
async fn auth_failures_are_retried_like_the_python_agent() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 401,
        body: "{\"detail\": \"Invalid API key or project ID\"}",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 1;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        2,
        "401 is retryable, not permanent"
    );
    assert_eq!(agent.get_stats().await.events_buffered, 1);
}

#[tokio::test]
async fn status_push_posts_the_agent_status_payload() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.push_status().await;

    let requests = mock.status_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].json();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["events_sent"], 0);
    assert_eq!(body["buffer_size"], 0);
    assert!(body["uptime"].as_f64().unwrap() >= 0.0);
    assert!(body["last_flush"].is_null());

    let stats = agent.get_stats().await;
    assert_eq!(stats.last_status_push_ok, Some(true));
    assert_eq!(stats.status_consecutive_failures, 0);
}

#[tokio::test]
async fn status_push_failures_are_counted_not_propagated() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 500,
        body: "boom",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 0;
    let agent = GuardAgent::new(config).unwrap();

    agent.push_status().await;
    agent.push_status().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.last_status_push_ok, Some(false));
    assert_eq!(stats.status_consecutive_failures, 2);
    assert_eq!(stats.loop_failures.status, 2);
}

#[tokio::test]
async fn endpoint_down_isolates_failures_and_reports_degraded() {
    let mut config = AgentConfig::new(API_KEY);
    // Port 9 (discard) is not listening; connection is refused immediately.
    config.endpoint = "http://127.0.0.1:9".to_owned();
    config.install_id = Some(INSTALL_ID.to_owned());
    config.timeout = 1;
    // Enough attempts in a single flush to trip the breaker threshold (5).
    config.retry_attempts = 6;
    config.backoff_factor = 0.01;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    // Ingest must never fail or panic, even with the endpoint down.
    for index in 0..3 {
        agent.send_event(event(index)).await;
    }
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 3, "batch requeued");
    assert_eq!(stats.events_buffered, 3, "events survive the outage");
    assert!(stats.requests_failed >= 1);

    let health = agent.get_status().await;
    assert_eq!(health.status, AgentHealth::Degraded);
    assert!(
        health
            .errors
            .iter()
            .any(|error| error.contains("High failure rate")),
        "{:?}",
        health.errors
    );
    assert_eq!(
        stats.circuit_breaker_state.as_str(),
        "OPEN",
        "breaker opens after repeated transport failures"
    );
    assert!(
        health
            .errors
            .iter()
            .any(|error| error == "Transport circuit breaker is open"),
        "{:?}",
        health.errors
    );
    assert!(
        !agent.health_check().await,
        "unhealthy under a total outage"
    );

    agent.stop().await;
}

#[tokio::test]
async fn shutdown_flush_delivers_buffered_events() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;
    assert!(mock.event_requests().is_empty(), "no flush yet");

    agent.stop().await;

    let received = mock.received_event_keys();
    assert_eq!(received.len(), 2, "final flush on shutdown");
    let stats = agent.get_stats().await;
    assert!(!stats.running);
    assert_eq!(stats.events_buffered, 0);
}

#[tokio::test]
async fn watermark_triggers_an_early_flush() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.buffer_size = 10;
    config.high_watermark_ratio = 0.8;
    config.flush_interval = 3_600; // only the watermark can trigger a flush
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    for index in 0..8 {
        agent.send_event(event(index)).await;
    }

    let delivered = wait_until(
        || mock.received_event_keys().len() == 8,
        Duration::from_secs(3),
    )
    .await;
    assert!(delivered, "watermark flush delivered the batch");
    assert_eq!(agent.get_stats().await.events_buffered, 0);

    agent.stop().await;
}

#[tokio::test]
async fn flush_interval_triggers_a_time_based_flush() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.flush_interval = 1;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;

    let delivered = wait_until(
        || mock.received_event_keys().len() == 1,
        Duration::from_secs(4),
    )
    .await;
    assert!(delivered, "time trigger flushed the buffer");

    agent.stop().await;
}

#[tokio::test]
async fn redaction_happens_before_buffering_and_on_the_wire() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent
        .send_event(
            SecurityEvent::new("auth_failure").with_metadata(serde_json::json!({
                "authorization": "Bearer super-secret",
                "nested": { "X-API-Key": "key-material" },
                "safe": "value"
            })),
        )
        .await;
    agent.flush_buffer().await;

    let body = mock.event_requests()[0].json();
    let metadata = &body["events"][0]["metadata"];
    assert_eq!(metadata["authorization"], "[REDACTED]");
    assert_eq!(metadata["nested"]["X-API-Key"], "[REDACTED]");
    assert_eq!(metadata["safe"], "value");
}

#[tokio::test]
async fn metrics_and_events_flush_independently() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::ErrorRate, 0.5))
        .await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1);
    assert_eq!(mock.metric_requests().len(), 1);
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.metrics_sent, 1);
    assert_eq!(stats.events_flushed, 1);
    assert_eq!(stats.metrics_flushed, 1);
    assert!(stats.bytes_sent > 0);
}

#[tokio::test]
async fn failed_flush_requeue_evicts_at_capacity_and_confirms_the_evicted() {
    // A delayed 500 keeps the flush in flight while the buffer refills; the
    // failed send then requeues more items than the capacity, evicting the
    // newest tail items whose records are confirmed immediately.
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(|_request: &wiremock::Request| {
            wiremock::ResponseTemplate::new(500)
                .set_body_string("down")
                .set_delay(std::time::Duration::from_millis(500))
        })
        .mount(&server)
        .await;
    let store = Arc::new(InMemoryRedisStore::new());
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = server.uri();
    config.install_id = Some(INSTALL_ID.to_owned());
    config.timeout = 5;
    config.retry_attempts = 0;
    config.backoff_factor = 0.01;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config.buffer_size = 2;
    config.buffer_overflow_policy = BufferOverflowPolicy::Drop;
    let agent = GuardAgent::new(config).unwrap();
    agent
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;

    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 1.0))
        .await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 2.0))
        .await;

    // The in-flight flush drains both kinds; while it waits on the delayed
    // 500, new items fill both buffers back to capacity.
    let flush_agent = agent.clone();
    let flush = tokio::spawn(async move { flush_agent.flush_buffer().await });
    // Each batch request is delayed 500ms: the events send is in flight
    // around 150ms, the metrics send around 750ms.
    tokio::time::sleep(Duration::from_millis(150)).await;
    agent.send_event(event(3)).await;
    agent.send_event(event(4)).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 3.0))
        .await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 4.0))
        .await;

    let _ = flush.await;
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 2, "the delayed send failed");
    assert_eq!(stats.metrics_failed, 2, "the delayed send failed");
    assert_eq!(stats.events_buffered, 2, "capacity holds after the requeue");
    assert_eq!(
        stats.metrics_buffered, 2,
        "capacity holds after the requeue"
    );
    // The two evicted tail items had durable records; their keys were
    // confirmed (deleted) so they can never be reloaded.
    assert!(
        store.keys(guard_agent_rs::NAMESPACE_EVENTS).len() <= 2,
        "evicted records are confirmed, retained records stay durable"
    );
}
