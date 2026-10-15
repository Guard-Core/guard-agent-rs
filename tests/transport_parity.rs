//! Transport and flush parity with the Python agent
//! (`_transport_send.py`, `_transport_dispatch.py`, `_client_flush.py`,
//! `_client_loops.py`, `client.py`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use guard_agent_rs::{
    AgentConfig, CircuitBreakerState, GuardAgent, PayloadEncryptor, SecurityEvent,
};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn config_for(server: &MockServer) -> AgentConfig {
    let mut config = AgentConfig::new("test-api-key-1234");
    config.endpoint = server.uri();
    config.install_id = Some("install-test-0001".to_owned());
    config.timeout = 5;
    config.retry_attempts = 3;
    config.backoff_factor = 0.01;
    config.compression_enabled = false;
    config
}

fn event(index: usize) -> SecurityEvent {
    SecurityEvent::new("rate_limited").with_ip_address(format!("10.0.0.{index}"))
}

async fn mount_events(server: &MockServer, template: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(template)
        .mount(server)
        .await;
}

async fn paths(server: &MockServer, wanted: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == wanted)
        .count()
}

/// Flushes with a deadline so a backoff sleep the reference does not take
/// fails the test instead of hanging it.
async fn flush_within(agent: &GuardAgent, seconds: u64) {
    tokio::time::timeout(Duration::from_secs(seconds), agent.flush_buffer())
        .await
        .expect("the flush finished without backoff sleeps");
}

fn decrypted_ips(request: &Request) -> Vec<String> {
    let envelope: Value = serde_json::from_slice(&request.body).unwrap();
    let encryptor = PayloadEncryptor::new(KEY).unwrap();
    let inner = encryptor
        .decrypt(envelope["encrypted_payload"].as_str().unwrap(), None)
        .unwrap();
    inner["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["ip_address"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn encrypted_413_splits_and_reencrypts_each_half() {
    let server = MockServer::start().await;
    let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let log = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/api/v1/events/encrypted"))
        .respond_with(move |request: &Request| {
            let ips = decrypted_ips(request);
            let too_big = ips.len() > 2;
            log.lock().unwrap().push(ips);
            if too_big {
                ResponseTemplate::new(413).set_body_string("too large")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"success": true}))
            }
        })
        .mount(&server)
        .await;
    let mut config = config_for(&server);
    config.project_encryption_key = Some(KEY.to_owned());
    let agent = GuardAgent::new(config).unwrap();

    for index in 0..4 {
        agent.send_event(event(index)).await;
    }
    agent.flush_buffer().await;

    let batches = seen.lock().unwrap().clone();
    assert_eq!(batches.len(), 3, "4 rejected, then 2 + 2: {batches:?}");
    let mut delivered: Vec<String> = batches[1..].concat();
    delivered.sort();
    assert_eq!(delivered, ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 4, "every event reached the server");
    assert_eq!(stats.events_buffered, 0);
}

#[tokio::test]
async fn the_right_half_is_still_sent_when_the_left_half_fails() {
    let server = MockServer::start().await;
    let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let log = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let ips: Vec<String> = body["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["ip_address"].as_str().unwrap().to_owned())
                .collect();
            log.lock().unwrap().push(ips.clone());
            if ips.len() > 2 {
                ResponseTemplate::new(413).set_body_string("too large")
            } else if ips.contains(&"10.0.0.0".to_owned()) {
                ResponseTemplate::new(500).set_body_string("down")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"success": true}))
            }
        })
        .mount(&server)
        .await;
    let mut config = config_for(&server);
    config.retry_attempts = 0;
    let agent = GuardAgent::new(config).unwrap();

    for index in 0..4 {
        agent.send_event(event(index)).await;
    }
    agent.flush_buffer().await;

    let batches = seen.lock().unwrap().clone();
    assert!(
        batches.contains(&vec!["10.0.0.2".to_owned(), "10.0.0.3".to_owned()]),
        "the right half was sent despite the left failing: {batches:?}"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 4, "the whole batch is requeued");
    assert_eq!(stats.events_sent, 0);
    assert_eq!(stats.events_failed, 4);
}

#[tokio::test]
async fn a_dropped_permanent_rejection_counts_as_sent() {
    let server = MockServer::start().await;
    mount_events(&server, ResponseTemplate::new(400).set_body_string("bad")).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/metrics"))
        .respond_with(ResponseTemplate::new(422).set_body_string("bad"))
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server)).unwrap();

    agent.send_event(event(1)).await;
    agent
        .send_metric(guard_agent_rs::SecurityMetric::new(
            guard_agent_rs::MetricType::RequestCount,
            1.0,
        ))
        .await;
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1, "reference: sent += len on a drop");
    assert_eq!(stats.metrics_sent, 1);
    assert_eq!(stats.events_failed, 0);
    assert_eq!(stats.events_buffered, 0);
}

/// Yields so in-flight paused-time work (loop ticks, HTTP calls) progresses.
async fn pump_once() {
    tokio::time::advance(Duration::from_secs(61)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

async fn rules_agent(server: &MockServer, project_id: Option<&str>) -> GuardAgent {
    Mock::given(path("/api/v1/rules"))
        .respond_with(ResponseTemplate::new(500))
        .mount(server)
        .await;
    let mut config = config_for(server);
    config.project_id = project_id.map(str::to_owned);
    config.dynamic_rule_interval = 60;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config.retry_attempts = 0;
    config.timeout = 600;
    GuardAgent::new(config).unwrap()
}

#[tokio::test(start_paused = true)]
async fn rules_polling_needs_a_project_id() {
    let server = MockServer::start().await;
    let agent = rules_agent(&server, None).await;
    agent.start().await;
    for _ in 0..5 {
        pump_once().await;
    }
    agent.stop().await;
    assert_eq!(paths(&server, "/api/v1/rules").await, 0);
}

#[tokio::test(start_paused = true)]
async fn rules_polling_runs_with_a_project_id() {
    let server = MockServer::start().await;
    let agent = rules_agent(&server, Some("proj-1")).await;
    agent.start().await;
    for _ in 0..5 {
        pump_once().await;
    }
    agent.stop().await;
    assert!(paths(&server, "/api/v1/rules").await >= 1);
}

#[tokio::test]
async fn failed_flushes_do_not_accumulate_the_flush_loop_counter() {
    let server = MockServer::start().await;
    mount_events(&server, ResponseTemplate::new(500)).await;
    let mut config = config_for(&server);
    config.flush_interval = 1;
    config.status_interval = 3_600;
    config.dynamic_rule_interval = 3_600;
    config.retry_attempts = 0;
    let agent = GuardAgent::new(config).unwrap();
    agent.send_event(event(1)).await;
    agent.start().await;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let stats = agent.get_stats().await;
    agent.stop().await;
    assert!(stats.events_failed >= 1, "the flush really failed");
    assert_eq!(
        stats.loop_failures.flush, 0,
        "reference: the flush loop counter resets every iteration"
    );
}

/// Statuses and bodies the reference treats as a transient "no result":
/// retried immediately, never opening the breaker, never accepted.
async fn assert_transient_no_result(template: ResponseTemplate) {
    let server = MockServer::start().await;
    mount_events(&server, template).await;
    let mut config = config_for(&server);
    config.retry_attempts = 6;
    config.backoff_factor = 100.0;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    flush_within(&agent, 10).await;

    assert_eq!(paths(&server, "/api/v1/events").await, 7, "all attempts");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 0, "never counted as accepted");
    assert_eq!(stats.events_buffered, 1, "requeued");
    assert_eq!(stats.circuit_breaker_state, CircuitBreakerState::Closed);
}

#[tokio::test]
async fn status_202_is_a_transient_failure() {
    assert_transient_no_result(ResponseTemplate::new(202).set_body_string("{}")).await;
}

#[tokio::test]
async fn status_204_is_a_transient_failure() {
    assert_transient_no_result(ResponseTemplate::new(204)).await;
}

#[tokio::test]
async fn other_4xx_is_a_transient_failure_that_does_not_open_the_breaker() {
    assert_transient_no_result(ResponseTemplate::new(405).set_body_string("no")).await;
}

#[tokio::test]
async fn a_redirect_is_a_transient_failure_and_is_not_followed() {
    let server = MockServer::start().await;
    mount_events(
        &server,
        ResponseTemplate::new(307).insert_header("Location", "/api/v1/elsewhere"),
    )
    .await;
    Mock::given(path("/api/v1/elsewhere"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .mount(&server)
        .await;
    let mut config = config_for(&server);
    config.retry_attempts = 6;
    config.backoff_factor = 100.0;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    flush_within(&agent, 10).await;

    assert_eq!(paths(&server, "/api/v1/elsewhere").await, 0, "not followed");
    assert_eq!(agent.get_stats().await.events_sent, 0);
}

#[tokio::test]
async fn an_unparseable_200_is_retried_without_opening_the_breaker() {
    assert_transient_no_result(ResponseTemplate::new(200).set_body_string("<html>")).await;
}

#[tokio::test]
async fn an_empty_object_200_is_a_transient_failure() {
    assert_transient_no_result(ResponseTemplate::new(200).set_body_string("{}")).await;
}

#[tokio::test]
async fn a_non_object_json_200_is_accepted() {
    let server = MockServer::start().await;
    mount_events(&server, ResponseTemplate::new(200).set_body_string("[]")).await;
    let agent = GuardAgent::new(config_for(&server)).unwrap();
    agent.send_event(event(1)).await;
    agent.flush_buffer().await;
    assert_eq!(agent.get_stats().await.events_sent, 1);
    assert_eq!(paths(&server, "/api/v1/events").await, 1);
}

#[tokio::test]
async fn a_truthy_non_list_errors_field_is_a_partial_failure() {
    let server = MockServer::start().await;
    mount_events(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({"success": true, "errors": "quota"})),
    )
    .await;
    let agent = GuardAgent::new(config_for(&server)).unwrap();
    agent.send_event(event(1)).await;
    agent.flush_buffer().await;
    assert_eq!(paths(&server, "/api/v1/events").await, 1, "no retry");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 0);
    assert_eq!(stats.events_buffered, 1);
}

#[tokio::test]
async fn status_201_is_accepted() {
    let server = MockServer::start().await;
    mount_events(&server, ResponseTemplate::new(201)).await;
    let agent = GuardAgent::new(config_for(&server)).unwrap();
    agent.send_event(event(1)).await;
    agent.flush_buffer().await;
    assert_eq!(agent.get_stats().await.events_sent, 1);
}
