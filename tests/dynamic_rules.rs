//! Dynamic rules surface tests against a mock `GET /api/v1/rules` endpoint,
//! exercising the model, the transport retry path, the TTL cache, the rules
//! loop, and the stats counters through the public API.

use std::time::Duration;

use guard_agent_rs::{AgentConfig, GuardAgent};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const API_KEY: &str = "test-api-key-1234";

fn config_for(uri: &str) -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    uri.clone_into(&mut config.endpoint);
    config.install_id = Some("install-test-rules-1".to_owned());
    config.timeout = 5;
    config.retry_attempts = 0;
    config.compression_enabled = false;
    config
}

fn rules_body() -> Value {
    json!({
        "rule_id": "rule-42",
        "version": 7,
        "ttl": 300,
        "ip_blacklist": ["9.9.9.9"],
        "ip_whitelist": ["10.0.0.1"],
        "ip_ban_duration": 1800,
        "blocked_countries": ["KP"],
        "whitelist_countries": ["US"],
        "global_rate_limit": 100,
        "global_rate_window": 60,
        "endpoint_rate_limits": {"/api/login": [5, 60]},
        "blocked_cloud_providers": ["AWS", "GCP"],
        "blocked_user_agents": ["curl/*"],
        "suspicious_patterns": ["(?i)union.*select"],
        "enable_penetration_detection": false,
        "enable_ip_banning": true,
        "enable_rate_limiting": true,
        "auto_ban_threshold": 10,
        "auto_ban_duration": 7200,
        "enable_rate_limit_auto_ban": true,
        "emergency_mode": true,
        "emergency_whitelist": ["10.0.0.1"],
        "emergency_whitelist_only": true,
        "message": "lockdown"
    })
}

fn rules_response(body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(serde_json::to_vec(&body).unwrap(), "application/json")
}

#[tokio::test]
async fn fetches_rules_and_serves_the_full_wire_surface() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(move |_request: &wiremock::Request| rules_response(&rules_body()))
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    let rules = agent.get_dynamic_rules().await.expect("rules returned");
    assert_eq!(rules.rule_id, "rule-42");
    assert_eq!(rules.version, 7);
    assert_eq!(rules.ttl, 300);
    assert_eq!(rules.ip_blacklist, vec!["9.9.9.9".to_owned()]);
    assert_eq!(rules.ip_whitelist, vec!["10.0.0.1".to_owned()]);
    assert_eq!(rules.ip_ban_duration, 1800);
    assert_eq!(rules.blocked_countries, vec!["KP".to_owned()]);
    assert_eq!(rules.whitelist_countries, vec!["US".to_owned()]);
    assert_eq!(rules.global_rate_limit, Some(100));
    assert_eq!(rules.global_rate_window, Some(60));
    assert_eq!(rules.endpoint_rate_limits.get("/api/login"), Some(&(5, 60)));
    assert_eq!(rules.blocked_cloud_providers.len(), 2);
    assert_eq!(rules.blocked_user_agents, vec!["curl/*".to_owned()]);
    assert_eq!(
        rules.suspicious_patterns,
        vec!["(?i)union.*select".to_owned()]
    );
    assert_eq!(rules.enable_penetration_detection, Some(false));
    assert_eq!(rules.enable_ip_banning, Some(true));
    assert_eq!(rules.enable_rate_limiting, Some(true));
    assert_eq!(rules.auto_ban_threshold, Some(10));
    assert_eq!(rules.auto_ban_duration, Some(7200));
    assert_eq!(rules.enable_rate_limit_auto_ban, Some(true));
    assert!(rules.emergency_mode);
    assert_eq!(rules.emergency_whitelist, vec!["10.0.0.1".to_owned()]);
    assert!(rules.emergency_whitelist_only);
    assert_eq!(rules.message.as_deref(), Some("lockdown"));

    let stats = agent.get_stats().await;
    assert_eq!(stats.rules_fetched, 1);
    assert!(stats.cached_rules);
    assert!(stats.rules_last_update > 0.0);
    assert_eq!(stats.requests_sent, 1);
    assert_eq!(stats.requests_failed, 0);
}

#[tokio::test]
async fn sparse_payload_takes_the_python_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "sparse", "ttl": 300}))
        })
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    let rules = agent.get_dynamic_rules().await.expect("rules returned");
    assert_eq!(rules.rule_id, "sparse");
    assert_eq!(rules.version, 1);
    assert_eq!(rules.ip_ban_duration, 3600);
    assert!(!rules.emergency_mode && !rules.emergency_whitelist_only);
    assert_eq!(rules.enable_ip_banning, None);
    assert_eq!(rules.message, None);
}

#[tokio::test]
async fn ttl_cache_serves_the_cached_copy_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "cached", "ttl": 3600}))
        })
        .expect(1)
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    let first = agent.get_dynamic_rules().await.expect("first fetch");
    let second = agent.get_dynamic_rules().await.expect("cached fetch");
    assert_eq!(first.rule_id, "cached");
    assert_eq!(second.rule_id, "cached");
    // Only one HTTP request: the second call was served from the cache.
    assert_eq!(agent.get_stats().await.requests_sent, 1);
    assert_eq!(agent.get_stats().await.rules_fetched, 1);
}

#[tokio::test]
async fn stale_ttl_triggers_a_refetch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "stale", "ttl": 0}))
        })
        .expect(2)
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    assert!(agent.get_dynamic_rules().await.is_some());
    // ttl == 0 means the cache is immediately stale, so the second call
    // goes back to the network.
    assert!(agent.get_dynamic_rules().await.is_some());
    assert_eq!(agent.get_stats().await.requests_sent, 2);
    assert_eq!(agent.get_stats().await.rules_fetched, 2);
}

#[tokio::test]
async fn failed_fetch_surfaces_none_but_keeps_the_last_good_rules_cached() {
    let server = MockServer::start().await;
    // First request succeeds with a short ttl; every later request 500s.
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "good", "ttl": 1, "version": 3}))
        })
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            ResponseTemplate::new(500).set_body_string("boom")
        })
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    let good = agent.get_dynamic_rules().await.expect("first fetch");
    assert_eq!(good.rule_id, "good");

    // While the cache is fresh, the cached copy is served.
    let fresh = agent.get_dynamic_rules().await.expect("cached copy");
    assert_eq!(fresh.rule_id, "good");

    // After the ttl lapses the fetch fails and surfaces None, but the last
    // good rules stay cached for the next poll.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(agent.get_dynamic_rules().await.is_none(), "failure is None");
    let stats = agent.get_stats().await;
    assert!(stats.cached_rules, "last good rules stay cached");
    assert_eq!(stats.requests_failed, 1);
}

#[tokio::test]
async fn malformed_rules_payload_surfaces_none_like_the_python_blanket_except() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "bad", "ttl": "not-a-number"}))
        })
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config_for(&server.uri())).unwrap();

    assert!(agent.get_dynamic_rules().await.is_none());
    assert!(!agent.get_stats().await.cached_rules);
}

#[tokio::test]
async fn retries_server_errors_with_backoff_then_succeeds() {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = "<set-below>".to_owned();
    config.retry_attempts = 2;
    config.backoff_factor = 0.01;
    config.timeout = 5;

    let server = MockServer::start().await;
    config.endpoint = server.uri();
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            ResponseTemplate::new(503).set_body_string("down")
        })
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "recovered", "ttl": 60}))
        })
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config).unwrap();

    let rules = agent.get_dynamic_rules().await.expect("rules after retry");
    assert_eq!(rules.rule_id, "recovered");
    // The counters mirror the Python agent: only the successful dict
    // response counts as sent; the intermediate failures never exhausted
    // the retry budget, so nothing is counted as failed.
    assert_eq!(agent.get_stats().await.requests_sent, 1);
    assert_eq!(agent.get_stats().await.requests_failed, 0);
}

#[tokio::test]
async fn honors_retry_after_on_429() {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = "<set-below>".to_owned();
    config.retry_attempts = 1;
    config.timeout = 5;

    let server = MockServer::start().await;
    config.endpoint = server.uri();
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            ResponseTemplate::new(429)
                .set_body_string("slow down")
                .insert_header("Retry-After", "1")
        })
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "after-429", "ttl": 60}))
        })
        .mount(&server)
        .await;
    let agent = GuardAgent::new(config).unwrap();

    let started = std::time::Instant::now();
    let rules = agent.get_dynamic_rules().await.expect("rules after 429");
    assert_eq!(rules.rule_id, "after-429");
    assert!(
        started.elapsed() >= Duration::from_millis(1000),
        "the Retry-After delay must be honored"
    );
    assert_eq!(agent.get_stats().await.requests_sent, 1);
}

/// Pumps the paused tokio timer and yields so background tasks run; used by
/// the loop tests, which need to cross a 60 second interval instantly
/// (the config minimum mirrors the Python agent's `ge=60`).
async fn pump() {
    tokio::time::advance(Duration::from_secs(61)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn rules_loop_polls_on_the_configured_interval() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            rules_response(&json!({"rule_id": "loop", "ttl": 0}))
        })
        .mount(&server)
        .await;
    let mut config = config_for(&server.uri());
    config.dynamic_rule_interval = 60;
    let agent = GuardAgent::new(config).unwrap();

    agent.start().await;
    // Two loop ticks cross the (paused) 60 second interval instantly.
    pump().await;
    pump().await;
    let mut refreshed = false;
    for _ in 0..100 {
        if agent.get_stats().await.rules_fetched >= 2 {
            refreshed = true;
            break;
        }
        pump().await;
    }
    assert!(refreshed, "rules loop should refresh at least twice");
    let stats = agent.get_stats().await;
    assert!(stats.cached_rules);
    assert_eq!(stats.loop_failures.rules, 0);
    agent.stop().await;
}

#[tokio::test(start_paused = true)]
async fn failed_polls_are_counted_as_consecutive_loop_failures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/rules"))
        .respond_with(|_request: &wiremock::Request| {
            ResponseTemplate::new(500).set_body_string("down")
        })
        .mount(&server)
        .await;
    let mut config = config_for(&server.uri());
    config.dynamic_rule_interval = 60;
    let agent = GuardAgent::new(config).unwrap();

    agent.start().await;
    pump().await;
    let mut failed = false;
    for _ in 0..100 {
        if agent.get_stats().await.loop_failures.rules >= 1 {
            failed = true;
            break;
        }
        pump().await;
    }
    assert!(failed, "rules loop failures must be counted in stats");
    assert!(!agent.get_stats().await.cached_rules);
    agent.stop().await;
}
