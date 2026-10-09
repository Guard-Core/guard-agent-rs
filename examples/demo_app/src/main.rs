//! Command `demo_app` serves the Guard Agent demo container: a small
//! tokio TCP HTTP service that starts guard-agent-rs, ships one test event
//! on boot, and exposes the agent lifecycle over three routes (`/` :
//! service info, `/health` : agent status, `POST /events` : emit a test
//! event). It mirrors the Python agent's `examples/demo_app`. The HTTP
//! surface is hand-rolled over `std`/tokio so the demo stays
//! dependency-free beyond the agent itself.
//!
//! Set `GUARD_AGENT_API_KEY` (required by the ingestion API), and
//! optionally `GUARD_AGENT_ENDPOINT`, `GUARD_AGENT_PROJECT_ID`,
//! `GUARD_AGENT_SIGNING_SECRET`, and `PORT` before running.

use std::env;
use std::sync::Arc;

use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};

const DEMO_EVENT_TYPE: &str = "custom_request_check";

fn build_test_event() -> SecurityEvent {
    let mut event = SecurityEvent::new(DEMO_EVENT_TYPE);
    "192.168.1.100".clone_into(&mut event.ip_address);
    event.endpoint = Some("/demo/test-event".to_owned());
    event.method = Some("POST".to_owned());
    "logged".clone_into(&mut event.action_taken);
    "Guard Agent demo container test event".clone_into(&mut event.reason);
    event
}

/// Resolves an environment variable into `None` when unset or empty.
fn env(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    env(key).unwrap_or_else(|| fallback.to_owned())
}

/// A parsed request: only the routing surface the demo needs.
struct Request {
    method: String,
    path: String,
}

fn parse_request(head: &str) -> Option<Request> {
    let mut lines = head.lines();
    let request_line = lines.next()?.split_whitespace().collect::<Vec<_>>();
    if request_line.len() < 2 {
        return None;
    }
    Some(Request {
        method: request_line[0].to_owned(),
        path: request_line[1].split('?').next().unwrap_or("/").to_owned(),
    })
}

fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_method_not_allowed() -> String {
    "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: application/json\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"error\":\"POST only\"}\n"
        .to_owned()
}

async fn handle(
    agent: &GuardAgent,
    endpoint: &str,
    project_id: &str,
    request: Request,
) -> String {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => http_ok(&format!(
            "{{\"service\":\"guard-agent-demo\",\"endpoint\":\"{endpoint}\",\"project_id\":\"{project_id}\"}}\n"
        )),
        ("GET", "/health") => {
            let status = agent.get_status().await;
            // `AgentHealth` serializes lowercase on the wire; mirror that
            // spelling here by hand so the route stays dependency-free.
            let health = match status.status {
                guard_agent_rs::AgentHealth::Healthy => "healthy",
                guard_agent_rs::AgentHealth::Degraded => "degraded",
                guard_agent_rs::AgentHealth::Failed => "failed",
            };
            http_ok(&format!("{{\"status\":\"{health}\"}}\n"))
        }
        ("POST", "/events") => {
            // `send_event` never fails: telemetry problems surface through
            // stats, status, logs, and the optional `on_error` hook.
            agent.send_event(build_test_event()).await;
            http_ok(&format!("{{\"emitted\":\"{DEMO_EVENT_TYPE}\"}}\n"))
        }
        ("POST", "/" | "/health") | ("GET", "/events") => http_method_not_allowed(),
        _ => http_ok("{\"error\":\"not found\"}\n"),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let endpoint = env_or("GUARD_AGENT_ENDPOINT", "https://api.guard-core.com");
    let project_id = env_or("GUARD_AGENT_PROJECT_ID", "demo-project");
    let addr = format!("0.0.0.0:{}", env_or("PORT", "8080"));

    let Some(api_key) = env("GUARD_AGENT_API_KEY") else {
        log::error!("GUARD_AGENT_API_KEY is required");
        return;
    };

    let mut config = AgentConfig::new(api_key);
    config.endpoint = endpoint.clone();
    config.project_id = Some(project_id.clone());
    config.buffer_size = 10;
    config.flush_interval = 5;
    config.guard_version = Some("demo".to_owned());
    let agent = Arc::new(match GuardAgent::new(config) {
        Ok(agent) => agent,
        Err(error) => {
            log::error!("agent: {error}");
            return;
        }
    });

    agent.start().await;

    // Boot-time test event, like the Python demo's lifespan startup.
    agent.send_event(build_test_event()).await;

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(error) => {
            log::error!("bind {addr}: {error}");
            return;
        }
    };
    log::info!("guard-agent demo listening on {addr} (endpoint {endpoint}, project {project_id})");

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
    };

    let serve = async {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let agent = Arc::clone(&agent);
                    let endpoint = endpoint.clone();
                    let project_id = project_id.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

                        let mut head = String::new();
                        // Read to the end-of-headers blank line; the demo
                        // ignores request bodies entirely.
                        loop {
                            let mut byte = [0_u8; 1];
                            match stream.read_exact(&mut byte).await {
                                Ok(_) => head.push(byte[0] as char),
                                Err(_) => return,
                            }
                            if head.ends_with("\r\n\r\n") {
                                break;
                            }
                            if head.len() > 16 * 1024 {
                                return;
                            }
                        }
                        let Some(request) = parse_request(&head) else {
                            return;
                        };
                        let response =
                            handle(&agent, &endpoint, &project_id, request).await;
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
                Err(error) => {
                    log::error!("accept: {error}");
                    return;
                }
            }
        }
    };

    tokio::select! {
        () = serve => {},
        () = shutdown => {},
    }

    agent.stop().await;
    log::info!("agent stopped after final flush");
}
