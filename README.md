<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Telemetry and monitoring agent for the [Guard ecosystem](https://github.com/Guard-Core) (Rust). Companion agent to [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) and its thin adapters, mirroring the semantics of [guard-agent](https://github.com/Guard-Core/guard-agent) (Python) and [guardagent](https://github.com/Guard-Core/guard-agent-ts) (TypeScript).</strong>
</p>

<p align="center">
    <a href="https://crates.io/crates/guard-agent-rs">
        <img src="https://img.shields.io/crates/v/guard-agent-rs?color=0080ff" alt="Crates.io version">
    </a>
    <a href="https://guard-core.github.io/guard-agent-rs/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-agent-rs/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-agent-rs?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Rust-DEA584.svg?style=flat&logo=rust&logoColor=white" alt="Rust"> <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&logo=redis&logoColor=white" alt="Redis">
    <a href="https://crates.io/crates/guard-agent-rs">
        <img src="https://img.shields.io/crates/d/guard-agent-rs" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-agent-rs/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

## Status

Released. Version 3.2.0, published to crates.io.

## Features

- **Buffered ingestion** with size (high watermark) and time (flush interval) triggers, and three overflow policies: `drop` (evict oldest), `block` (backpressure), and `raise` (surface an error).
- **At-least-once flush handshake**: drain, send, confirm (delete persisted records) or requeue in the original order.
- **Retry with exponential backoff**, honoring `Retry-After` on 429, with a client-side circuit breaker (5 consecutive failures open the circuit for 60 seconds).
- **413 split-or-drop**: batches rejected as too large are halved recursively; a singleton that still exceeds the cap is dropped.
- **Permanent rejection** for 400, 404, and 422: the batch is dropped without retrying and counted as confirmed.
- **Per-kind failure streaks**: events and metrics back off independently (up to 300 seconds) after failed flushes, and a computed degraded state is exposed to callers and the status endpoint.
- **Optional Redis persistence** (feature `persistence`): every accepted record is written with a TTL on enqueue, deleted only on confirmation, and reloaded into the buffer on startup. Alternatively, implement the `RedisHandler` trait and inject your own store.
- **Payload hygiene**: gzip compression above a threshold, HMAC-SHA256 request signing (`X-Payload-Signature: v1=<hex>`), and redaction of sensitive metadata and tag keys.
- **Failure isolation**: `send_event` and `send_metric` never fail; telemetry problems are visible through stats, status, logs, and an optional `on_error` hook, never in the caller's request path.
- **Dynamic rules sync**: `GET /api/v1/rules` fetched through the shared retry machinery (rate limiter, circuit breaker, capped `Retry-After`), cached for the document TTL, refreshed by a background loop on `dynamic_rule_interval`; a failed poll keeps the last good rules.

## Installation

```bash
cargo add guard-agent-rs
# with the built-in Redis backend:
cargo add guard-agent-rs --features persistence
```

## Usage

```rust
use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};

#[tokio::main]
async fn main() {
    let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
    config.endpoint = "https://api.guard-core.com".to_owned();
    config.project_id = Some("proj_your-project".to_owned());
    config.payload_signing_secret = Some("server-provided-signing-secret".to_owned());

    let agent = GuardAgent::new(config).expect("valid configuration");
    agent.start().await;

    agent
        .send_event(
            SecurityEvent::new("rate_limited")
                .with_ip_address("10.0.0.1")
                .with_endpoint("/api/users")
                .with_action_taken("blocked"),
        )
        .await;

    // ... at shutdown:
    agent.stop().await;
}
```

Manual flushes are available at any time:

```rust
agent.flush_buffer().await;
let status = agent.get_status().await;
let stats = agent.get_stats().await;
```

## Encryption

Set `config.project_encryption_key` (a urlsafe-base64-encoded 256-bit key from the core backend) and every event/metric batch is AES-256-GCM encrypted and POSTed to `/api/v1/events/encrypted`, byte-compatible with the Python agent. An invalid key fails startup; the agent never falls back to plaintext.

## Reliability semantics

The ingestion API contract is verified against the Guard backend source (`guard-core-api/guard_core_api/api/routers/telemetry_router.py`):

| Situation | Behavior |
| --- | --- |
| 2xx from `POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status` | Batch confirmed; persisted records deleted |
| 200 with `success: false` or non-empty `errors` | Partial failure: batch requeued, no in-loop retry |
| 429 | Honors `Retry-After` (seconds; default 60, capped at 300) inside the retry loop |
| 400, 404, 422 | Permanent rejection: batch dropped, durable records deleted, no retry |
| 413 | Split the batch in half and retry each half; drop a singleton that still 413s |
| 401, 403, other 4xx, 5xx, network errors | Retryable with exponential backoff under the circuit breaker |
| Buffer overflow | Configurable: evict oldest (default), block the caller, or surface an error |
| Redis write failure | Fail-open: record stays in memory, failure counted in stats |
| Process restart with persistence | Records with surviving TTL are reloaded into the buffer |

The HMAC signature covers the uncompressed JSON body, which is what the server verifies after its gzip middleware decompresses the request (this intentionally differs from the Python and TypeScript agents, which sign the post-gzip wire bytes and therefore fail verification when compression is active).

## Configuration

All fields live on `AgentConfig` and have defaults; see the rustdoc for the full list. Highlights:

| Field | Default | Notes |
| --- | --- | --- |
| `endpoint` | `https://api.guard-core.com` | Trailing slashes and a legacy `/api/v1` suffix are stripped |
| `buffer_size` | `100` | Per kind (events and metrics each) |
| `flush_interval` | `30` seconds | Time trigger |
| `dynamic_rule_interval` | `300` seconds | Dynamic rules polling cadence, minimum 60 |
| `high_watermark_ratio` | `0.8` | Occupancy trigger |
| `buffer_overflow_policy` | `drop` | `drop`, `block`, or `raise` |
| `retry_attempts` | `3` | Total attempts are this value plus one |
| `compression_threshold` | `1024` bytes | Bodies at or above this size are gzipped |
| `payload_signing_secret` | none | No signature header when unset |
| `project_encryption_key` | none | Urlsafe-base64 AES-256 key; enables encrypted ingest to `/api/v1/events/encrypted` |
| `install_id` | generated | Persisted at `~/.guard-agent/install-id` when not overridden |

## Feature flags

- `persistence` (optional): adds the `redis` dependency and the built-in `RedisClientHandler` plus `RedisConfig`. The `RedisHandler` trait and an in-memory store are always available, so a custom store needs no feature.

## Links

- Repository: <https://github.com/Guard-Core/guard-agent-rs>
- Guard Core (Rust): <https://github.com/Guard-Core/guard-core-rs>
- Guard Agent (Python): <https://github.com/Guard-Core/guard-agent>
- Guard Agent (TypeScript): <https://github.com/Guard-Core/guard-agent-ts>

## License

Dual licensed under MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
