# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-09-27

Parity release: the 3.0.2 to 3.1.0 agent feature train, in the same window as the Python and TypeScript agents.

### Added

- **AES-256-GCM encrypted ingest** (`src/encryption.rs`): batches can be encrypted end to end before they leave the host, matching the Python agent contract.
- **Sensitive-header redaction**: configurable `sensitive_headers` / metadata and tag keys (`src/config.rs`, `DEFAULT_SENSITIVE_HEADERS`) redacted before buffering.
- **Dynamic rules**: the agent pulls rule updates from the ingestion API and applies them locally without a restart (`src/agent.rs`, `src/models.rs`), with tests in `tests/dynamic_rules.rs`.
- **Local rate limiter** (`src/rate_limiter.rs`): token-bucket local limiting protects the host from event floods before anything is buffered or shipped.
- **`on_error` and `max_payload_size` knobs** (`src/config.rs`): operators choose the failure behavior and cap the serialized payload size.
- **Helper ports** (`src/utils.rs`): the LOW-surface helpers shared by the new subsystems.

### Changed

- **Crate version is 3.1.0** (`Cargo.toml` / `Cargo.lock`), matching the release tag.

## [3.0.2] - 2026-09-24

### Added

- First tagged release of guard-agent-rs; parity with the reference guard-agent 3.0.2, including the payload-signature contract: HMAC-SHA256 over the uncompressed body, with the server verifying after decompression.
- Release automation: `release.yml` Release Gate (fmt, clippy, tests at tag on stable and 1.92, tag-matches-crate-version gate) plus an automated crates.io publish job on GitHub release creation using `CARGO_REGISTRY_TOKEN`.
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across Cargo.toml, Cargo.lock, and a CHANGELOG scaffold).

### Fixed

- The partial-failure warning no longer claims Redis retention when Redis is not configured.

## [0.1.0] - 2026-09-20

### Added

- `GuardAgent` with buffered events and metrics: size (high watermark) and time (flush interval) triggers, `drop`/`block`/`raise` overflow policies, and at-least-once flush handshake (drain, send, confirm or requeue in original order).
- HTTP transport: gzip compression above a configurable threshold, HMAC-SHA256 request signing over the uncompressed body (`X-Payload-Signature: v1=<hex>`), exponential backoff with `Retry-After` handling on 429, 413 split-or-drop, permanent rejection for 400/404/422, and a client-side circuit breaker.
- Per-kind failure streaks with capped backoff (up to 300s) and a computed degraded state exposed through `get_status`, `health_check`, and status pushes to `/api/v1/status`.
- Optional `persistence` feature with a built-in Redis client (`RedisClientHandler`, `RedisConfig`), a store-agnostic `RedisHandler` trait with an in-memory implementation, TTL-based records (3600s), and startup reload.
- Install identifier resolution (override, `~/.guard-agent/install-id`, or generated UUID) and sensitive metadata/tag redaction.
- Wiremock-based integration tests mirroring the verified ingestion API contract, plus real-Redis integration tests (ignored by default; run with `--include-ignored`).

[3.0.2]: https://github.com/rennf93/guard-agent-rs/releases/tag/v3.0.2
[0.1.0]: https://github.com/rennf93/guard-agent-rs/releases/tag/v0.1.0
