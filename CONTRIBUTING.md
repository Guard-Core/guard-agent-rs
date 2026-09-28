# Contributing to Guard Agent Rust

Thanks for considering a contribution to Guard Agent Rust, part of the Guard ecosystem (guard-agent-rs follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- Rust 1.92 (MSRV, what CI gates on) or newer; rustup recommended

## Build and test

```bash
cargo build
cargo test                                     # default features, no services needed
docker run -p 6379:6379 redis:7-alpine         # only needed for the Redis-backed tests
cargo test --all-features -- --include-ignored # needs Redis on 127.0.0.1:6379
```

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --all-features -- --include-ignored   # needs Redis on 127.0.0.1:6379
cargo install cargo-audit --locked && cargo audit
cargo install cargo-deny --locked && cargo deny check
```

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
