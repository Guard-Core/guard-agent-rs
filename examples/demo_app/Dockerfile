# Build context is the repository root:
#   docker build -f examples/demo_app/Dockerfile .
FROM rust:1.95-slim-bookworm AS build

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY examples/demo_app/ examples/demo_app/

# The demo crate is intentionally outside the workspace (see its
# [workspace] table); build it by manifest path so the release build stays
# standalone.
RUN cargo build --release --manifest-path examples/demo_app/Cargo.toml && \
    cp examples/demo_app/target/release/guard-agent-demo-app /usr/local/bin/guard-agent-demo

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system guard && \
    useradd --system --gid guard --create-home guard

COPY --from=build /usr/local/bin/guard-agent-demo /usr/local/bin/guard-agent-demo

LABEL org.opencontainers.image.title="guard-agent-rs demo" \
    org.opencontainers.image.description="Containerized Guard Agent demo: a small Rust service streaming security telemetry to a Guard Core ingestion endpoint" \
    org.opencontainers.image.source="https://github.com/Guard-Core/guard-agent-rs" \
    org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV GUARD_AGENT_ENDPOINT=https://api.guard-core.com \
    GUARD_AGENT_PROJECT_ID=demo-project \
    PORT=8080

USER guard

EXPOSE 8080

ENTRYPOINT ["guard-agent-demo"]
