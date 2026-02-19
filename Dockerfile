# syntax=docker/dockerfile:1.7

FROM rust:1.85-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
COPY third_party ./third_party

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/leash /usr/local/bin/leash
COPY config/default.yaml /app/config/config.yaml

ENV RUST_LOG=leash=info
ENTRYPOINT ["/usr/local/bin/leash"]
CMD ["watch", "--config", "/app/config/config.yaml"]
