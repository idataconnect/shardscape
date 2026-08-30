# Multi-stage build for the Rust binary
FROM rust:1 AS builder
WORKDIR /usr/src/shardscape

# Copy only manifests and prefetch dependencies in a dedicated layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() { println!("docker-fetch-dummy"); }' > src/main.rs \
    && cargo build --release

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked && cp target/release/shardscape /tmp/shardscape

# Final minimal runtime image
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/shardscape /usr/local/bin/shardscape
# S3 API (8014) and internal Noise cluster port (8015).
EXPOSE 8014 8015
# Expects /data/config.toml (created by `shardscape init`/`join` on a mounted
# volume). No external database or object-store daemon — the binary is the node.
ENTRYPOINT ["/usr/local/bin/shardscape"]
CMD ["serve", "--config", "/data/config.toml"]
