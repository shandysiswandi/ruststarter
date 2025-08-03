FROM rust:1.88-slim AS builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN cargo init --bin
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf src/
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ruststarter /
COPY config/config.yaml /config/config.yaml
EXPOSE 8000
CMD ["/ruststarter"]
