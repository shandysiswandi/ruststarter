# ==========
# Builder
# ==========
FROM rust:1.89-slim AS builder

# Install necessary build dependencies for dynamic linking (e.g., against OpenSSL).
RUN apt-get update && apt-get install -y --no-install-recommends \
    # build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin ruststarter


# ==========
# Runtime
# ==========
FROM gcr.io/distroless/cc-debian12:debug
COPY --from=builder /app/target/release/ruststarter /ruststarter
EXPOSE 8000
CMD ["/ruststarter"]
