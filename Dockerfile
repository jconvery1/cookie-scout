# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Create a new empty project for caching dependencies
RUN cargo init --name cookie-scout

# Copy over manifests
COPY Cargo.toml Cargo.lock* ./

# Build dependencies only (this layer will be cached)
RUN cargo build --release && rm -rf src target/release/cookie-scout target/release/deps/cookie_scout*

# Copy source code
COPY src ./src

# Build the actual application
RUN cargo build --release

# Runtime stage - use a slim image
FROM debian:bookworm-slim

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/cookie-scout /usr/local/bin/cookie-scout

# Set the entrypoint
ENTRYPOINT ["cookie-scout"]

# Default help command
CMD ["--help"]

