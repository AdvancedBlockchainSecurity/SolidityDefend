# Multi-stage build for SolidityDefend
# Builder stage
FROM rust:1.88-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy workspace configuration first (Cargo.lock generated during build)
COPY Cargo.toml ./

# Copy source code
COPY . .

# Build the application in release mode with optimizations
RUN cargo build --release --bin soliditydefend && \
    strip target/release/soliditydefend

# Runtime stage - minimal image for production
FROM debian:bookworm-slim

# Install runtime dependencies (libssl3 for bookworm)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -r -s /bin/false soliditydefend

# Copy the binary from builder
COPY --from=builder /app/target/release/soliditydefend /usr/local/bin/soliditydefend

# Create working directory and set permissions
WORKDIR /workspace
RUN chown soliditydefend:soliditydefend /workspace

# Switch to non-root user for security
USER soliditydefend

# Set default entrypoint
ENTRYPOINT ["soliditydefend"]

# Default command shows help
CMD ["--help"]

# Build arguments for OCI labels
ARG SERVICE_VERSION=2.0.1
ARG BUILD_DATE
ARG VCS_REF

# OCI Image Format Specification labels
LABEL org.opencontainers.image.title="SolidityDefend" \
      org.opencontainers.image.version="${SERVICE_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.description="High-performance static analysis security tool for Solidity smart contracts with 81 detectors and intra-procedural dataflow analysis" \
      org.opencontainers.image.authors="Apogee" \
      org.opencontainers.image.vendor="Apogee" \
      org.opencontainers.image.url="https://github.com/AdvancedBlockchainSecurity/SolidityDefend" \
      org.opencontainers.image.source="https://github.com/AdvancedBlockchainSecurity/SolidityDefend" \
      org.opencontainers.image.documentation="https://github.com/AdvancedBlockchainSecurity/SolidityDefend/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"