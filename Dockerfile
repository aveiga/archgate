# Multi-architecture Dockerfile
# Supports: linux/amd64, linux/arm64 (Apple M-series, AWS Graviton)
# Build for current platform: docker build -t archgate .
# Build for multiple platforms: docker buildx build --platform linux/amd64,linux/arm64 -t archgate .

# Build stage
FROM golang:1.25-alpine AS builder

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for multi-architecture support
# TARGETARCH and TARGETOS are automatically set by Docker buildx
ARG TARGETARCH
ARG TARGETOS=linux

# Build the application
# CGO_ENABLED=0 creates a statically linked binary
# -ldflags="-w -s" strips debug information to reduce binary size
# Supports both amd64 and arm64 (Apple M-series) architectures
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o gateway \
    ./cmd/gateway

# Runtime stage
FROM alpine:latest

# Create non-root user for security
RUN addgroup -g 1000 gateway && \
    adduser -D -u 1000 -G gateway gateway

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/gateway /app/gateway

# Copy example config (users should mount their own config.yaml)
COPY --from=builder /build/config.example.yaml /app/config.example.yaml

# Change ownership to non-root user
RUN chown -R gateway:gateway /app

# Switch to non-root user
USER gateway

# Expose default port (configurable via config file)
EXPOSE 4010

# Run the gateway
# Default config path can be overridden via CONFIG_PATH env var or -config flag
ENTRYPOINT ["/app/gateway"]
CMD ["-config", "/app/config.yaml"]

