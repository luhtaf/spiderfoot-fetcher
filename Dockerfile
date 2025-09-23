# Multi-stage build for smaller image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o spiderfoot-fetcher main.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite

# Create app user
RUN addgroup -g 1001 app && \
    adduser -D -s /bin/sh -u 1001 -G app app

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/spiderfoot-fetcher .

# Copy config example
COPY --from=builder /app/config.yaml.example .

# Create necessary directories
RUN mkdir -p data logs && \
    chown -R app:app /app

# Switch to app user
USER app

# Expose profiling port (optional)
EXPOSE 6060

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep spiderfoot-fetcher || exit 1

# Set default command
ENTRYPOINT ["./spiderfoot-fetcher"]
CMD ["-config", "config.yaml"]