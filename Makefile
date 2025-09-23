# Makefile for SpiderFoot Fetcher

.PHONY: all build test clean install lint fmt vet coverage benchmark docker-build docker-run setup

# Variables
BINARY_NAME=spiderfoot-fetcher
VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")
BUILD_TIME := $(shell date +%Y-%m-%dT%H:%M:%S%z)
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Default target
all: fmt vet test build

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) main.go

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 main.go

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	go test -race ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	go vet ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	golangci-lint run

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f pipeline_stats.json error.log timestamp_cron.txt

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/

# Setup development environment
setup:
	@echo "Setting up development environment..."
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	cp config.yaml.example config.yaml

# Run the application in development mode
run-dev:
	@echo "Running in development mode..."
	go run main.go

# Run the application in production mode
run-prod: build
	@echo "Running in production mode..."
	./bin/$(BINARY_NAME) -mode production

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t luhtaf/spiderfoot-fetcher:$(VERSION) .
	docker build -t luhtaf/spiderfoot-fetcher:latest .

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run -d \
		--name spiderfoot-fetcher \
		-v $(PWD)/config.yaml:/app/config.yaml \
		-v $(PWD)/data:/app/data \
		luhtaf/spiderfoot-fetcher:latest

# Create release
release: test build-all
	@echo "Creating release $(VERSION)..."
	mkdir -p release
	cp bin/* release/
	tar -czf release/$(BINARY_NAME)-$(VERSION).tar.gz -C release .

# Performance profiling
profile:
	@echo "Starting performance profiling server..."
	go run main.go -pprof :6060 &
	@echo "Profiling server started on :6060"
	@echo "Access profiles at:"
	@echo "  CPU: http://localhost:6060/debug/pprof/profile"
	@echo "  Memory: http://localhost:6060/debug/pprof/heap"
	@echo "  Goroutines: http://localhost:6060/debug/pprof/goroutine"

# Generate documentation
docs:
	@echo "Generating documentation..."
	godoc -http=:6060
	@echo "Documentation server started on :6060"

# Security scan
security:
	@echo "Running security scan..."
	gosec ./...

# Update dependencies
update-deps:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Git hooks setup
hooks:
	@echo "Setting up git hooks..."
	echo '#!/bin/sh\nmake fmt vet test' > .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

# Help
help:
	@echo "Available commands:"
	@echo "  build        - Build the application"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  test         - Run tests"
	@echo "  coverage     - Run tests with coverage"
	@echo "  benchmark    - Run benchmarks"
	@echo "  test-race    - Run tests with race detection"
	@echo "  fmt          - Format code"
	@echo "  vet          - Vet code"
	@echo "  lint         - Lint code"
	@echo "  clean        - Clean build artifacts"
	@echo "  setup        - Setup development environment"
	@echo "  run-dev      - Run in development mode"
	@echo "  run-prod     - Run in production mode"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  profile      - Start profiling server"
	@echo "  docs         - Generate documentation"
	@echo "  security     - Run security scan"
	@echo "  help         - Show this help"