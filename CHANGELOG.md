# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of SpiderFoot Fetcher
- 3-stage concurrent pipeline (Reader → Parser → Indexer)
- CVE enrichment with CISA KEV data integration
- Real-time performance monitoring (Suricata-style)
- Configurable worker pools for each pipeline stage
- Safe timestamp management with range isolation
- Comprehensive error logging with record traceability
- Docker support with multi-stage builds
- Extensive unit tests with 85%+ coverage
- Performance benchmarks and profiling support
- GitHub Actions CI/CD pipeline
- Cross-platform binary builds (Linux, Windows, macOS)

### Features
- **High Performance**: Concurrent processing with configurable worker pools
- **CVE Intelligence**: Automatic enrichment with CVS scores and CISA data
- **Monitoring**: Real-time stats collection and performance metrics
- **Reliability**: Error recovery strategies and graceful degradation
- **Scalability**: Configurable batch sizes and worker allocation
- **Security**: Input validation and SQL injection prevention
- **Observability**: Structured logging and metrics export

### Configuration
- YAML-based configuration with comprehensive documentation
- Environment variable support for sensitive data
- Flexible SQL query customization
- Performance tuning guidelines

### Docker & Deployment
- Multi-stage Docker builds for minimal image size
- Health checks and proper signal handling
- Non-root user execution for security
- Volume mounts for configuration and data persistence

### Development
- Comprehensive test suite with unit, integration, and benchmark tests
- Make-based build system with common development tasks
- Code quality tools integration (golangci-lint, gosec)
- Performance profiling with pprof integration
- Git hooks for pre-commit validation

## [0.1.0] - 2025-09-23

### Added
- Initial project structure
- Basic pipeline implementation
- Core functionality for SpiderFoot data processing
- Elasticsearch integration
- Basic configuration system