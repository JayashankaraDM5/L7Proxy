# Go L7 Proxy

## Overview

This project implements a Layer 7 (L7) HTTP/HTTPS proxy in Go with:

- HTTP/1.1 support for HTTP and HTTPS
- HTTP/2 support for HTTPS (via TLS ALPN)
- TLS termination integration with HAProxy
- HTTPS passthrough with SNI filtering
- Full TCP connection tracking and atomic metrics
- External file watcher for graceful connection shutdown
- Prometheus-compatible metrics endpoint on port 9090
- Unit and integration tests included
- CI pipeline with GitHub Actions

## Building

git clone https://github.com/your-org/go-l7-proxy.git
cd go-l7-proxy
go build ./cmd/proxy

## Running
./proxy
- Listens on port 80 for HTTP
- Listens on port 443 for HTTPS (handles TLS termination and passthrough)
- Metrics exposed on http://localhost:9090/metrics

## Configuration

- Filtering rules, HAProxy addresses, and file watcher paths can be configured in source or future config files (TBD).

## Testing
go test ./...


## CI Pipeline

- GitHub Actions run build, lint, and tests on push and PR
- Configuration in `.github/workflows/ci.yml`

## Contributions

Feel free to open issues or submit pull requests.

## License

MIT License


