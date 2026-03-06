# Archgate

A high-performance, configurable API Gateway written in Go with Keycloak integration for RBAC (Role-Based Access Control).

## Features

- **YAML-based Configuration**: Dynamic route configuration with regex pattern matching
- **Keycloak Integration**: Token introspection for authentication and authorization
- **RBAC Support**: Role-based access control with AND/OR logic
- **Token Caching**: Configurable token cache to reduce Keycloak load
- **Connection Pooling**: Efficient connection reuse for upstream services
- **Path Rewriting**: Strip prefixes before forwarding to upstream services
- **Graceful Shutdown**: Clean shutdown handling for production deployments

## Project Structure

```
archgate/
├── cmd/gateway/main.go           # Entry point, config loading, server startup
├── internal/
│   ├── config/config.go          # YAML config structs and loader
│   ├── auth/keycloak.go          # Keycloak introspection client
│   ├── middleware/
│   │   ├── auth.go               # JWT extraction and validation middleware
│   │   └── rbac.go               # Role-based access control middleware
│   ├── proxy/proxy.go            # Reverse proxy with connection pooling
│   └── router/router.go          # Regex-based route matching
├── config.example.yaml           # Example configuration
└── go.mod
```

## Building

### Local Build

```bash
go build ./cmd/gateway
```

### Docker Build

```bash
# Build for current platform
docker build -t archgate .

# Build for specific platform (e.g., Apple M-series)
docker build --platform linux/arm64 -t archgate .

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t archgate .
```

## Running

### Local Execution

```bash
# Using command line flag
./gateway -config config.yaml

# Using environment variable
CONFIG_PATH=config.yaml ./gateway
```

### Docker Execution

```bash
# Using Docker image from GitHub Container Registry
docker run -p 4010:4010 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/aveiga/archgate:latest

# Or build and run locally
docker run -p 4010:4010 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  archgate
```

**Note**: Replace `aveiga/archgate` with your GitHub username/organization and repository name.

## Configuration

See `config.example.yaml` for a complete example configuration file.

### Key Configuration Options

- **Server**: Port, timeouts, and HTTP server settings
- **Authz**: Introspection URL, client credentials, and timeout
- **Cache**: Token caching settings (enabled/disabled, TTL)
- **Routes**: Route definitions with path patterns, upstream URLs, and `rules[]` authorization policies

### Route Model

- All routes must define `rules[]`.
- `methods`, `require_auth`, `required_roles`, and `require_all_roles` are defined inside each rule.
- Rule authentication defaults to `require_auth: true` when omitted.
- Authorization is OR across rules: a request is allowed if any matching rule passes.
- Rules with `require_auth: false` must not define non-empty `required_roles`.

### Environment Variable Substitution

Configuration supports environment variable substitution:

- `${VAR_NAME}` - Replaced with environment variable value
- `${VAR_NAME:-default}` - Uses default value if environment variable is not set

Example:

```yaml
client_secret: "${KEYCLOAK_CLIENT_SECRET}"
```

## Request Flow

```
Request → Router Match (method rules) → Conditional Auth/RBAC → Reverse Proxy → Upstream
                ↓                              ↓
            404 if no                 auth/rbac only when no
            route match               matching rule has require_auth=false
```

## Dependencies

- `gopkg.in/yaml.v3` - YAML parsing (only external dependency)
- All other functionality uses Go standard library

## License

See LICENSE file for details.
