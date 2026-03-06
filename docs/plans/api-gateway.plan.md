---
name: Go API Gateway
overview: Build a high-performance, configurable API gateway in Go using primarily stdlib, with Keycloak integration for RBAC via token introspection, and YAML-based dynamic route configuration with regex pattern matching.
todos:
  - id: project-setup
    content: Initialize project structure, update go.mod with yaml.v3 dependency
    status: pending
  - id: config-loader
    content: Implement YAML config loading with env var substitution and regex pre-compilation
    status: pending
  - id: keycloak-client
    content: Implement Keycloak introspection client with connection pooling and token cache
    status: pending
  - id: router
    content: Implement regex-based route matcher
    status: pending
  - id: auth-middleware
    content: Implement authentication middleware (token extraction, introspection, context storage)
    status: pending
  - id: rbac-middleware
    content: Implement RBAC middleware (role checking with AND/OR logic)
    status: pending
  - id: reverse-proxy
    content: Implement reverse proxy with path rewriting and header forwarding
    status: pending
  - id: main-entrypoint
    content: Wire everything together in main.go with graceful shutdown
    status: pending
  - id: example-config
    content: Create example configuration file with documentation
    status: pending
---

# Go API Gateway with Keycloak RBAC

## Third-Party Dependencies

Only one external dependency required:

- `gopkg.in/yaml.v3` - Go stdlib has no YAML parser; this is the de-facto standard

All other functionality uses stdlib: `net/http`, `httputil.ReverseProxy`, `regexp`, `encoding/json`, `sync`, `context`.

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

## Configuration Schema (YAML)

```yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s

keycloak:
  introspection_url: "https://keycloak/realms/{realm}/protocol/openid-connect/token/introspect"
  client_id: "gateway-client"
  client_secret: "${KEYCLOAK_CLIENT_SECRET}"  # env var substitution
  timeout: 5s

cache:
  enabled: true
  ttl: 60s          # token cache TTL

routes:
  - name: "user-api"
    path_pattern: "^/api/v1/users(/.*)?$"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstream: "http://user-service:8080"
    strip_prefix: "/api/v1"
    required_roles: ["user:read"]
    
  - name: "admin-api"
    path_pattern: "^/api/v1/admin(/.*)?$"
    upstream: "http://admin-service:8080"
    required_roles: ["admin"]
    require_all_roles: true   # AND vs OR for multiple roles
```

## Core Components

### 1. Config Loader (`internal/config/config.go`)

- Parse YAML with environment variable substitution for secrets
- Pre-compile all regex patterns at startup (fail fast on invalid patterns)
- Validate required fields

### 2. Keycloak Client (`internal/auth/keycloak.go`)

- HTTP client with configurable timeout and connection pooling
- Token introspection via POST to Keycloak endpoint
- Parse introspection response to extract `active`, `realm_access.roles`, `resource_access`
- **Token cache**: `sync.Map` with TTL to avoid repeated introspection calls (critical for performance)

### 3. Router (`internal/router/router.go`)

- Store compiled `*regexp.Regexp` per route
- Match incoming request path and method against routes
- Return matched route config or 404

### 4. Auth Middleware (`internal/middleware/auth.go`)

- Extract `Authorization: Bearer <token>` header
- Check cache first, then call Keycloak introspection if miss
- Store token claims in request context
- Return 401 on invalid/expired token

### 5. RBAC Middleware (`internal/middleware/rbac.go`)

- Read required roles from matched route config
- Compare against roles in token (from context)
- Support both AND (`require_all_roles: true`) and OR logic
- Return 403 on insufficient permissions

### 6. Reverse Proxy (`internal/proxy/proxy.go`)

- Use `httputil.ReverseProxy` from stdlib
- Custom `http.Transport` with connection pooling:
  ```go
  &http.Transport{
      MaxIdleConns:        100,
      MaxIdleConnsPerHost: 10,
      IdleConnTimeout:     90 * time.Second,
  }
  ```

- Path rewriting (strip prefix)
- Preserve/forward relevant headers

### 7. Main (`cmd/gateway/main.go`)

- Load config from file path (CLI flag or env var)
- Initialize all components
- Compose middleware chain: `Router -> Auth -> RBAC -> Proxy`
- Graceful shutdown handling

## Performance Optimizations

1. **Token caching**: Cache introspection results with configurable TTL
2. **Regex pre-compilation**: All patterns compiled once at startup
3. **Connection pooling**: Reuse connections to both Keycloak and upstreams
4. **Minimal allocations**: Use `sync.Pool` for request-scoped buffers
5. **Context propagation**: Pass auth data via `context.Context` (no map lookups)
6. **Efficient routing**: Routes checked in definition order (put high-traffic routes first)

## Request Flow

```
Request → Router Match → Auth Middleware → RBAC Check → Reverse Proxy → Upstream
                ↓              ↓                ↓
            404 if no      401 if token      403 if
            route match    invalid           roles missing
```