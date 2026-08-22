# kong-jwt-keycloak

A [Kong Gateway](https://konghq.com/) plugin that validates Keycloak-issued JWTs,
written in Go using the [Kong Go PDK](https://github.com/Kong/go-pdk).

It verifies token signatures against the issuing realm's JWKS endpoint, enforces
role- and scope-based access rules, and forwards the authenticated identity to
your upstream service as HTTP headers.

## Features

- **Multi-realm** — accept tokens from an explicit list of issuers, with `*`
  wildcard support for per-tenant realms.
- **JWKS with rotation handling** — keys are cached and automatically refetched
  when an unknown `kid` appears, with a configurable grace period.
- **Authorization** — require realm roles, client roles, or scopes. Checks use
  OR logic: the token needs *any* one of the listed values.
- **Public paths** — skip authentication entirely for health checks and docs.
- **CORS-safe** — optionally skip preflight (`OPTIONS`) requests so the CORS
  plugin can answer them.
- **Identity propagation** — sets `X-User-Sub`, `X-User-Email`, `X-User-Name`,
  `X-Realm-Roles`, `X-Token-Audience` and `X-Tenant-Slug` on the upstream request.

## Installation

The plugin ships as a container image containing a single static binary. Copy it
into the Kong container with an init container and register it as a plugin server.

```yaml
gateway:
  env:
    plugins: "bundled,jwt-keycloak"
    pluginserver_names: "jwt-keycloak"
    pluginserver_jwt_keycloak_socket: "/usr/local/kong/plugin-servers/jwt-keycloak.socket"
    pluginserver_jwt_keycloak_start_cmd: "/usr/local/kong/plugins/jwt-keycloak -kong-prefix /usr/local/kong/plugin-servers"
    pluginserver_jwt_keycloak_query_cmd: "/usr/local/kong/plugins/jwt-keycloak -dump"

  deployment:
    userDefinedVolumes:
      - name: kong-plugins
        emptyDir: {}
      - name: kong-plugin-servers
        emptyDir: {}

    userDefinedVolumeMounts:
      - name: kong-plugins
        mountPath: /usr/local/kong/plugins
      - name: kong-plugin-servers
        mountPath: /usr/local/kong/plugin-servers

    initContainers:
      - name: plugin-jwt-keycloak
        image: ghcr.io/open-source-cloud/kong-jwt-keycloak:v0.2.0
        command: ["cp", "/kong-jwt-keycloak", "/plugins/jwt-keycloak"]
        volumeMounts:
          - name: kong-plugins
            mountPath: /plugins
```

Kong's container filesystem is read-only, so the plugin server is pointed at a
writable `emptyDir` via `-kong-prefix`. The socket path must match the directory
the binary will create it in.

## Configuration

```yaml
apiVersion: configuration.konghq.com/v1
kind: KongClusterPlugin
metadata:
  name: jwt-keycloak
  annotations:
    kubernetes.io/ingress.class: kong
plugin: jwt-keycloak
config:
  allowed_iss:
    - "https://auth.example.com/realms/main"
    - "https://auth.example.com/realms/tenant-*"
  algorithm: RS256
  jwks_cache_ttl: 3600
  key_grace_period: 10
  set_upstream_headers: true
  strip_auth_header: false
  run_on_preflight: false
  public_paths:
    - /health
    - /ready
    - /docs
```

Apply it to a route with `konghq.com/plugins: jwt-keycloak` on the Ingress.

### Options

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed_iss` | `[]string` | — | Allowed token issuers. An entry ending in `*` matches any non-empty suffix. |
| `well_known_template` | `string` | `%s/.well-known/openid-configuration` | Discovery URL template. |
| `algorithm` | `string` | `RS256` | Expected signing algorithm. |
| `header_names` | `[]string` | `["authorization"]` | Headers to read the token from. |
| `cookie_names` | `[]string` | — | Cookies to read the token from. |
| `uri_param_names` | `[]string` | — | Query parameters to read the token from. |
| `realm_roles` | `[]string` | — | Require any one of these realm roles. |
| `client_roles` | `[]string` | — | Require any one of these roles on the `azp` client. |
| `scope` | `[]string` | — | Require any one of these scopes. |
| `public_paths` | `[]string` | — | Path prefixes that skip authentication. |
| `jwks_cache_ttl` | `int` | `3600` | JWKS cache lifetime, in seconds. |
| `key_grace_period` | `int` | `10` | Seconds to tolerate clock skew on key rotation. |
| `maximum_expiration` | `int` | — | Reject tokens whose lifetime exceeds this many seconds. |
| `run_on_preflight` | `bool` | `true` | Whether to validate `OPTIONS` requests. |
| `set_upstream_headers` | `bool` | — | Forward identity headers to the upstream. |
| `strip_auth_header` | `bool` | — | Remove `Authorization` before proxying. |

If no `realm_roles`, `client_roles` or `scope` are set, any valid token from an
allowed issuer is accepted.

### Upstream headers

When `set_upstream_headers` is enabled:

| Header | Source claim |
|---|---|
| `X-User-Sub` | `sub` |
| `X-User-Email` | `email` |
| `X-User-Name` | `preferred_username` |
| `X-Realm-Roles` | `realm_access.roles`, comma-separated |
| `X-Token-Audience` | `aud`, comma-separated |
| `X-Tenant-Slug` | `tenant_id`, if present |

## Responses

| Status | Meaning |
|---|---|
| `401` | Missing, malformed, expired, or untrusted token. |
| `403` | Valid token, but the required roles or scopes are absent. |

Both return a JSON body of the form `{"error": "...", "message": "..."}`.

## Development

```bash
go vet ./...
go test ./... -race
docker build -t kong-jwt-keycloak .
```

## License

[Apache-2.0](LICENSE)
