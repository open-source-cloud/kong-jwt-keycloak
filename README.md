# kong-jwt-keycloak

[![CI](https://github.com/open-source-cloud/kong-jwt-keycloak/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cloud/kong-jwt-keycloak/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/open-source-cloud/kong-jwt-keycloak?sort=semver)](https://github.com/open-source-cloud/kong-jwt-keycloak/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/open-source-cloud/kong-jwt-keycloak.svg)](https://pkg.go.dev/github.com/open-source-cloud/kong-jwt-keycloak)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Stop every unauthenticated request at the gateway, not in your services.**

`kong-jwt-keycloak` is a [Kong Gateway](https://konghq.com/) plugin that validates
Keycloak-issued JWTs at the edge. It verifies signatures against each realm's JWKS
endpoint, enforces role- and scope-based rules, and hands your upstream services an
already-trusted identity as plain HTTP headers — so they never parse a token,
never fetch a key, and never implement auth twice.

Written in Go against the [Kong Go PDK](https://github.com/Kong/go-pdk) and shipped
as a single static binary in a container image.

## Why

Kong's bundled `jwt` plugin needs every issuer's public key registered as a
consumer credential by hand. That breaks the moment Keycloak rotates keys, and it
does not scale to per-tenant realms. This plugin discovers keys via OpenID Connect
discovery, caches them, and refetches automatically when an unrecognised `kid`
appears — so key rotation and new tenant realms need no gateway changes.

## Features

- **Multi-realm** — accept tokens from an explicit list of issuers, with `*`
  wildcard support for per-tenant realms.
- **JWKS with rotation handling** — keys are cached and automatically refetched
  when an unknown `kid` appears, at most once per issuer per `key_grace_period`,
  so clients cannot use random `kid` values to flood Keycloak.
- **Authorization** — require realm roles, client roles, or scopes. Checks use
  OR logic: the token needs _any_ one of the listed values.
- **Public paths** — skip authentication entirely for health checks and docs.
- **CORS-safe** — optionally skip preflight (`OPTIONS`) requests so the CORS
  plugin can answer them.
- **Identity propagation** — sets `X-User-Sub`, `X-User-Email`, `X-User-Name`,
  `X-Realm-Roles`, `X-Token-Audience` and `X-Tenant-Slug` on the upstream request.

## Installation

The plugin ships as a container image containing a single static binary. Copy it
into the Kong container with an init container and register it as a plugin server.
How the plugin server process is started depends on the Kong version.

### Kong 3.10 and later

Kong starts and supervises the plugin server itself (`start_cmd`).

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
        image: ghcr.io/open-source-cloud/kong-jwt-keycloak:0.4.0 # x-release-please-version
        command: ["cp", "/kong-jwt-keycloak", "/plugins/jwt-keycloak"]
        volumeMounts:
          - name: kong-plugins
            mountPath: /plugins
```

Kong's container filesystem is read-only, so the plugin server is pointed at a
writable `emptyDir` via `-kong-prefix`. The socket path must match the directory
the binary will create it in.

### Kong 3.9.x

Do not set `start_cmd` on Kong 3.9. When Kong starts a plugin server it stores
the process handle in its configuration, and the Admin API `GET /` then fails
with `Cannot serialise cdata: type not supported`
([Kong/kong#14260](https://github.com/Kong/kong/issues/14260)). The Kong Ingress
Controller reads `GET /` on startup, so it crash-loops and the gateway never
receives a configuration. This affects every Go plugin, not only this one.

Run the plugin server as a native sidecar instead. Kong then only connects to the
socket and `GET /` keeps working:

```yaml
gateway:
  env:
    plugins: "bundled,jwt-keycloak"
    pluginserver_names: "jwt-keycloak"
    pluginserver_jwt_keycloak_socket: "/usr/local/kong/plugin-servers/jwt-keycloak.socket"
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
        image: ghcr.io/open-source-cloud/kong-jwt-keycloak:0.4.0 # x-release-please-version
        command: ["cp", "/kong-jwt-keycloak", "/plugins/jwt-keycloak"]
        volumeMounts:
          - name: kong-plugins
            mountPath: /plugins
      - name: plugin-server-jwt-keycloak
        image: ghcr.io/open-source-cloud/kong-jwt-keycloak:0.4.0 # x-release-please-version
        restartPolicy: Always
        command: ["/plugins/jwt-keycloak", "-kong-prefix", "/usr/local/kong/plugin-servers"]
        securityContext:
          runAsUser: 1000
          runAsGroup: 1000
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
          - name: kong-plugins
            mountPath: /plugins
            readOnly: true
          - name: kong-plugin-servers
            mountPath: /usr/local/kong/plugin-servers
```

- The sidecar runs the copy in the shared `emptyDir`, so the binary is named
  `jwt-keycloak` and creates `jwt-keycloak.socket`, matching the plugin name Kong
  gets from `-dump`.
- It must run as the same user as the Kong container (`1000` in the Kong Helm
  chart), or Kong cannot connect to the socket.
- `restartPolicy: Always` on an init container (native sidecar, Kubernetes 1.29+)
  starts it after the copy and before Kong, and restarts it if it exits.

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
  allowed_typ:
    - Bearer
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

| Field                  | Type       | Default                               | Description                                                                 |
| ---------------------- | ---------- | ------------------------------------- | --------------------------------------------------------------------------- |
| `allowed_iss`          | `[]string` | —                                     | Allowed token issuers. An entry ending in `*` matches any non-empty suffix. |
| `well_known_template`  | `string`   | `%s/.well-known/openid-configuration` | Discovery URL template.                                                     |
| `algorithm`            | `string`   | `RS256`                               | Expected signing algorithm.                                                 |
| `allowed_aud`          | `[]string` | —                                     | Require the token's `aud` to contain any one of these values.               |
| `allowed_typ`          | `[]string` | —                                     | Require Keycloak's `typ` claim to be one of these, e.g. `["Bearer"]`.       |
| `header_names`         | `[]string` | `["authorization"]`                   | Headers to read the token from.                                             |
| `cookie_names`         | `[]string` | —                                     | Cookies to read the token from.                                             |
| `uri_param_names`      | `[]string` | —                                     | Query parameters to read the token from.                                    |
| `realm_roles`          | `[]string` | —                                     | Require any one of these realm roles.                                       |
| `client_roles`         | `[]string` | —                                     | Require any one of these roles on the `azp` client.                         |
| `scope`                | `[]string` | —                                     | Require any one of these scopes.                                            |
| `public_paths`         | `[]string` | —                                     | Path prefixes that skip authentication, matched against the client path.    |
| `jwks_cache_ttl`       | `int`      | `3600`                                | JWKS cache lifetime, in seconds.                                            |
| `key_grace_period`     | `int`      | `10`                                  | Minimum seconds between JWKS fetches for one issuer (see below).            |
| `maximum_expiration`   | `int`      | —                                     | Reject tokens whose lifetime exceeds this many seconds.                     |
| `run_on_preflight`     | `bool`     | `true`                                | Whether to validate `OPTIONS` requests.                                     |
| `set_upstream_headers` | `bool`     | —                                     | Forward identity headers to the upstream.                                   |
| `strip_auth_header`    | `bool`     | —                                     | Remove `Authorization` before proxying.                                     |

If no `realm_roles`, `client_roles` or `scope` are set, any valid token from an
allowed issuer is accepted.

Keycloak signs ID tokens with the same realm key, issuer and algorithm as access
tokens, so without `allowed_typ` an ID token is accepted like an access token.
Set `allowed_typ: ["Bearer"]` to accept access tokens only; Keycloak sets `typ`
to `ID` on ID tokens. `allowed_aud` restricts tokens to the clients your API serves;
Keycloak adds a client to `aud` through an Audience mapper on the client scope.
Both checks run after the signature check and are skipped when the list is empty.
A token that fails either one gets a `401`.

`key_grace_period` limits how often the plugin goes back to an issuer. A token
with an unknown `kid`, or one that fails the signature check, triggers at most one
JWKS fetch per issuer in that window; other tokens in the window are answered
from the cache. Failed fetches count too. Concurrent fetches for one issuer are
merged into one. A key Keycloak starts signing with is picked up within
`key_grace_period` seconds of the last fetch.

`public_paths` is compared with the path the client sent, before Kong strips a
route prefix. Behind an Ingress with `konghq.com/strip-path: "true"` on `/app`,
list `/app/health`, not `/health`.

### Upstream headers

When `set_upstream_headers` is enabled:

| Header             | Source claim                          |
| ------------------ | ------------------------------------- |
| `X-User-Sub`       | `sub`                                 |
| `X-User-Email`     | `email`                               |
| `X-User-Name`      | `preferred_username`                  |
| `X-Realm-Roles`    | `realm_access.roles`, comma-separated |
| `X-Token-Audience` | `aud`, comma-separated                |
| `X-Tenant-Slug`    | `tenant_id`, if present               |

## Responses

| Status | Meaning                                                   |
| ------ | --------------------------------------------------------- |
| `401`  | Missing, malformed, expired, or untrusted token.          |
| `403`  | Valid token, but the required roles or scopes are absent. |

A `401` always has the body `{"error": "unauthorized"}`, whatever check failed,
so clients cannot probe which issuers are trusted or which check they tripped.
The reason is written to the Kong error log at `info` level, prefixed with
`jwt-keycloak: rejected token:`; set Kong's `log_level` to `info` to see it.

A `403` has the body `{"error": "forbidden", "message": "..."}`, where the message
names the roles or scopes the route requires.

## Project layout

```
cmd/kong-jwt-keycloak/   plugin server entrypoint
internal/plugin/         Kong-facing handler, config schema, authorization rules
pkg/keycloak/            reusable Keycloak primitives: claims, JWKS discovery + cache
```

`pkg/keycloak` carries no Kong dependency and can be imported on its own if you
need Keycloak JWKS handling or claim parsing elsewhere.

## Versioning and releases

Releases are automated and follow [Semantic Versioning](https://semver.org/).
Commits use [Conventional Commits](https://www.conventionalcommits.org/); on merge
to `main`, [release-please](https://github.com/googleapis/release-please) opens a
release PR that computes the next version and updates `CHANGELOG.md`. Merging that
PR tags the release, which builds and publishes the multi-architecture image to
GHCR.

| Commit prefix                 | Version bump |
| ----------------------------- | ------------ |
| `fix:`                        | patch        |
| `feat:`                       | minor        |
| `feat!:` / `BREAKING CHANGE:` | major        |

Images are published to `ghcr.io/open-source-cloud/kong-jwt-keycloak`, tagged with
the exact version, the major.minor series, the major series, and `latest`.

## Development

```bash
go vet ./...
go test ./... -race
gofmt -l .
docker build -t kong-jwt-keycloak .
```

Contributions are welcome. Please keep commit messages in Conventional Commits
form, since the release automation derives versions from them.

## License

[Apache-2.0](LICENSE)
