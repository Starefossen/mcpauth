# mcpauth

[![ci](https://github.com/Starefossen/mcpauth/actions/workflows/ci.yml/badge.svg)](https://github.com/Starefossen/mcpauth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/starefossen/mcpauth.svg)](https://pkg.go.dev/github.com/starefossen/mcpauth)

Per-caller bearer token authentication for MCP and other HTTP servers in Go.
Standard library only, no dependencies.

Each caller gets its own token, so logs and handlers know who made a request.
Tokens can be static secrets read from files, or JWT access tokens from an
OAuth 2.0 / OIDC issuer.

```sh
go get github.com/starefossen/mcpauth
```

## Threat model

- **Fail closed.** `Load` returns an error if the directory is unset or
  missing, has no groups, or a group has no usable token. Requests to an
  unknown group are rejected.
- **Header only.** Tokens are read from `Authorization: Bearer <token>`,
  never from query strings or cookies.
- **Constant-time comparison** of static tokens, against every token in the
  group with no early exit. Tokens shorter than 16 bytes and duplicate tokens
  are rejected at load time.
- **Per-caller identity.** The caller name is logged for each request and is
  available to handlers. Tokens are never logged.
- **JWT checks:** ES256 only (`none`, HS\* and RS\* are rejected), header
  `typ` must be `at+jwt`, known `kid`, `iss`, `aud`, `exp` (required) and
  `nbf` with 60 s skew, every `required_scope` entry present, and `sub` must
  be listed in `callers`.
- **JWKS** fetches never follow redirects. Keys are cached, refreshed hourly
  and on an unknown `kid` at most once per 60 s. A failed fetch keeps the last
  good keyset.

Out of scope: TLS (terminate it in front of the server), rate limiting, and
per-tool authorization inside a group.

## Quick start: static tokens

Tokens are files under a directory, laid out as `<group>/<caller>`. The file
content is the token. Hidden entries (names starting with `.`) are ignored.

```
callers/
  read/
    alice
    bob
  write/
    alice
```

```go
auth, err := mcpauth.Load(os.Getenv("MCP_CALLERS_DIR"))
if err != nil {
	log.Fatal(err) // no usable tokens: do not start
}

mux := http.NewServeMux()
mux.HandleFunc("/health", health) // keep outside Require
mux.Handle("/mcp", auth.Require("read", mcpHandler))

// inside a handler:
caller := mcpauth.Caller(r.Context())
```

### Kubernetes

A Secret projected as a volume produces this layout:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-mcp-callers
stringData:
  alice: "<random token, at least 16 bytes>"
  svc-reader: "<random token>"
---
# in the pod spec
containers:
  - name: server
    env:
      - name: MCP_CALLERS_DIR
        value: /var/run/mcp-callers
    volumeMounts:
      - name: callers
        mountPath: /var/run/mcp-callers
        readOnly: true
volumes:
  - name: callers
    projected:
      sources:
        - secret:
            name: example-mcp-callers
            items:
              - key: alice
                path: read/alice
              - key: svc-reader
                path: read/svc-reader
```

## JWT access tokens

A group directory may also contain `jwks.json`. The group then accepts ES256
access tokens (RFC 9068) signed by a key from that JWKS, beside any static
tokens in the same group:

```json
{
  "issuer": "https://issuer.example.com",
  "audience": "mcp-read",
  "jwks_url": "https://issuer.example.com/jwks.json",
  "required_scope": ["mcp:read"],
  "callers": {"3f1c9a2e-0d4b-4c6e-9a7f-2b8d5e1f0c3a": "svc-reader"}
}
```

`callers` maps the token's `sub` to a caller name and is an allowlist: a
token whose `sub` is not listed is rejected, and a missing or empty `callers`
accepts no JWT (`Load` logs a warning). A caller name may not reuse a static
caller name in the same group. A group may hold only `jwks.json`. Until the
JWKS first loads, JWTs are rejected; static tokens are not affected.

A typical client gets its token by OAuth 2.0 token exchange (RFC 8693),
trading its own credential for a short-lived access token:

```sh
curl -s https://issuer.example.com/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=mcp-read \
  -d subject_token="$SERVICE_ACCOUNT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d scope=mcp:read
```

Send the `access_token` from the response as the bearer token. Do not store
the `refresh_token`; request a new access token when the old one expires.

### Kanidm notes

Tested against Kanidm 1.11.x:

- Service-account token exchange needs a public OAuth2 client on 1.11.x.
- Access tokens carry no `groups` or `preferred_username` claim. Gate access
  on a scope (`required_scope`) mapped to the group in Kanidm.
- `sub` is the account UUID, so `callers` is keyed by UUID.
- ID tokens are signed with the same key but have `typ: JWT`, so they are
  rejected.

## Rotation

Static tokens and `jwks.json` are read once at start. To rotate, update the
files and restart the process (for Kubernetes, roll out the Deployment).
JWT signing keys rotate on their own through JWKS refresh.

## Limitations

- No hot reload of token files.
- JWT support is ES256 only, with one issuer per group.
- No token revocation for JWTs beyond expiry; keep access token lifetimes short.

## Versioning

The module is at 0.x. Breaking changes can happen in minor releases and are
noted in the release notes.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT
