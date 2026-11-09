# mcpauth

Per-caller bearer token authentication for Go HTTP servers, built for MCP
servers. Plain `net/http`, no dependencies.

```sh
go get github.com/starefossen/mcpauth
```

## Token layout

Tokens are files under a directory, one subdirectory per route group:

```
callers/
  read/
    alice      # file content is alice's token
    bob
  write/
    alice
```

A Kubernetes Secret projected as a volume fits this layout. Hidden entries
(names starting with `.`) are ignored.

## Usage

```go
auth, err := mcpauth.Load(os.Getenv("MCP_CALLERS_DIR"))
if err != nil {
	log.Fatal(err) // fail closed: no tokens, no server
}

mux := http.NewServeMux()
mux.HandleFunc("/health", health)                 // keep outside Require
mux.Handle("/mcp", auth.Require("read", mcpHandler))

// inside a handler:
caller := mcpauth.Caller(r.Context())
```

## Kanidm JWTs (optional)

A group directory may also contain `jwks.json`:

```json
{"issuer": "https://id.example.org/oauth2/openid/mcp-read",
 "audience": "mcp-read",
 "jwks_url": "https://id.example.org/oauth2/openid/mcp-read/public_key.jwk",
 "required_group": "mcp-read"}
```

The group then also accepts ES256 access tokens (RFC 9068) signed by a key in
that JWKS. Checks: `alg` is ES256 (none/HS*/RS* rejected), `kid` known, `iss`,
`aud` contains `audience`, `exp` required, `nbf`, with 60 s skew. If
`required_group` is set, the `groups` claim must contain it (an SPN such as
`mcp-read@id.example.org` matches). The caller is `preferred_username`
before `@`, else `sub`. Static tokens in the same group keep working, so
callers migrate one at a time. A group may hold only `jwks.json`.

The JWKS is fetched in the background at start (retry with backoff; JWTs are
rejected until it loads, static tokens are not affected), then hourly, and
on an unknown `kid` at most once per 60 s. A failed fetch keeps the last good
keyset, so an issuer outage only stops callers once their tokens expire.

## Security notes

- Fail closed. `Load` returns an error if the directory is unset, missing,
  has no groups, or a group has no usable token. Requests to an unknown group
  are rejected.
- Header only. Tokens are accepted from `Authorization: Bearer <token>`,
  never from query strings or cookies.
- Constant-time comparison against every token in the group.
- Tokens shorter than 16 bytes are rejected at load time.
- Tokens are read once at start. To rotate, update the files and restart
  the process.

## License

MIT
