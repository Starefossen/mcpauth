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
