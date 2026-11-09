// Package mcpauth adds per-caller bearer token authentication to Go HTTP
// servers, such as MCP servers. It uses only the standard library.
//
// Tokens are files under a directory, laid out as <group>/<caller>; a
// Kubernetes Secret projected as a volume fits this layout. A group directory
// may also hold a jwks.json file, in which case the group accepts ES256 JWT
// access tokens from that issuer as well.
//
// Call Load once at start and wrap protected routes with Require. Load fails
// if no usable token is found, so a misconfigured server does not start.
// Tokens are read once: to rotate, update the files and restart the process.
//
//	auth, err := mcpauth.Load(os.Getenv("MCP_CALLERS_DIR"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	mux := http.NewServeMux()
//	mux.HandleFunc("/health", health) // outside Require
//	mux.Handle("/mcp", auth.Require("read", mcpHandler))
//
// Inside a handler, Caller returns the authenticated caller's name.
package mcpauth
