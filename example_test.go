package mcpauth_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/starefossen/mcpauth"
)

func ExampleLoad() {
	dir, err := os.MkdirTemp("", "callers")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.MkdirAll(filepath.Join(dir, "read"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "read", "alice"), []byte("alice-token-0123456789\n"), 0o600)

	auth, err := mcpauth.Load(dir)
	if err != nil {
		log.Fatal(err)
	}
	h := auth.Require("read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello", mcpauth.Caller(r.Context()))
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer alice-token-0123456789")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	fmt.Print(rec.Body.String())
	// Output: hello alice
}
