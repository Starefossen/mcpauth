// Package mcpauth authenticates MCP callers by bearer token.
//
// Tokens live in files under MCP_CALLERS_DIR as <group>/<caller>, typically a
// projected Kubernetes Secret. Servers call Load once at start and wrap
// protected routes with Require. /health must be mounted outside Require.
// Tokens are read once at start: rotate by rolling out a new revision or
// restarting the pods.
package mcpauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const minTokenLen = 16

// verifier is the extension point for phase 2 (Kanidm JWTs). Keep it
// unexported until a second implementation exists.
type verifier interface {
	verify(ctx context.Context, bearer string) (caller string, ok bool)
}

type Auth struct {
	groups map[string]verifier
}

type ctxKey struct{}

var logf = log.Printf

// ctEqual is a variable so tests can count comparisons.
var ctEqual = func(a, b [32]byte) int { return subtle.ConstantTimeCompare(a[:], b[:]) }

type staticVerifier struct {
	callers []string
	hashes  [][32]byte
}

func (s *staticVerifier) verify(_ context.Context, bearer string) (string, bool) {
	h := sha256.Sum256([]byte(bearer))
	idx := -1
	for i := range s.hashes {
		if ctEqual(h, s.hashes[i]) == 1 && idx < 0 {
			idx = i
		}
	}
	if idx < 0 {
		return "", false
	}
	return s.callers[idx], true
}

// Load reads <dir>/<group>/<caller> token files. It fails if dir is empty,
// missing, has no groups, or any group has no usable token.
func Load(dir string) (*Auth, error) {
	if dir == "" {
		return nil, errors.New("mcpauth: callers dir not set")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("mcpauth: %w", err)
	}
	a := &Auth{groups: map[string]verifier{}}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		gdir := filepath.Join(dir, name)
		if fi, err := os.Stat(gdir); err != nil || !fi.IsDir() {
			continue
		}
		v, err := loadGroup(gdir)
		if err != nil {
			return nil, fmt.Errorf("mcpauth: group %s: %w", name, err)
		}
		a.groups[name] = v
	}
	if len(a.groups) == 0 {
		return nil, fmt.Errorf("mcpauth: no groups in %s", dir)
	}
	return a, nil
}

func loadGroup(gdir string) (verifier, error) {
	entries, err := os.ReadDir(gdir)
	if err != nil {
		return nil, err
	}
	v := &staticVerifier{}
	seen := map[[32]byte]string{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == jwksFile {
			continue
		}
		p := filepath.Join(gdir, name)
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(p) //nolint:gosec // p is under the operator-controlled callers dir
		if err != nil {
			return nil, err
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			continue
		}
		if len(tok) < minTokenLen {
			return nil, fmt.Errorf("caller %s: token shorter than %d bytes", name, minTokenLen)
		}
		h := sha256.Sum256([]byte(tok))
		if prev, dup := seen[h]; dup {
			return nil, fmt.Errorf("callers %s and %s share a token", prev, name)
		}
		seen[h] = name
		v.callers = append(v.callers, name)
		v.hashes = append(v.hashes, h)
	}
	jp := filepath.Join(gdir, jwksFile)
	if _, err := os.Stat(jp); err != nil {
		if len(v.callers) == 0 {
			return nil, errors.New("no non-empty token files")
		}
		return v, nil
	}
	j, err := loadJWTConfig(jp)
	if err != nil {
		return nil, err
	}
	for sub, name := range j.cfg.Callers {
		if strings.TrimSpace(sub) == "" {
			return nil, fmt.Errorf("%s: caller %q has an empty sub", jwksFile, name)
		}
		if name == "" || slices.Contains(v.callers, name) {
			return nil, fmt.Errorf("%s: caller name %q empty or used by a static token", jwksFile, name)
		}
	}
	if len(j.cfg.Callers) == 0 {
		logf("mcpauth: %s has no callers; no JWT will be accepted", jp)
	}
	j.start(context.Background())
	if len(v.callers) == 0 {
		return j, nil
	}
	return multiVerifier{v, j}, nil
}

// Has reports whether group was loaded.
func (a *Auth) Has(group string) bool {
	_, ok := a.groups[group]
	return ok
}

// Require admits requests with a valid "Authorization: Bearer <token>" for
// group. An unknown group rejects everything.
func (a *Auth) Require(group string, next http.Handler) http.Handler {
	v := a.groups[group]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v != nil {
			if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
				if caller, ok := v.verify(r.Context(), bearer); ok {
					logf("caller=%q path=%s", caller, r.URL.Path)
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, caller)))
					return
				}
			}
		}
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remote = r.RemoteAddr
		}
		logf("auth=denied path=%s remote=%s", r.URL.Path, remote)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// Caller returns the authenticated caller name, or "" outside Require.
func Caller(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}
