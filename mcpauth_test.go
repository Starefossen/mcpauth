package mcpauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	tokAlice = "alice-token-0123456789"
	tokBob   = "bob-token-0123456789"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) string {
	d := t.TempDir()
	write(t, filepath.Join(d, "read/alice"), tokAlice+"\n")
	write(t, filepath.Join(d, "read/bob"), tokBob)
	return d
}

func TestLoadFailsClosed(t *testing.T) {
	empty := t.TempDir()
	emptyGroup := t.TempDir()
	write(t, filepath.Join(emptyGroup, "read/x"), "  \n")
	short := t.TempDir()
	write(t, filepath.Join(short, "read/x"), "123456789012345\n")
	for name, dir := range map[string]string{
		"unset": "", "missing": filepath.Join(empty, "nope"), "empty": empty,
		"group without tokens": emptyGroup, "short token": short,
	} {
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}

func TestLoadSixteenBytesOK(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "read/x"), " 1234567890123456 \n")
	a, err := Load(d)
	if err != nil || !a.Has("read") || a.Has("write") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadK8sProjection(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "..2025_01_01_00_00_00.123/read/alice"), tokAlice)
	must(t, os.Symlink("..2025_01_01_00_00_00.123", filepath.Join(d, "..data")))
	must(t, os.Symlink("..data/read", filepath.Join(d, "read")))
	a, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.groups) != 1 || !a.Has("read") {
		t.Fatalf("groups=%v", a.groups)
	}
	if c := do(t, a, "read", "Bearer "+tokAlice, ""); c.code != 200 || c.caller != "alice" {
		t.Fatalf("%+v", c)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type result struct {
	code         int
	body, caller string
	log          string
}

func do(t *testing.T, a *Auth, group, authz, query string) result {
	t.Helper()
	stop := captureLog()
	var caller string
	h := a.Require(group, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller = Caller(r.Context())
	}))
	req := httptest.NewRequest("GET", "/sse"+query, nil)
	req.RemoteAddr = "10.0.0.7:5555"
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return result{rec.Code, rec.Body.String(), caller, stop()}
}

// logSink lets tests capture logf output while background JWKS goroutines
// keep logging concurrently.
var logSink struct {
	sync.Mutex
	buf *bytes.Buffer
}

func init() {
	logf = func(f string, v ...any) {
		logSink.Lock()
		defer logSink.Unlock()
		if logSink.buf != nil {
			fmt.Fprintf(logSink.buf, f+"\n", v...)
		}
	}
}

// captureLog starts capturing logf output; the returned func stops and
// returns it.
func captureLog() func() string {
	logSink.Lock()
	defer logSink.Unlock()
	b := &bytes.Buffer{}
	logSink.buf = b
	return func() string {
		logSink.Lock()
		defer logSink.Unlock()
		logSink.buf = nil
		return b.String()
	}
}

func TestRequire(t *testing.T) {
	a, err := Load(fixture(t))
	must(t, err)
	if c := do(t, a, "read", "Bearer "+tokAlice, ""); c.code != 200 || c.caller != "alice" || c.log != "caller=\"alice\" path=/sse\n" {
		t.Errorf("alice: %+v", c)
	}
	if c := do(t, a, "read", "Bearer "+tokBob, ""); c.code != 200 || c.caller != "bob" {
		t.Errorf("bob: %+v", c)
	}
	denied := map[string][2]string{
		"none":          {"", ""},
		"query":         {"", "?token=" + tokAlice},
		"bare":          {tokAlice, ""},
		"basic":         {"Basic " + tokAlice, ""},
		"lower bearer":  {"bearer " + tokAlice, ""},
		"wrong":         {"Bearer wrong-token-0123456789", ""},
		"prefix":        {"Bearer " + tokAlice[:16], ""},
		"trailing junk": {"Bearer " + tokAlice + "x", ""},
	}
	for name, in := range denied {
		c := do(t, a, "read", in[0], in[1])
		if c.code != 401 || c.body != "unauthorized\n" || c.caller != "" {
			t.Errorf("%s: %+v", name, c)
		}
		if c.log != "auth=denied path=/sse remote=10.0.0.7\n" {
			t.Errorf("%s: log %q", name, c.log)
		}
	}
	if c := do(t, a, "write", "Bearer "+tokAlice, ""); c.code != 401 {
		t.Errorf("unknown group: %+v", c)
	}
}

func TestLogNeverContainsToken(t *testing.T) {
	a, err := Load(fixture(t))
	must(t, err)
	for _, authz := range []string{"Bearer " + tokAlice, "Bearer " + tokAlice + "x", tokBob} {
		if c := do(t, a, "read", authz, ""); strings.Contains(c.log, tokAlice) || strings.Contains(c.log, tokBob) {
			t.Errorf("token in log: %q", c.log)
		}
	}
}

func TestCompareAllTokensNoEarlyExit(t *testing.T) {
	a, err := Load(fixture(t))
	must(t, err)
	n := 0
	old := ctEqual
	ctEqual = func(x, y [32]byte) int { n++; return old(x, y) }
	defer func() { ctEqual = old }()
	for _, tok := range []string{tokBob, tokAlice, "nope-nope-nope-nope"} {
		n = 0
		a.groups["read"].verify(t.Context(), tok)
		if n != 2 {
			t.Errorf("%s: %d compares, want 2", tok, n)
		}
	}
}

func TestCallerEmptyOutsideRequire(t *testing.T) {
	if Caller(t.Context()) != "" {
		t.Fatal("caller set")
	}
}

func TestLoadRejectsDuplicateToken(t *testing.T) {
	d := t.TempDir()
	const tok = "shared-token-0123456789"
	write(t, filepath.Join(d, "g", "a"), tok)
	write(t, filepath.Join(d, "g", "b"), tok+"\n")
	_, err := Load(d)
	if err == nil || !strings.Contains(err.Error(), "a and b") || strings.Contains(err.Error(), tok) {
		t.Fatalf("err = %v", err)
	}
}
