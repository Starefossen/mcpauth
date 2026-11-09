package mcpauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIss = "https://id.example.org/oauth2/openid/mcp-read"
	testAud = "mcp-read"
)

type jwksServer struct {
	*httptest.Server
	mu    sync.Mutex
	keys  map[string]*ecdsa.PrivateKey
	down  atomic.Bool
	calls atomic.Int32
}

func newJWKSServer(t *testing.T) *jwksServer {
	s := &jwksServer{keys: map[string]*ecdsa.PrivateKey{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.calls.Add(1)
		if s.down.Load() {
			http.Error(w, "down", 503)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var ks []map[string]string
		for kid, k := range s.keys {
			b, _ := k.PublicKey.Bytes()
			ks = append(ks, map[string]string{
				"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
				"x": base64.RawURLEncoding.EncodeToString(b[1:33]),
				"y": base64.RawURLEncoding.EncodeToString(b[33:]),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	}))
	t.Cleanup(s.Close)
	old := httpClient
	httpClient = s.Client()
	t.Cleanup(func() { httpClient = old })
	return s
}

func (s *jwksServer) addKey(t *testing.T, kid string) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	s.mu.Lock()
	s.keys[kid] = k
	s.mu.Unlock()
	return k
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(t *testing.T, k *ecdsa.PrivateKey, hdr, cl map[string]any) string {
	in := b64json(hdr) + "." + b64json(cl)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	must(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// kanidmClaims mirrors the shape of a Kanidm 1.11 exchanged access token.
func kanidmClaims() map[string]any {
	n := time.Now().Unix()
	return map[string]any{
		"iss": testIss, "sub": "0b0e5c4e-uuid", "aud": testAud,
		"iat": n, "nbf": n, "exp": n + 900,
		"preferred_username": "sa-varden@id.example.org",
		"groups":             []string{"mcp-read@id.example.org", "00000000-uuid"},
	}
}

func setupJWT(t *testing.T, cfg string, static bool) (*Auth, *jwksServer, *ecdsa.PrivateKey) {
	s := newJWKSServer(t)
	k := s.addKey(t, "k1")
	d := t.TempDir()
	if static {
		write(t, filepath.Join(d, "read/legacy"), tokLegacy)
	}
	write(t, filepath.Join(d, "read", jwksFile), fmt.Sprintf(cfg, s.URL))
	a, err := Load(d)
	must(t, err)
	waitLoaded(t, a)
	return a, s, k
}

func jv(a *Auth) *jwtVerifier {
	switch v := a.groups["read"].(type) {
	case *jwtVerifier:
		return v
	case multiVerifier:
		return v[1].(*jwtVerifier)
	}
	return nil
}

func waitLoaded(t *testing.T, a *Auth) {
	j := jv(a)
	for range 200 {
		j.mu.RLock()
		n := len(j.keys)
		j.mu.RUnlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("jwks never loaded")
}

const baseCfg = `{"issuer":"` + testIss + `","audience":"` + testAud + `","jwks_url":"%s","required_group":"mcp-read"}`

func TestJWTAccepts(t *testing.T) {
	a, _, k := setupJWT(t, baseCfg, true)
	tok := sign(t, k, map[string]any{"alg": "ES256", "kid": "k1", "typ": "at+jwt"}, kanidmClaims())
	if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 200 || c.caller != "sa-varden" {
		t.Fatalf("%+v", c)
	}
	if c := do(t, a, "read", "Bearer "+tokLegacy, ""); c.code != 200 || c.caller != "legacy" {
		t.Fatalf("static: %+v", c)
	}
	cl := kanidmClaims()
	delete(cl, "preferred_username")
	cl["aud"] = []string{"other", testAud}
	if c := do(t, a, "read", "Bearer "+sign(t, k, map[string]any{"alg": "ES256", "kid": "k1"}, cl), ""); c.caller != "0b0e5c4e-uuid" {
		t.Fatalf("sub fallback: %+v", c)
	}
}

func TestJWTRejects(t *testing.T) {
	a, _, k := setupJWT(t, baseCfg, false)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hdr := map[string]any{"alg": "ES256", "kid": "k1"}
	mod := func(f func(map[string]any)) map[string]any { c := kanidmClaims(); f(c); return c }
	n := time.Now().Unix()
	good := sign(t, k, hdr, kanidmClaims())
	hs := b64json(map[string]any{"alg": "HS256", "kid": "k1"}) + "." + b64json(kanidmClaims())
	mac := hmac.New(sha256.New, []byte("x"))
	mac.Write([]byte(hs))
	cases := map[string]string{
		"expired":        sign(t, k, hdr, mod(func(c map[string]any) { c["exp"] = n - 61 })),
		"no exp":         sign(t, k, hdr, mod(func(c map[string]any) { delete(c, "exp") })),
		"future nbf":     sign(t, k, hdr, mod(func(c map[string]any) { c["nbf"] = n + 120 })),
		"wrong aud":      sign(t, k, hdr, mod(func(c map[string]any) { c["aud"] = "mcp-write" })),
		"wrong iss":      sign(t, k, hdr, mod(func(c map[string]any) { c["iss"] = "https://evil" })),
		"missing group":  sign(t, k, hdr, mod(func(c map[string]any) { c["groups"] = []string{"mcp-write"} })),
		"wrong key":      sign(t, other, hdr, kanidmClaims()),
		"unknown kid":    sign(t, k, map[string]any{"alg": "ES256", "kid": "nope"}, kanidmClaims()),
		"no kid":         sign(t, k, map[string]any{"alg": "ES256"}, kanidmClaims()),
		"alg none":       b64json(map[string]any{"alg": "none", "kid": "k1"}) + "." + b64json(kanidmClaims()) + ".",
		"alg HS256":      hs + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
		"crit":           sign(t, k, map[string]any{"alg": "ES256", "kid": "k1", "crit": []string{"x"}}, kanidmClaims()),
		"tampered claim": good[:len(good)-90] + "A" + good[len(good)-89:],
		"two parts":      good[:len(good)-87],
	}
	for name, tok := range cases {
		if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 401 {
			t.Errorf("%s: %+v", name, c)
		}
	}
	// Within skew.
	if c := do(t, a, "read", "Bearer "+sign(t, k, hdr, mod(func(c map[string]any) { c["exp"] = n - 30 })), ""); c.code != 200 {
		t.Errorf("skew: %+v", c)
	}
}

func TestJWTUnknownKidRefetchRateLimited(t *testing.T) {
	a, s, _ := setupJWT(t, baseCfg, false)
	j := jv(a)
	j.mu.Lock()
	j.lastFetch = time.Time{}
	j.mu.Unlock()
	k2 := s.addKey(t, "k2")
	before := s.calls.Load()
	tok := sign(t, k2, map[string]any{"alg": "ES256", "kid": "k2"}, kanidmClaims())
	if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 200 {
		t.Fatalf("rotated key: %+v", c)
	}
	for range 20 {
		do(t, a, "read", "Bearer "+sign(t, k2, map[string]any{"alg": "ES256", "kid": "random"}, kanidmClaims()), "")
	}
	if got := s.calls.Load() - before; got != 1 {
		t.Fatalf("jwks fetches = %d, want 1", got)
	}
}

func TestJWKSOutageKeepsKeysAndStatic(t *testing.T) {
	a, s, k := setupJWT(t, baseCfg, true)
	s.down.Store(true)
	j := jv(a)
	if err := j.refresh(t.Context()); err == nil {
		t.Fatal("refresh succeeded while down")
	}
	tok := sign(t, k, map[string]any{"alg": "ES256", "kid": "k1"}, kanidmClaims())
	if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 200 {
		t.Errorf("cached key: %+v", c)
	}
	if c := do(t, a, "read", "Bearer "+tokLegacy, ""); c.code != 200 {
		t.Errorf("static: %+v", c)
	}
}

func TestJWKSDownAtStart(t *testing.T) {
	s := newJWKSServer(t)
	k := s.addKey(t, "k1")
	s.down.Store(true)
	old := retryDelays
	retryDelays = []time.Duration{10 * time.Millisecond}
	defer func() { retryDelays = old }()
	d := t.TempDir()
	write(t, filepath.Join(d, "read/legacy"), tokLegacy)
	write(t, filepath.Join(d, "read", jwksFile), fmt.Sprintf(baseCfg, s.URL))
	a, err := Load(d)
	must(t, err)
	if c := do(t, a, "read", "Bearer "+tokLegacy, ""); c.code != 200 {
		t.Fatalf("static while jwks down: %+v", c)
	}
	tok := sign(t, k, map[string]any{"alg": "ES256", "kid": "k1"}, kanidmClaims())
	if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 401 {
		t.Fatalf("jwt before jwks: %+v", c)
	}
	s.down.Store(false)
	waitLoaded(t, a)
	if c := do(t, a, "read", "Bearer "+tok, ""); c.code != 200 {
		t.Fatalf("jwt after recovery: %+v", c)
	}
}

func TestJWTConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"http url":      `{"issuer":"i","audience":"a","jwks_url":"http://x"}`,
		"no audience":   `{"issuer":"i","jwks_url":"https://x"}`,
		"unknown field": `{"issuer":"i","audience":"a","jwks_url":"https://x","alg":"none"}`,
		"bad json":      `{`,
	} {
		d := t.TempDir()
		write(t, filepath.Join(d, "read", jwksFile), cfg)
		if _, err := Load(d); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}
