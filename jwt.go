package mcpauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// jwksFile in a group dir enables JWT verification for that group.
const jwksFile = "jwks.json"

const (
	clockSkew       = 60 * time.Second
	refreshInterval = time.Hour
	kidRefetchGap   = 60 * time.Second
	maxJWTLen       = 8 << 10
	maxJWKSBytes    = 64 << 10
)

var (
	now        = time.Now
	httpClient = &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	// retryDelays is the startup backoff until the first JWKS loads; the
	// last value repeats.
	retryDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}
)

type jwtConfig struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
	// RequiredScope lists scopes that must all be in the token's scope claim.
	RequiredScope []string `json:"required_scope"`
	// Callers maps sub (a Kanidm UUID) to a readable caller name.
	Callers map[string]string `json:"callers"`
}

type jwtVerifier struct {
	cfg jwtConfig

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	lastFetch time.Time
}

func loadJWTConfig(p string) (*jwtVerifier, error) {
	b, err := os.ReadFile(p) //nolint:gosec // operator-controlled callers dir
	if err != nil {
		return nil, err
	}
	var c jwtConfig
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", jwksFile, err)
	}
	if c.Issuer == "" || c.Audience == "" || !strings.HasPrefix(c.JWKSURL, "https://") {
		return nil, fmt.Errorf("%s: issuer, audience and https jwks_url are required", jwksFile)
	}
	return &jwtVerifier{cfg: c}, nil
}

// start loads the JWKS in the background: retry with backoff until the first
// success, then refresh hourly. Until loaded, every JWT is rejected.
func (j *jwtVerifier) start(ctx context.Context) {
	go func() {
		for i := 0; j.refresh(ctx) != nil; i++ {
			d := retryDelays[min(i, len(retryDelays)-1)]
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
		}
		t := time.NewTicker(refreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = j.refresh(ctx)
			}
		}
	}()
}

// refresh fetches the JWKS. On error the previous keyset is kept.
func (j *jwtVerifier) refresh(ctx context.Context) error {
	j.mu.Lock()
	j.lastFetch = now()
	j.mu.Unlock()
	return j.fetch(ctx)
}

func (j *jwtVerifier) fetch(ctx context.Context) error {
	keys, err := fetchJWKS(ctx, j.cfg.JWKSURL)
	if err != nil {
		logf("mcpauth: jwks fetch %s: %v", j.cfg.JWKSURL, err)
		return err
	}
	j.mu.Lock()
	j.keys = keys
	j.mu.Unlock()
	return nil
}

func fetchJWKS(ctx context.Context, url string) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Crv, Kid, X, Y, Use, Alg string
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "ES256") {
			continue
		}
		x, err1 := base64.RawURLEncoding.DecodeString(k.X)
		y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable ES256 keys")
	}
	return keys, nil
}

// key returns the key for kid, refetching the JWKS on a miss at most once
// per kidRefetchGap so random kids cannot hammer Kanidm.
func (j *jwtVerifier) key(ctx context.Context, kid string) *ecdsa.PublicKey {
	j.mu.Lock()
	k := j.keys[kid]
	if k != nil || now().Sub(j.lastFetch) < kidRefetchGap {
		j.mu.Unlock()
		return k
	}
	j.lastFetch = now()
	j.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = j.fetch(ctx)
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keys[kid]
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

type claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   audience `json:"aud"`
	Exp   *float64 `json:"exp"`
	Nbf   *float64 `json:"nbf"`
	Scope string   `json:"scope"`
}

func (j *jwtVerifier) verify(ctx context.Context, bearer string) (string, bool) {
	if len(bearer) > maxJWTLen {
		return "", false
	}
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return "", false
	}
	var hdr struct {
		Alg, Kid, Typ string
		Crit          json.RawMessage
	}
	if !decodeSegment(parts[0], &hdr) || hdr.Alg != "ES256" || hdr.Kid == "" || !strings.EqualFold(hdr.Typ, "at+jwt") || hdr.Crit != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return "", false
	}
	pub := j.key(ctx, hdr.Kid)
	if pub == nil {
		return "", false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return "", false
	}
	var c claims
	if !decodeSegment(parts[1], &c) || c.Iss != j.cfg.Issuer || !contains(c.Aud, j.cfg.Audience) || c.Exp == nil {
		return "", false
	}
	t := float64(now().Unix())
	skew := clockSkew.Seconds()
	if t > *c.Exp+skew || (c.Nbf != nil && t < *c.Nbf-skew) {
		return "", false
	}
	scopes := strings.Fields(c.Scope)
	for _, want := range j.cfg.RequiredScope {
		if !contains(scopes, want) {
			return "", false
		}
	}
	if name, ok := j.cfg.Callers[c.Sub]; ok {
		return name, true
	}
	return c.Sub, c.Sub != ""
}

func decodeSegment(seg string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	return err == nil && json.Unmarshal(b, v) == nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// multiVerifier tries static tokens first, then JWTs. Static tokens are
// always compared in constant time even when the bearer looks like a JWT.
type multiVerifier []verifier

func (m multiVerifier) verify(ctx context.Context, bearer string) (string, bool) {
	for _, v := range m {
		if c, ok := v.verify(ctx, bearer); ok {
			return c, true
		}
	}
	return "", false
}
