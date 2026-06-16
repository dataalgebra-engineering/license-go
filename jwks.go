package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// DefaultJWKSMaxAge bounds how long a fetched JWKS is trusted before a refresh
// is attempted. Rotation overlap (one token TTL) means a modest age is safe.
const DefaultJWKSMaxAge = time.Hour

// DefaultJWKSFailOpenTTL caps how long a cached key may be served when refreshes
// keep failing. Fail-open keeps a valid deployment working through a brief
// outage, but an unbounded window would let a revoked/compromised key be trusted
// forever — so past this age (since the last successful fetch) we fail closed.
const DefaultJWKSFailOpenTTL = 24 * time.Hour

// JWKSClient fetches and caches Burnside's ES256 public keys (JWKS) for offline
// token verification. It refreshes on an unknown `kid` or when the cache is
// stale, and is **fail-open within token validity**: if a refresh fails it
// keeps serving the cached key so a brief outage or a rotation first seen
// offline does not strand a still-valid deployment.
type JWKSClient struct {
	url         string
	hc          *http.Client
	maxAge      time.Duration
	failOpenTTL time.Duration

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
}

// JWKSOption configures a JWKSClient.
type JWKSOption func(*JWKSClient)

// WithHTTPClient overrides the HTTP client used to fetch the JWKS.
func WithHTTPClient(hc *http.Client) JWKSOption { return func(c *JWKSClient) { c.hc = hc } }

// WithMaxAge sets the cache freshness window.
func WithMaxAge(d time.Duration) JWKSOption { return func(c *JWKSClient) { c.maxAge = d } }

// WithFailOpenTTL caps how long a cached key is served while refreshes fail
// (default DefaultJWKSFailOpenTTL). After this age since the last successful
// fetch, the client fails closed instead of serving a stale key.
func WithFailOpenTTL(d time.Duration) JWKSOption {
	return func(c *JWKSClient) { c.failOpenTTL = d }
}

// NewJWKSClient builds a client for the JWKS at url (e.g.
// https://license.burnsideproject.ai/.well-known/jwks.json).
func NewJWKSClient(url string, opts ...JWKSOption) *JWKSClient {
	c := &JWKSClient{
		url:         url,
		hc:          &http.Client{Timeout: 5 * time.Second},
		maxAge:      DefaultJWKSMaxAge,
		failOpenTTL: DefaultJWKSFailOpenTTL,
		keys:        map[string]*ecdsa.PublicKey{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// KeyByID returns the ES256 public key for kid. It serves a fresh cached key
// directly; otherwise it refreshes. On refresh failure it falls back to any
// cached key for kid (fail-open) and only errors when nothing is cached.
func (c *JWKSClient) KeyByID(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	fresh := !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < c.maxAge
	c.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	if err := c.Refresh(ctx); err != nil {
		// Fail-open, but only within failOpenTTL of the last successful fetch: a
		// still-cached key keeps a valid deployment working through a brief
		// outage, while a prolonged outage fails closed so a revoked/compromised
		// key is not trusted indefinitely.
		c.mu.RLock()
		key, ok = c.keys[kid]
		withinGrace := !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < c.failOpenTTL
		c.mu.RUnlock()
		if ok && withinGrace {
			return key, nil
		}
		if ok {
			return nil, fmt.Errorf("jwks: refresh failed and cached kid %q is stale beyond fail-open TTL %s: %w", kid, c.failOpenTTL, err)
		}
		return nil, fmt.Errorf("jwks: refresh failed and kid %q not cached: %w", kid, err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found", kid)
	}
	return key, nil
}

// Refresh fetches and replaces the cached key set.
func (c *JWKSClient) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}

	next := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := k.ecdsaPublicKey()
		if err != nil {
			continue // skip unsupported keys, keep the rest
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return fmt.Errorf("jwks: no usable ES256 keys in document")
	}

	c.mu.Lock()
	c.keys = next
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// jwk is a JSON Web Key (subset for EC P-256 signing keys).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func (k jwk) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("jwks: unsupported key kty=%q crv=%q", k.Kty, k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwks: bad y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}
