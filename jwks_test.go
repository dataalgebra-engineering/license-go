package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// jwksServer serves a JWKS document with the given keys and counts fetches.
func jwksServer(t *testing.T, keys map[string]*ecdsa.PublicKey) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	doc := map[string]any{"keys": []any{}}
	list := make([]jwk, 0, len(keys))
	for kid, pub := range keys {
		list = append(list, jwk{
			Kty: "EC", Crv: "P-256", Kid: kid, Alg: "ES256", Use: "sig",
			X: b64coord(pub.X.Bytes()), Y: b64coord(pub.Y.Bytes()),
		})
	}
	doc["keys"] = list
	body, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// b64coord left-pads a P-256 coordinate to 32 bytes and base64url-encodes it.
func b64coord(b []byte) string {
	const size = 32
	if len(b) < size {
		p := make([]byte, size)
		copy(p[size-len(b):], b)
		b = p
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func TestJWKS_KeyByID(t *testing.T) {
	k := newKey(t)
	srv, hits := jwksServer(t, map[string]*ecdsa.PublicKey{"kid-1": &k.PublicKey})

	c := NewJWKSClient(srv.URL)
	got, err := c.KeyByID(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("KeyByID: %v", err)
	}
	if got.X.Cmp(k.PublicKey.X) != 0 || got.Y.Cmp(k.PublicKey.Y) != 0 {
		t.Fatal("returned key does not match served key")
	}

	// Second lookup of a fresh, known kid must not refetch.
	if _, err := c.KeyByID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("second KeyByID: %v", err)
	}
	if h := atomic.LoadInt32(hits); h != 1 {
		t.Errorf("expected 1 fetch for a fresh cache, got %d", h)
	}
}

func TestJWKS_UnknownKidTriggersRefresh(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	// Server initially only has kid-1; KeyByID for an unknown kid forces a fetch.
	srv, hits := jwksServer(t, map[string]*ecdsa.PublicKey{"kid-1": &k1.PublicKey, "kid-2": &k2.PublicKey})
	c := NewJWKSClient(srv.URL)

	if _, err := c.KeyByID(context.Background(), "kid-2"); err != nil {
		t.Fatalf("KeyByID kid-2: %v", err)
	}
	if h := atomic.LoadInt32(hits); h < 1 {
		t.Errorf("expected a fetch, got %d", h)
	}
	// A kid that is genuinely absent errors (after a refresh attempt).
	if _, err := c.KeyByID(context.Background(), "kid-absent"); err == nil {
		t.Error("expected error for absent kid")
	}
}

func TestJWKS_FailOpenServesCached(t *testing.T) {
	k := newKey(t)
	srv, _ := jwksServer(t, map[string]*ecdsa.PublicKey{"kid-1": &k.PublicKey})

	// maxAge=0 forces a refresh on every call; we prime the cache, then kill
	// the server and confirm the stale-but-cached key is still served.
	c := NewJWKSClient(srv.URL, WithMaxAge(0))
	if _, err := c.KeyByID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	srv.Close() // server now unreachable

	got, err := c.KeyByID(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("fail-open expected to serve cached key, got error: %v", err)
	}
	if got.X.Cmp(k.PublicKey.X) != 0 {
		t.Error("fail-open returned wrong key")
	}
}

func TestJWKS_FailClosedBeyondFailOpenTTL(t *testing.T) {
	k := newKey(t)
	srv, _ := jwksServer(t, map[string]*ecdsa.PublicKey{"kid-1": &k.PublicKey})

	// maxAge=0 forces a refresh every call; a tiny failOpenTTL means that once
	// the server is unreachable and the cache ages past it, we fail closed.
	c := NewJWKSClient(srv.URL, WithMaxAge(0), WithFailOpenTTL(5*time.Millisecond))
	if _, err := c.KeyByID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	srv.Close()
	time.Sleep(10 * time.Millisecond) // age past failOpenTTL

	if _, err := c.KeyByID(context.Background(), "kid-1"); err == nil {
		t.Error("expected fail-closed once cache aged beyond fail-open TTL")
	}
}

func TestJWKS_StaleTriggersRefetch(t *testing.T) {
	k := newKey(t)
	srv, hits := jwksServer(t, map[string]*ecdsa.PublicKey{"kid-1": &k.PublicKey})

	c := NewJWKSClient(srv.URL, WithMaxAge(10*time.Millisecond))
	if _, err := c.KeyByID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // let the cache go stale
	if _, err := c.KeyByID(context.Background(), "kid-1"); err != nil {
		t.Fatalf("second: %v", err)
	}
	if h := atomic.LoadInt32(hits); h < 2 {
		t.Errorf("expected refetch after staleness, got %d fetches", h)
	}
}

func TestJWKS_RejectsNonEC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"r1","n":"x","e":"AQAB"}]}`))
	}))
	t.Cleanup(srv.Close)
	c := NewJWKSClient(srv.URL)
	if _, err := c.KeyByID(context.Background(), "r1"); err == nil {
		t.Error("expected error: RSA key is not a usable ES256 key")
	}
}
