package license_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	license "github.com/dataalgebra-engineering/license-go"
	"github.com/golang-jwt/jwt/v5"
)

// Example_verify shows the full customer-side flow: point a JWKS client at the
// Burnside JWKS, pin the deployment's own customer_id, and verify a token
// offline. (Key generation + signing here stand in for the Burnside backend.)
func Example_verify() {
	// --- stands in for the Burnside backend / KMS signing key ---
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const kid = "2026-key-1"

	jwks := mustJWKS(map[string]*ecdsa.PublicKey{kid: &key.PublicKey})
	defer jwks.Close()

	now := time.Now()
	claims := license.LicenseClaims{
		Plan: license.PlanPro, Channel: license.ChannelAWS,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: license.Issuer, Subject: "cust_42",
			Audience:  jwt.ClaimStrings{license.Audience},
			ID:        "jti_demo",
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(72 * time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	signed, _ := tok.SignedString(key)

	// --- customer deployment: verify offline ---
	v, err := license.NewVerifier(license.NewJWKSClient(jwks.URL), "cust_42")
	if err != nil {
		fmt.Println("verifier:", err)
		return
	}
	got, err := v.Verify(context.Background(), signed)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}
	fmt.Printf("licensed: sub=%s plan=%s\n", got.Subject, got.Plan)
	// Output: licensed: sub=cust_42 plan=pro
}

// mustJWKS serves a JWKS for the example (mirrors the test helper, kept here so
// the example is self-contained godoc).
func mustJWKS(keys map[string]*ecdsa.PublicKey) *httptest.Server {
	type jwk struct {
		Kty, Crv, Kid, X, Y, Alg, Use string
	}
	pad := func(b []byte) string {
		const n = 32
		if len(b) < n {
			p := make([]byte, n)
			copy(p[n-len(b):], b)
			b = p
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	list := make([]map[string]string, 0, len(keys))
	for kid, pub := range keys {
		list = append(list, map[string]string{
			"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
			"x": pad(pub.X.Bytes()), "y": pad(pub.Y.Bytes()),
		})
	}
	body, _ := json.Marshal(map[string]any{"keys": list})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
}
