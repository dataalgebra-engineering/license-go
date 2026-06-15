package license

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSub = "cust_0a1b2c"

// signES256 signs claims with key under the given kid.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims LicenseClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// validClaims builds clock-relative, valid claims for testSub.
func validClaims() LicenseClaims {
	now := time.Now()
	return LicenseClaims{
		Plan: PlanPro, Channel: ChannelAWS,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: Issuer, Subject: testSub, Audience: jwt.ClaimStrings{Audience},
			ID:        "jti_1",
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
}

func newVerifier(t *testing.T, key *ecdsa.PrivateKey, kid, sub string) *Verifier {
	t.Helper()
	srv, _ := jwksServer(t, map[string]*ecdsa.PublicKey{kid: &key.PublicKey})
	v, err := NewVerifier(NewJWKSClient(srv.URL), sub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerify_Valid(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, key, "kid-1", testSub)
	tok := signES256(t, key, "kid-1", validClaims())

	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != testSub || claims.Plan != PlanPro {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestNewVerifier_RequiresSubAndKeys(t *testing.T) {
	if _, err := NewVerifier(NewJWKSClient("http://x"), ""); err == nil {
		t.Error("expected error for empty expectedSub")
	}
	if _, err := NewVerifier(nil, testSub); err == nil {
		t.Error("expected error for nil key source")
	}
}

func TestVerify_Rejections(t *testing.T) {
	key := newKey(t)

	t.Run("wrong sub (cross-tenant)", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", "cust_OTHER")
		tok := signES256(t, key, "kid-1", validClaims())
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Error("expected rejection: sub mismatch")
		}
	})

	t.Run("expired", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		c := validClaims()
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		if _, err := v.Verify(context.Background(), signES256(t, key, "kid-1", c)); err == nil {
			t.Error("expected rejection: expired")
		}
	})

	t.Run("missing exp", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		c := validClaims()
		c.ExpiresAt = nil
		if _, err := v.Verify(context.Background(), signES256(t, key, "kid-1", c)); err == nil {
			t.Error("expected rejection: exp required")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		c := validClaims()
		c.Issuer = "https://evil.example"
		if _, err := v.Verify(context.Background(), signES256(t, key, "kid-1", c)); err == nil {
			t.Error("expected rejection: issuer")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		c := validClaims()
		c.Audience = jwt.ClaimStrings{"someone-else"}
		if _, err := v.Verify(context.Background(), signES256(t, key, "kid-1", c)); err == nil {
			t.Error("expected rejection: audience")
		}
	})

	t.Run("future iat", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		c := validClaims()
		c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		if _, err := v.Verify(context.Background(), signES256(t, key, "kid-1", c)); err == nil {
			t.Error("expected rejection: future iat")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims())
		s, _ := tok.SignedString(key) // no kid header
		if _, err := v.Verify(context.Background(), s); err == nil {
			t.Error("expected rejection: missing kid")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
		tok.Header["kid"] = "kid-1"
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if _, err := v.Verify(context.Background(), s); err == nil {
			t.Error("expected rejection: alg=none")
		}
	})

	t.Run("alg confusion HS256", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
		tok.Header["kid"] = "kid-1"
		s, _ := tok.SignedString([]byte("secret"))
		if _, err := v.Verify(context.Background(), s); err == nil {
			t.Error("expected rejection: HS256 not allowed")
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		v := newVerifier(t, key, "kid-1", testSub)
		other := newKey(t)
		if _, err := v.Verify(context.Background(), signES256(t, other, "kid-1", validClaims())); err == nil {
			t.Error("expected rejection: signature from wrong key")
		}
	})
}
