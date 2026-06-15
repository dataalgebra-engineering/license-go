package license

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultLeeway absorbs minor clock skew on customer deployments.
const DefaultLeeway = 60 * time.Second

// keySource is the subset of JWKSClient the Verifier needs (also eases testing).
type keySource interface {
	KeyByID(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// Verifier validates Burnside license tokens **offline**. It pins:
//   - alg = ES256 (rejects "none" and alg-confusion);
//   - iss = Issuer, aud = Audience;
//   - exp present (with leeway), iat not implausibly future;
//   - sub = the deployment's own customer_id (REQUIRED) — so a token minted for
//     one customer cannot be replayed in another.
type Verifier struct {
	keys        keySource
	expectedSub string
	leeway      time.Duration
	parser      *jwt.Parser
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithVerifyLeeway overrides the clock-skew leeway (default 60s).
func WithVerifyLeeway(d time.Duration) VerifierOption { return func(v *Verifier) { v.leeway = d } }

// NewVerifier builds a Verifier. expectedSub is REQUIRED: it is the deployment's
// own customer_id, and verification fails for any other subject. Making it a
// required argument means tenancy pinning cannot be silently skipped.
func NewVerifier(keys keySource, expectedSub string, opts ...VerifierOption) (*Verifier, error) {
	if keys == nil {
		return nil, errors.New("license: nil key source")
	}
	if expectedSub == "" {
		return nil, errors.New("license: expectedSub is required (pin the deployment's customer_id)")
	}
	v := &Verifier{keys: keys, expectedSub: expectedSub, leeway: DefaultLeeway}
	for _, o := range opts {
		o(v)
	}
	v.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.leeway),
	)
	return v, nil
}

// Verify parses and validates tokenString, returning its claims if valid.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*LicenseClaims, error) {
	claims := &LicenseClaims{}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token missing kid header")
		}
		return v.keys.KeyByID(ctx, kid)
	}

	if _, err := v.parser.ParseWithClaims(tokenString, claims, keyFunc); err != nil {
		return nil, fmt.Errorf("license: verify: %w", err)
	}

	// Tenancy pin: sub must equal this deployment's customer_id.
	if claims.Subject != v.expectedSub {
		return nil, fmt.Errorf("license: subject %q does not match pinned customer_id", claims.Subject)
	}

	// Reject implausibly future-dated tokens (iat) beyond the leeway window.
	if iat := claims.IssuedAt; iat != nil && iat.Time.After(time.Now().Add(v.leeway)) {
		return nil, errors.New("license: token issued in the future")
	}

	return claims, nil
}
