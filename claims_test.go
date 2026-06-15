package license

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestConstants(t *testing.T) {
	if Issuer != "https://license.burnsideproject.ai" {
		t.Errorf("Issuer = %q", Issuer)
	}
	if Audience != "burnside-saas" {
		t.Errorf("Audience = %q", Audience)
	}
}

func sampleClaims() LicenseClaims {
	iat := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	return LicenseClaims{
		Plan:    PlanPro,
		Channel: ChannelAWS,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "cust_0a1b2c",
			Audience:  jwt.ClaimStrings{Audience},
			ID:        "jti_abc123",
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(iat.Add(72 * time.Hour)),
		},
	}
}

func TestLicenseClaims_RoundTrip(t *testing.T) {
	in := sampleClaims()

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out LicenseClaims
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Plan != in.Plan {
		t.Errorf("plan: got %q want %q", out.Plan, in.Plan)
	}
	if out.Channel != in.Channel {
		t.Errorf("channel: got %q want %q", out.Channel, in.Channel)
	}
	if out.Subject != in.Subject {
		t.Errorf("sub: got %q want %q", out.Subject, in.Subject)
	}
	if out.ID != in.ID {
		t.Errorf("jti: got %q want %q", out.ID, in.ID)
	}
	if !out.ExpiresAt.Equal(in.ExpiresAt.Time) {
		t.Errorf("exp: got %v want %v", out.ExpiresAt, in.ExpiresAt)
	}
}

// TestLicenseClaims_JSONShape locks the wire shape so the contract cannot
// silently drift between issuer and verifier.
func TestLicenseClaims_JSONShape(t *testing.T) {
	b, err := json.Marshal(sampleClaims())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	for _, key := range []string{"iss", "aud", "sub", "jti", "iat", "exp", "plan", "channel"} {
		if _, ok := m[key]; !ok {
			t.Errorf("expected claim %q in JSON, got keys %v", key, keys(m))
		}
	}
}

// TestClaimsInterface confirms golang-jwt's accessors read the embedded claims.
func TestClaimsInterface(t *testing.T) {
	c := sampleClaims()

	iss, err := c.GetIssuer()
	if err != nil || iss != Issuer {
		t.Errorf("GetIssuer = %q, %v", iss, err)
	}
	aud, err := c.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != Audience {
		t.Errorf("GetAudience = %v, %v", aud, err)
	}
	exp, err := c.GetExpirationTime()
	if err != nil || exp == nil {
		t.Errorf("GetExpirationTime = %v, %v", exp, err)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
