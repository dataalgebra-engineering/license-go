package license

import "github.com/golang-jwt/jwt/v5"

// Issuer and Audience are the fixed identity values for every Burnside
// license token (SPEC-001). The verifier pins both.
const (
	Issuer   = "https://license.burnsideproject.ai"
	Audience = "burnside-saas"
)

// Channel identifies the sales channel a license originated from. It is
// informational (issuance topology) and not security-relevant — verifiers
// ignore it.
type Channel string

const (
	ChannelAWS    Channel = "aws"
	ChannelGCP    Channel = "gcp"    // future
	ChannelGitHub Channel = "github" // future
	ChannelStripe Channel = "stripe" // future
)

// Plan is a coarse entitlement tier. Plans are deliberately coarse — there
// are no per-feature scopes (SPEC-001 non-goals).
type Plan string

const (
	PlanStandard Plan = "standard"
	PlanPro      Plan = "pro"
)

// LicenseClaims is the shared JWT claim set for a Burnside license token and
// the single source of truth imported by both the issuer (backend) and the
// offline Verifier. The embedded jwt.RegisteredClaims carries the standard
// claims (iss, sub, aud, exp, iat, jti, nbf).
//
// Note: this contract depends only on golang-jwt/jwt — never aws-sdk-go-v2 —
// keeping the module dependency-light for customer import.
type LicenseClaims struct {
	Plan    Plan    `json:"plan"`
	Channel Channel `json:"channel"`

	jwt.RegisteredClaims
}

// Compile-time guarantee that LicenseClaims satisfies the jwt.Claims interface
// so it can be signed and verified by golang-jwt.
var _ jwt.Claims = (*LicenseClaims)(nil)
