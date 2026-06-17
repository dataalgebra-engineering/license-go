package license

// Wire contract for the Burnside licensing HTTP surface (SPEC-006). These are
// the request/response DTOs and constants shared by the key service
// (aws-marketplace-keys, the producer) and consumers (e.g. pg-cdc), so the
// contract has one definition and drift is a compile error rather than a
// runtime JSON-decode failure. Plain structs only — no new dependencies; secret
// handling (API-key hashing, pepper) deliberately stays server-side.

// Endpoint paths.
const (
	PathToken      = "/token"                 // POST: refresh a license token (Bearer API key)
	PathSelfEnroll = "/aws/self-enroll"       // POST: container self-enroll (SigV4/AWS_IAM)
	PathJWKS       = "/.well-known/jwks.json" // GET: published verification keys
)

// APIKeyPrefix marks a Burnside license API key: APIKeyPrefix_<key_id>_<secret>.
const APIKeyPrefix = "bk"

// Enrollment status values returned by PathSelfEnroll.
const (
	EnrollStatusPending         = "pending"
	EnrollStatusAlreadyEnrolled = "already_enrolled"
)

// TokenResponse is the PathToken success body: a freshly-issued license JWT.
type TokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresAt int64  `json:"expires_at"` // token exp, Unix seconds
}

// SelfEnrollRequest is the PathSelfEnroll request body: the AWS Marketplace
// RegisterUsage signature proving an entitled instance is running.
type SelfEnrollRequest struct {
	RegisterUsageSignature string `json:"register_usage_signature"`
}

// SelfEnrollResponse is the PathSelfEnroll response. On first enroll Status is
// EnrollStatusPending and APIKey carries the (once-shown) key; on re-enroll
// Status is EnrollStatusAlreadyEnrolled and APIKey is empty.
type SelfEnrollResponse struct {
	Status     string `json:"status"`
	CustomerID string `json:"customer_id,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
	Message    string `json:"message,omitempty"`
}
