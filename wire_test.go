package license

import (
	"encoding/json"
	"testing"
)

// Pin the wire field names — these bytes are the cross-repo contract.
func TestWire_TokenResponseJSON(t *testing.T) {
	b, _ := json.Marshal(TokenResponse{Token: "jwt", TokenType: "license-jwt", ExpiresAt: 123})
	got := string(b)
	want := `{"token":"jwt","token_type":"license-jwt","expires_at":123}`
	if got != want {
		t.Errorf("TokenResponse JSON = %s, want %s", got, want)
	}
}

func TestWire_SelfEnrollJSON(t *testing.T) {
	var req SelfEnrollRequest
	if err := json.Unmarshal([]byte(`{"register_usage_signature":"sig"}`), &req); err != nil || req.RegisterUsageSignature != "sig" {
		t.Fatalf("SelfEnrollRequest decode: %+v err=%v", req, err)
	}
	b, _ := json.Marshal(SelfEnrollResponse{Status: EnrollStatusPending, CustomerID: "cust_1", APIKey: "bk_a_b", Message: "save it"})
	want := `{"status":"pending","customer_id":"cust_1","api_key":"bk_a_b","message":"save it"}`
	if string(b) != want {
		t.Errorf("SelfEnrollResponse JSON = %s, want %s", b, want)
	}
	// Re-enroll: omitempty drops the empty key/customer fields.
	b2, _ := json.Marshal(SelfEnrollResponse{Status: EnrollStatusAlreadyEnrolled})
	if string(b2) != `{"status":"already_enrolled"}` {
		t.Errorf("already_enrolled JSON = %s", b2)
	}
}

func TestWire_Constants(t *testing.T) {
	if APIKeyPrefix != "bk" || PathToken != "/token" || PathSelfEnroll != "/aws/self-enroll" || PathJWKS != "/.well-known/jwks.json" {
		t.Error("wire constants drifted")
	}
}
