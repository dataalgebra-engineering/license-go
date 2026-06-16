// Command consumer is a minimal example of how a customer's SaaS deployment
// integrates the license verifier (SPEC-001 TICKET-008). It builds against the
// public module exactly as a customer would after `go get`.
//
// Configuration a real deployment supplies:
//   - JWKS_URL:    https://license.burnsideproject.ai/.well-known/jwks.json
//   - CUSTOMER_ID: the deployment's own customer_id (pinned as the token sub)
//   - the cached license token (refreshed from POST /token when online)
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	license "github.com/dataalgebra-engineering/license-go"
)

func main() {
	jwksURL := getenv("JWKS_URL", "https://license.burnsideproject.ai/.well-known/jwks.json")
	customerID := getenv("CUSTOMER_ID", "cust_example")
	token := os.Getenv("LICENSE_TOKEN")

	verifier, err := license.NewVerifier(
		license.NewJWKSClient(jwksURL, license.WithMaxAge(6*time.Hour)),
		customerID,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}

	if token == "" {
		// No token to check (e.g. first boot before refresh) — the integration
		// compiles and the verifier is wired correctly.
		fmt.Println("license verifier configured for", customerID)
		return
	}

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "license invalid:", err)
		os.Exit(1)
	}
	fmt.Printf("license OK: plan=%s expires=%s\n", claims.Plan, claims.ExpiresAt)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
