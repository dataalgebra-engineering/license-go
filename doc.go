// Package license is the shared, dependency-light contract for Burnside
// license tokens (SPEC-001). It holds the claim structs and an offline
// Verifier that customer deployments use to validate ES256 license JWTs
// against a published JWKS — no AWS SDK, no network dependency beyond JWKS.
//
// Implemented across:
//   - TICKET-005  claims (LicenseClaims, plan codes, iss/aud constants)
//   - TICKET-006  JWKS client (cache, rotation, fail-open)
//   - TICKET-007  Verifier (alg pin, exp/iss/aud + required sub pin)
package license
