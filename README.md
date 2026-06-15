# license-go

Public, dependency-light Go module for verifying Burnside license tokens
**offline** (SPEC-001). Import it in your SaaS deployment to verify an ES256
license JWT against Burnside's JWKS.

```
go get github.com/burnsideproject/license-go
```

The only runtime dependency (added in TICKET-005/007) is `golang-jwt/jwt/v5`.
It deliberately does **not** import `aws-sdk-go-v2`.

## Verifier contract (security-critical)
- Pin `alg=ES256` (reject `none`/alg-confusion).
- Require `exp` (~60s leeway); reject far-future `iat`.
- Validate `iss`, `aud=burnside-saas`, and a **required** deployment-pinned `sub`.
- Fail-open within token validity when JWKS is unreachable; fail closed at `exp`.

See `specs/.../SPEC-001` for the full spec.
