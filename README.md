# license-go

Dependency-light Go module for verifying Burnside license tokens **offline**
(SPEC-001). Import it in your SaaS deployment to verify an ES256 license JWT
against Burnside's JWKS.

```
go get github.com/dataalgebra-engineering/license-go@v0.3.0
```

The only runtime dependency is `golang-jwt/jwt/v5`; it deliberately does **not**
import `aws-sdk-go-v2`.

> This repo is **private** — `go get` needs `GOPRIVATE=github.com/dataalgebra-engineering/*`
> plus read access. See [`docs/integration.md`](docs/integration.md).

## Verifier contract (security-critical)
- Pin `alg=ES256` (reject `none`/alg-confusion).
- Require `exp` (~60s leeway); reject far-future `iat`.
- Validate `iss`, `aud=burnside-saas`, and a **required** deployment-pinned `sub`.
- JWKS fail-open is **bounded** (`WithFailOpenTTL`, default 24h since last
  successful fetch), then fails closed; tokens still fail closed at `exp`.

## Docs
- [`docs/integration.md`](docs/integration.md) — consumer integration guide.
- [`docs/runbooks/release.md`](docs/runbooks/release.md) — cutting a new version.

Delivery/process artifacts (spec, tickets, verification) live in the workspace
repo; see SPEC-001/002/003.
