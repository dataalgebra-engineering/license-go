# Integration: Offline License Verification

For a **customer SaaS deployment** integrating Burnside license verification. Your
deployment verifies a signed license token **offline** (no per-request call to
Burnside) and refreshes it from `POST /token` when online.

## Install

```
go get github.com/dataalgebra-engineering/license-go@v0.3.0
```

Only dependency pulled: `golang-jwt/jwt/v5` (no `aws-sdk-go-v2`).

> **Private module.** This repo is private, so `go get` needs repo access plus:
> ```
> export GOPRIVATE=github.com/dataalgebra-engineering/*
> # auth: git config --global url."git@github.com:".insteadOf "https://github.com/"
> #   or a ~/.netrc token with read access
> ```
> Use `v0.3.0`+ (first tag at this module path; v0.1.x/v0.2.0 carry the old
> `burnsideproject` path).

## Configuration you receive

| Item | Source |
|---|---|
| **API key** `bk_<key_id>_<secret>` | shown once at registration + emailed (one-time link) |
| **JWKS URL** | `https://license.burnsideproject.ai/.well-known/jwks.json` |
| **Your `customer_id`** | returned at registration; pin it as the expected `sub` |

## Verify a token offline

```go
import (
    "context"
    "time"

    license "github.com/dataalgebra-engineering/license-go"
)

// Build once at startup. expectedSub (YOUR customer_id) is REQUIRED — a token
// minted for another customer is rejected.
jwks := license.NewJWKSClient(jwksURL, license.WithMaxAge(6*time.Hour))
verifier, err := license.NewVerifier(jwks, myCustomerID)
if err != nil { /* fatal config error */ }

claims, err := verifier.Verify(ctx, cachedToken)
if err != nil {
    // not licensed right now — deny the gated feature (and try a refresh if online)
}
```

## JWKS caching & fail-open (v0.2.0+)

The `JWKSClient` serves a fresh cached key, refreshes on an unknown `kid` or when
stale (`WithMaxAge`, default 1h), and is **fail-open within a bounded window**: if
a refresh fails it keeps serving the cached key — but only up to `failOpenTTL`
(`WithFailOpenTTL`, default **24h** since the last successful fetch). Past that it
**fails closed**, so a revoked/compromised key is not trusted indefinitely.

## What the verifier enforces

`alg=ES256` (rejects `none`/HS256 alg-confusion), `iss`, `aud`, `exp` (60s default
leeway), rejects future `iat`, and pins `sub` to your `customer_id`.

See the workspace integration guide for the full refresh/online flow.
