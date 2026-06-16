# Runbook: Releasing license-go

Audience: maintainers cutting a new version of the verifier library.

## Versioning (semver, pre-1.0)
- **Patch** (`v0.x.Y`) — bug fix, no API change.
- **Minor** (`v0.Y.0`) — new exported API or a default-behavior change
  (e.g. v0.2.0 added `WithFailOpenTTL` + bounded fail-open).
- A **module-path change** starts a fresh tag line (e.g. v0.3.0 = first tag at
  `github.com/dataalgebra-engineering/license-go`). Pre-1.0 needs no `/vN` suffix.

## Cut a release
```bash
# 0. main is green
make test-docker            # go vet + go test -race -cover + go build

# 1. tag (annotated) on the release commit
git tag -a vX.Y.Z -m "vX.Y.Z — <summary>"
git push origin vX.Y.Z

# 2. confirm
git ls-remote --tags origin
```

## After a release
- Update the consumer (`aws-marketplace-keys`): its `go.mod` uses a local
  `replace => ../license-go`, so in-workspace builds need no bump; for a
  standalone build, `go get github.com/dataalgebra-engineering/license-go@vX.Y.Z`.
- Update this repo's `docs/` if behavior/API changed (do it in the same PR).
- Record the release in the workspace delivery ledger + `knowledge/`.

## Private-module consumers
The repo is private — consumers need `GOPRIVATE=github.com/dataalgebra-engineering/*`
and read access (see `docs/integration.md`). If external customers must `go get`
directly, decide on making the repo public or vendoring.

## Tag history
| Tag | Notes |
|---|---|
| v0.1.0 / v0.1.1 | SPEC-001 era (old `burnsideproject` path; +PlanEnterprise at v0.1.1) |
| v0.2.0 | SPEC-002: bounded JWKS fail-open (old path) |
| v0.3.0 | SPEC-003: module renamed to `dataalgebra-engineering` (first tag at new path) |
