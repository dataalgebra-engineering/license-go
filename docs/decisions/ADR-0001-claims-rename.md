# ADR-0001 — Rename `LicenseClaims` → `Claims` (with deprecated alias)

- Status: Accepted (2026-06-23)
- Context: SPEC-008 / TICKET-062

## Context
`golangci-lint` (revive) flags the exported type `license.LicenseClaims` as
stuttering — it should be `Claims`. It is a **public** type on the shared wire
contract. The only current importer is `aws-marketplace-keys` (via a local
`replace`), and it uses the name in one non-test site plus tests; `pg-cdc` does not
import it.

## Decision
Rename the type to `Claims` and keep `type LicenseClaims = Claims` as a
**deprecated back-compat alias** (`//nolint:revive`, `// Deprecated: use Claims`).

- Lint passes (canonical name is `Claims`).
- **Non-breaking**: existing importers (and any pinned consumer) keep compiling on
  `LicenseClaims`.
- The alias is exercised by amk's build; `claims_test.go` also still references it.

## Consequences
- New code should use `Claims`.
- The alias will be removed in the next **major** version; consumers should migrate
  before then.
- Versioning: ship as a license-go **minor** bump (additive, non-breaking).
