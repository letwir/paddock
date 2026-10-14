# Canonical signing input · S07

## Record: implementation contract (documented claims)

- **Codec:** `internal/canonical.NewJCSCodec()` constructs the production RFC 8785 codec backed by `github.com/deszhou/jcs` **v1.1.0**, Apache-2.0. It returns concrete `*JCSCodec`; `Envelope` accepts only that type, preventing arbitrary codec or identity injection. Nil fails closed. There is no package-global default or identity fallback.
- **Bytes:** Canonicalized payload is bound into a second canonical object (the envelope) containing `domain`, `schema_version`, `audience`, `request_id`, and `nonce`.
- **Caller duties:** Callers remain responsible for nonce uniqueness, expiry, authorization, and durable replay tracking; canonicalization/envelope construction does not supply these controls.
- **Pre-dependency validation:** Before calling the dependency, integration validates UTF-8 and rejects duplicate object names (including names equivalent after escape decoding), unpaired surrogate escapes, and integral numeric values outside the IEEE-754 safe-integer interval.
- **Dependency boundary:** The dependency API is `jcs.Transform([]byte) ([]byte, error)`; it is not modified. Its serializer supplies UTF-16 property ordering, escaping, and ECMAScript-compatible number serialization.

## Record: coverage and limits

Conformance tests use fixed canonical-byte vectors for key order, Unicode, escaping, numeric thresholds/rounding, malformed input, duplicate keys, surrogates, and unsafe integers. The Issue evidence additionally describes negative zero and table-driven Ed25519 rejection checks across Bundle→Approval, Bundle→Command, and Approval→Command; only one direction per unordered domain pair is tested.

These are package/integration behavior checks, **not an independent cryptographic audit** and not exhaustive RFC Appendix B coverage. Neither tests nor this guide claim complete verification of the RFC or cryptographic correctness.

## Record: verification and portability

The implementation/test evidence recorded by `Issues.md` for `PDK-M06-S07` (`receipts/PDK-M06-S07/2026-10-14-jcs-tests.json`) states:

- `go test ./internal/canonical -count=1`
- `go test ./...`
- `go vet ./...`
- `./scripts/check-canonical-portability.sh` (script cross-compiles the canonical package with CGO disabled for Windows/arm64, Linux/arm64, and Android/arm64).

The receipt claims Go tests, vet, integration-tag **compile-only** check, and portability compile passed; no DB integration or target-OS runtime is claimed. Cross-compilation establishes compile portability only, not execution on Windows, Linux, or Android. These are statements recorded by the Issue/receipt, not checks independently run by this documentation edit.

## Record: status and evidence boundary

Status is unresolved in the source records and must not be silently reconciled here: `decisions.md` D-015 says implementation remains unconfirmed until the S07 verifier, while `Issues.md` marks `PDK-M06-S07` `[*] TESTED` and records test, vet, compile, portability, and separate-verifier evidence claims. Authoritative reconciliation requires checking the applicable receipt and source/revision; this guide does not assert that reconciliation, independently validate the receipt, or invent an outcome. The cited evidence is local-only; no CI attestation is claimed. Issue notes also say the worktree is dirty and the tested source is not committed.

## Record: third-party provenance and redistribution

For the consolidated dependency license inventory or `THIRD_PARTY_NOTICES`, record:

- **Module/version:** `github.com/deszhou/jcs` `v1.1.0`
- **Upstream:** <https://github.com/deszhou/jcs>
- **License:** Apache License 2.0
- **Role:** RFC 8785 JCS transformation used by `internal/canonical.JCSCodec`.

Retain the upstream copyright/license notice and include applicable upstream `NOTICE` text when redistributing. This reminder does not replace shipping the license text/notices. Re-check the exact pinned module's license and NOTICE files if its version changes.
