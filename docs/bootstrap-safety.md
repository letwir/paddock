# PADDOCK Bootstrap Trust and Safety Boundary

> Design baseline for `PDK-M00-S06`. This is not an operational runbook, key material, or authorization to connect to a database or change production systems. O-002, O-003, and O-010 remain OPEN for their owning Issues.

## Bootstrap trust root and PoC key scope

- Bootstrap trust begins with human-reviewed source in the PADDOCK repository and a locally invoked verifier whose command, target tree, exit status, and file hashes are recorded. A local result is not CI attestation or proof of an independent identity.
- PoC approval keys are disposable test fixtures, generated only inside an isolated test environment, never reused as production trust anchors, and never committed as private key material. Tests may contain public fixture keys and deterministic signing fixtures only when they cannot authorize live systems.
- No worker, proposal, artifact, test fixture, or self-reported receipt can create or rotate a trust root. Production trust-anchor custody, key ceremony, rotation, revocation, and approval quorum remain OPEN under O-002 (`PDK-M06-S08`).
- No credential, private key, secret DSN, or live system authority is needed for document tests. Secret values must not appear in source, logs, receipts, or test output.

## Database setup boundary (O-003)

- Database tests, when later authorized by their dependency gates, must use a dedicated disposable test database with non-production data and least-privilege test roles. Never point tests or migrations at production.
- The test database endpoint/DSN must be supplied outside tracked files and masked from logs. Missing or ambiguous target, credentials, or environment means skip/block—not fallback to a default or production database.
- PostgreSQL version, DSN provisioning, migration runner, and test-environment lifecycle are intentionally undecided here; they remain OPEN for `PDK-M02-S05`.
- Migrations must be exercised against an explicitly identified disposable database and verified before any future environment can be considered. This document grants no DB access or migration authorization.

## Emergency Stop lifecycle (O-010)

1. **Trigger:** an authenticated human Safety Plane operator requests stop. Agents, workers, policy candidates, and ordinary approvals cannot trigger on behalf of the human or veto it. Exact authentication factor and operator quorum remain OPEN.
2. **Enforcement:** stop intent is monotonic and fail-closed. The gateway denies new high-risk side effects, grants/leases, enrollment promotion, and policy activation. If authority state is unavailable, local deny-all applies. When DB is available, persist the stop and advance the global security epoch once per accepted stop transition; on recovery reconcile durable state before resuming.
3. **Safe Baseline:** an embedded, non-distributed deny-all policy independent of ordinary bundles, signatures, LKG validity, and database availability. Permit only narrowly defined diagnostic/recovery operations through a separate human-authorized path; ordinary worker credentials do not qualify. Safe Baseline is a safety state, not normal service availability.
4. **Release:** elapsed time, rollback success, agent action, or restored connectivity cannot release stop. Release requires a separately authenticated human action, independent approval as eventually specified, valid current trust configuration, and a new activation. Authentication method, quorum, key custody/rotation, and recovery authority remain OPEN under O-010 (`PDK-M06-S05`).
5. **Limits:** a disconnected endpoint cannot be physically stopped by this design. Already completed external effects cannot be undone. If the enforcing gateway itself is compromised, this design does not claim protection.

## Explicit unresolved decisions and links

| Open item | Deliberately unresolved here | Owning Issue |
|---|---|---|
| O-002 | Production trust-anchor custody, ceremony, rotation, revocation, quorum | `PDK-M06-S08` |
| O-003 | PostgreSQL version, DSN provisioning, migration runner, environment lifecycle | `PDK-M02-S05` |
| O-010 | Human authentication factors/quorum, emergency key custody and recovery | `PDK-M06-S05` |

This baseline defines boundaries and fail-closed expectations only. It does not resolve the listed decisions, create credentials, enable enrollment, access a database, or establish implementation safety.
