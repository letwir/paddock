# PADDOCK Bootstrap Trust and Safety Boundary

> **Status:** DESIGN_BASELINE for `PDK-M00-S06`; proposed design boundary only.
> **Not:** an operational runbook, key material, or authorization to connect to a database or change production systems.
> **Open decisions:** O-002 and O-010 remain OPEN for their owning Issues. O-003's PoC configuration is resolved per `PDK-M02-S05`; clean-empty-database apply remains unverified.

## BS-00. Reading rules

| ID | Subject / scope | Modality | Condition | Rule / outcome |
|---|---|---|---|---|
| BS-00.1 | This document | Status | Always | It defines boundaries and fail-closed expectations only. It does not resolve remaining OPEN decisions, create credentials, enable enrollment, access a database, or establish implementation safety. |
| BS-00.2 | Approval / authorization | MUST_NOT | Always | Do not interpret this design baseline as authorization to access a database, change production systems, or perform any other operation. |

## BS-01. Bootstrap trust root and PoC key scope

| ID | Subject / scope | Modality | Condition | Rule / outcome |
|---|---|---|---|---|
| BS-01.1 | Bootstrap trust | Baseline | At bootstrap | Trust begins with human-reviewed source in the PADDOCK repository and a locally invoked verifier. Record the verifier command, target tree, exit status, and file hashes. |
| BS-01.2 | Local verification evidence | Limitation | Local result | A local result is not CI attestation or proof of an independent identity. |
| BS-01.3 | PoC approval keys | MUST | PoC | Keys are disposable test fixtures, generated only inside an isolated test environment, never reused as production trust anchors, and never committed as private key material. |
| BS-01.4 | Test key fixtures | MAY | Tests | Tests may contain public fixture keys and deterministic signing fixtures only when they cannot authorize live systems. |
| BS-01.5 | Trust-root creation or rotation | MUST_NOT | Any worker, proposal, artifact, test fixture, or self-reported receipt | None can create or rotate a trust root. |
| BS-01.6 | Production trust-anchor lifecycle | OPEN | O-002 (`PDK-M06-S08`) | Production trust-anchor custody, key ceremony, rotation, revocation, and approval quorum remain OPEN. |
| BS-01.7 | Document tests | Condition | Document tests | No credential, private key, secret DSN, or live system authority is needed. Secret values must not appear in source, logs, receipts, or test output. |

## BS-02. Database setup boundary (O-003)

| ID | Subject / scope | Modality | Condition | Rule / outcome |
|---|---|---|---|---|
| BS-02.1 | Database tests | MUST | When later authorized by their dependency gates | Use a dedicated disposable test database with non-production data and least-privilege test roles. Never point tests or migrations at production. |
| BS-02.2 | Endpoint / DSN | MUST | Database use | Supply the test database endpoint/DSN outside tracked files and mask it from logs. |
| BS-02.3 | Missing or ambiguous target, credentials, or environment | STOP | Any is missing or ambiguous | Skip/block—not fallback to a default or production database. |
| BS-02.4 | O-003 PoC observation | As-of observation | `PDK-M02-S05` evidence, 2026-10-13 | The observed Test DB was PostgreSQL 18.6; the canonical operator-injected variable is `PADDOCK_DB_URL`; the psql-native guarded runner provides read-only `--check` and explicit `--apply`; there is no automated drop/recreate path; and populated `raw` is refused. This PoC configuration is resolved per its owning Issue, not a general PostgreSQL compatibility or policy promise. |
| BS-02.5 | `init.sql` | Unverified | Clean empty DB | Applying `init.sql` to a clean empty DB remains unverified. |
| BS-02.6 | Populated-target failure | MUST_NOT infer | Captured failure on a populated target | The failure does not imply reset or rollback. |
| BS-02.7 | Database operation | MUST_NOT | Always | This document grants no DB access or migration authorization. |

## BS-03. Emergency Stop lifecycle (O-010)

### BS-03.1 Trigger

- **Condition:** An authenticated human Safety Plane operator requests stop.
- **Rule:** Agents, workers, policy candidates, and ordinary approvals cannot trigger on behalf of the human or veto it.
- **OPEN:** Exact authentication factor and operator quorum remain OPEN.

### BS-03.2 Enforcement

- **Rule:** Stop intent is monotonic and fail-closed.
- **While stopped:** The gateway denies new high-risk side effects, grants/leases, enrollment promotion, and policy activation.
- **Authority state unavailable:** Local deny-all applies.
- **DB available:** Persist the stop and advance the global security epoch once per accepted stop transition.
- **Recovery:** Reconcile durable state before resuming.

### BS-03.3 Safe Baseline

- **Definition:** An embedded, non-distributed deny-all policy independent of ordinary bundles, signatures, LKG validity, and database availability.
- **Allowed operations:** Permit only narrowly defined diagnostic/recovery operations through a separate human-authorized path; ordinary worker credentials do not qualify.
- **Status:** Safe Baseline is a safety state, not normal service availability.

### BS-03.4 Release

- **MUST_NOT release on:** elapsed time, rollback success, agent action, or restored connectivity.
- **Release condition:** A separately authenticated human action, independent approval as eventually specified, valid current trust configuration, and a new activation are required.
- **OPEN under O-010 (`PDK-M06-S05`):** Authentication method, quorum, key custody/rotation, and recovery authority remain OPEN.

### BS-03.5 Limits

- A disconnected endpoint cannot be physically stopped by this design.
- Already completed external effects cannot be undone.
- If the enforcing gateway itself is compromised, this design does not claim protection.

## BS-04. Explicit unresolved decisions and links

| Open item | Status / remaining limitation | Owning Issue |
|---|---|---|
| O-002 | OPEN: Production trust-anchor custody, ceremony, rotation, revocation, quorum | `PDK-M06-S08` |
| O-003 | PoC configuration resolved per `PDK-M02-S05`; clean-empty-database `init.sql` apply remains unverified | `PDK-M02-S05` |
| O-010 | OPEN: Human authentication factors/quorum, emergency key custody and recovery | `PDK-M06-S05` |

This baseline defines boundaries and fail-closed expectations only. It does not resolve the remaining OPEN decisions, create credentials, enable enrollment, access a database, or establish implementation safety.
