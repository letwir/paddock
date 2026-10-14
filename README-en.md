# PADDOCK — English edition

> SIGMA/1: PIDGEN/text · Snapshot: 2026-10-12 · Revision: design-review/2

PADDOCK is an independent project for fully autonomous WorkOrder execution, distributed Trust, and self-improving Governance.

This is a human-readable presentation parallel to [README-forLLM.md](README-forLLM.md) and [README-ja.md](README-ja.md). They present the same historical PADDOCK snapshot and are not authority sources. The historical identifier is `snapshot_2026-10-12`, revision `design-review/2`; it does not state the repository's present status. Decisions, Issues, method, and rules are authoritative and supersede this overview.

## Historical snapshot and boundaries

At that snapshot PADDOCK was labeled `MAIN_DESIGN / DESIGN_ONLY`: no Go implementation, DB migration, real-device verification, or new GitHub repository had been performed. The count D-001 through D-014 (14 decisions) applies only as of that snapshot. D-015 through D-017 are later records and do not rewrite the old count or claims. This historical presentation makes no claim about later implementation status; consult authoritative Git state, `Issues.md`, and verification receipts for current status.

Emergency Stop, built-in Safe Baseline, Root-specific Epoch, Canary deadlines, and CI Receipt were described as DESIGN_BASELINE, not as changes to the snapshot's 14 ACCEPTED decisions and not as proof that Issues were complete. The snapshot's initial Cursor was `PDK-M00-S01` document validation; its next safety design gates were `PDK-M00-S05` (Threat Model) and `PDK-M00-S06` (Bootstrap/emergency-stop boundary). Those are dated historical statements only. The snapshot did not authorize changes to existing HARNESS, GitHub repository creation or push, DB access, or credential operations.

Existing [`.HARNESS`](https://github.com/letwir/config/tree/main/.HARNESS) is reference material only. PADDOCK does not implicitly inherit its execution rules, credentials, or permissions.

PADDOCK must remain an independent repository and must not be placed under `.HARNESS`. Only useful Handoff notation and Issue-state management practices were referenced; `.HARNESS` rules, credentials, and permissions were not inherited.

## Source of truth and derived documents

| File | Role / historical description |
|---|---|
| [AGENTS.md](AGENTS.md) | Newly added at this snapshot: agent bootstrap; reads SIGMA from `rules/BOOTSTRAP.lrf`; independent PADDOCK rules informed by the `.HARNESS` approach. |
| [rules/](rules/) and [rules/BOOTSTRAP.lrf](rules/BOOTSTRAP.lrf) | Newly added at this snapshot: LRF/1 design and execution rules; `.HARNESS` LRF is not loaded. |
| [decisions.md](decisions.md) | At snapshot: ACCEPTED D-001..D-014 (14 only as of then), Design Baseline, OPEN O-001..O-010; conversation transcription, human-signed Git approval incomplete. |
| [Issues.md](Issues.md) | At snapshot: 16 medium-goal areas and 89 small goals, stable IDs, dependencies, evidence, Cursor. Consult each issue for present status; the snapshot described local verification as in progress. |
| [method.md](method.md) | `SIGMA/1: PIDGEN/text`, `CONTINUE/1`, verification Receipt and restart contract; then described as a design proposal. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Safety Plane, Sybil, prompt injection, supply chain, DoS; then described as unreviewed/unverified. |
| [docs/bootstrap-safety.md](docs/bootstrap-safety.md) | PoC trust root, DB boundary, Emergency Stop/Safe Baseline DESIGN_BASELINE; S06 proposal, operational values OPEN. |
| [docs/issue-dependencies.generated.md](docs/issue-dependencies.generated.md) | Machine-generated dependency table; derived and must not be hand-edited. |
| [scripts/lint_design.py](scripts/lint_design.py) | Static checks for IDs, DAG, OPEN resolution, Markdown references, Cursor; local document check. |

The generated dependency index derives from small-goal `depends_on`; it is not a medium-goal dependency DAG. Decisions/Issues/method/rules supersede this overview.

## Worker startup and continuation

1. Confirm the repository root; do not accidentally write to `.HARNESS` or its parent repository.
2. Read `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`.
3. Run `python3 scripts/lint_design.py` to check IDs, the small-goal DAG, and OPEN resolution targets.
4. Reconcile the Durable Cursor in `Issues.md` with the real Git diff and CI/verification receipts. Cursor is a hint, not a substitute for actual state.
5. Choose one small goal with satisfied dependencies and permissions. State sequence: `[-] WIP` before work, `[~]` after implementation, `[*]` after an observed local check, `[x]` only after independent local verification and acceptance criteria. At the time of this source README, the then-current user direction did not require CI/remote attestation for completion. This is a historical statement about that source README, not current/general policy or present authorization.
6. If communication is lost, instruct `continue`. Resolve an uncertain DB commit with the same Command ID; do not rerun under a different ID.

### Exact recommended checks

```sh
python3 scripts/lint_design.py
python3 scripts/lint_design.py --emit-summary
```

Uses Python standard library only. These checks validate document structure; they do not prove Go or DB behavior or safety. The generated `docs/issue-dependencies.generated.md` derives from `Issues.md` and does not describe dependencies between medium goals.

## Exact SIGMA/1 handoff example

```text
<Γ>
SIGMA/1: PIDGEN/text
Role: Worker / design-review
Target: PDK-M00-S05; review THREAT_MODEL.md and map risks to stable Issues
Acceptance: Every threat has an Issue, acceptance and remaining risk; do not claim tests ran
Scope: THREAT_MODEL.md and Issues.md (repository-relative); no .HARNESS edits, no VCS push, no live DB/credential access
Known facts: D-001..D-014 imported conversation decisions; Emergency Stop and Safe Baseline are DESIGN_BASELINE; source=decisions.md
SIGMA/1
</Γ>
```

The field order and facts are part of this historical example. The Envelope is an instruction format, not authorization. Do not include unverified facts in `Known facts`.

## PoC outline (not implemented in the snapshot)

Go Contract First + pgx Native + one PostgreSQL instance + two Coordinator processes + two Worker Simulators + Root A/B. Policy v1 → Canary v2 for Root B only → global promotion → fault injection → rollback to verified LKG (built-in Safe Baseline if invalid).

- Epoch design baseline distinguishes Scope Activation, Root Authorization, and Security; Root A's old credential should not be improperly revoked during Root B's canary.
- Safety priorities: human Break-glass, Gateway fail-closed, pre-authorized rollback, deadline termination of HOLD/MONITORING.
- Verification outline: finite model checking, DDL/DB contention, commit-unknown behavior, CI observation of Receipts. LLM explanations and dummy signatures are not passing evidence.

This outline does not prove components exist or tests ran. Current status must be determined from authoritative records and actual evidence.

## Authoritative references

[decisions.md](decisions.md) · [Issues.md](Issues.md) · [method.md](method.md) · [rules/](rules/) · [THREAT_MODEL.md](THREAT_MODEL.md)
