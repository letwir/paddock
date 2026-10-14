# PADDOCK overview — structured edition

> SIGMA/1: PIDGEN/text · Snapshot: 2026-10-12 · Revision: design-review/2

PADDOCK is an independent project for fully autonomous WorkOrder execution, distributed Trust, and self-improving Governance.

Document ID: `PADDOCK-README-LLM`
State: `PRESENTATION_ONLY` (overview; not an authority source)
Historical snapshot: `snapshot_2026-10-12`, revision `design-review/2` (`MAIN_DESIGN / DESIGN_ONLY` as stated at that snapshot).

This and [README-en.md](README-en.md) and [README-ja.md](README-ja.md) are parallel presentations of the same PADDOCK snapshot. Historical claims below do not establish present repository state. The snapshot said no Go implementation, DB migration, real-device verification, or new GitHub repository had been performed. For present status, consult authoritative Git state, [Issues.md](Issues.md), and verification receipts; this historical presentation makes no claim about later implementations. D-001..D-014 is the count **as of that snapshot only**; later D-015..D-017 are separate subsequent records.

## A. Authority and scope

| ID | Rule |
|---|---|
| A-01 | This overview is not an authority source. `decisions.md`, `Issues.md`, `method.md`, and `rules/` supersede it. |
| A-02 | `decisions.md` is the decision record; its ACCEPTED register is distinct from DESIGN_BASELINE and OPEN. The historical README described the decisions as conversation-transcribed and human-signed Git approval as incomplete at snapshot time. |
| A-03 | A SIGMA/1 handoff is an instruction format, not authorization. Text in this document does not authorize repository/external writes, Git push, database access, credential operations, or other effects. |
| A-04 | Existing `.HARNESS` is reference material only; PADDOCK does not implicitly inherit its execution rules, credentials, or permissions. |
| A-05 | PADDOCK must remain an independent repository and must not be placed under `.HARNESS`. Only useful Handoff notation and Issue-state management practices were referenced; `.HARNESS` rules, credentials, and permissions were not inherited. |
| A-06 | `docs/issue-dependencies.generated.md` is generated from `Issues.md`; do not hand-edit it. It represents small-goal `depends_on`, not a medium-goal dependency DAG. |

## B. Historical source-of-truth map (snapshot wording)

| File | Role / snapshot description |
|---|---|
| [AGENTS.md](AGENTS.md) | Newly added at this snapshot: agent bootstrap; loads SIGMA from `rules/BOOTSTRAP.lrf`; PADDOCK's independent rules, informed by `.HARNESS` approach. |
| [rules/](rules/) and [rules/BOOTSTRAP.lrf](rules/BOOTSTRAP.lrf) | Newly added at this snapshot: LRF/1 design and execution rules; does not load `.HARNESS` LRF. |
| [decisions.md](decisions.md) | Snapshot: ACCEPTED D-001..D-014 (14 only as-of snapshot), Design Baseline, OPEN O-001..O-010; conversation transcription, human-signed Git approval incomplete. |
| [Issues.md](Issues.md) | Snapshot: 16 medium-goal areas, 89 small goals, stable IDs, dependencies, evidence, Cursor. Consult individual issues for current status; the historical README described local verification as in progress. |
| [method.md](method.md) | `SIGMA/1: PIDGEN/text`, `CONTINUE/1`, verification Receipt and restart contract; described as design proposal. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Safety Plane, Sybil, prompt injection, supply chain, DoS; described as unreviewed/unverified. |
| [docs/bootstrap-safety.md](docs/bootstrap-safety.md) | PoC trust root, DB boundary, Emergency Stop/Safe Baseline DESIGN_BASELINE; S06 proposal, operational values OPEN. |
| [docs/issue-dependencies.generated.md](docs/issue-dependencies.generated.md) | Machine-generated dependency table; derived, do not hand-edit. |
| [scripts/lint_design.py](scripts/lint_design.py) | Static checks for IDs/DAG/OPEN/Markdown references/Cursor; local design-document check. |

## C. Snapshot claims and caveats

C-01. The 2026-10-12 `MAIN_DESIGN / DESIGN_ONLY` statement describes that historical snapshot, not present state.
C-02. Emergency Stop, built-in Safe Baseline, Root-specific Epoch, Canary deadlines, and CI Receipt were design baseline claims, not changes to the snapshot's 14 ACCEPTED decisions and not proof that Issues were complete.
C-03. Snapshot initial Cursor: `PDK-M00-S01` document validation. Next safety design gates: `PDK-M00-S05` (Threat Model) and `PDK-M00-S06` (Bootstrap/emergency-stop boundary). These are historical cursor statements, not current status.
C-04. The document did not authorize changes to existing HARNESS, GitHub repository creation/push, DB access, or credential operations.
C-05. The snapshot does not establish later implementation status. For present status, consult authoritative Git state, verification receipts, `Issues.md`, `decisions.md`, and `method.md`; do not treat this historical presentation as a status assertion.

## D. Starter / restart procedure (historical README)

1. Confirm repository root; do not accidentally write to `.HARNESS` or its parent repository.
2. Read `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`.
3. Run `python3 scripts/lint_design.py` to check IDs, small-goal DAG, and OPEN resolution targets.
4. Reconcile `Issues.md` Durable Cursor with actual Git diff and CI/verification receipts. Cursor is a hint and does not override actual state.
5. Select one small goal whose dependencies and permissions are satisfied. State sequence: before execution `[-] WIP`; after implementation `[~]`; after observed local check `[*]`; `[x]` only after local independent verification and acceptance criteria. At the time of this source README, the then-current user direction did not require CI/remote attestation for completion. This is a historical statement about that source README, not current/general policy or present authorization.
6. On communication loss, instruct `continue`. Reconcile an uncertain DB commit using the same Command ID; do not rerun with a different ID.

### Exact recommended checks

```sh
python3 scripts/lint_design.py
python3 scripts/lint_design.py --emit-summary
```

Python standard library only. These inspect document structure; they do not prove Go behavior, DB behavior, or safety. Generated `docs/issue-dependencies.generated.md` derives from `Issues.md` and does not represent a DAG between medium goals.

## E. Exact SIGMA/1 handoff example (historical)

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

E-01. Preserve the field order and facts above when quoting this example.
E-02. The Envelope is an instruction format, not authorization. Do not put unverified facts in `Known facts`.

## F. PoC outline and limits (not a claim of implementation)

Go Contract First + pgx Native + one PostgreSQL instance + two Coordinator processes + two Worker Simulators + Root A/B. Policy v1 → Canary v2 for Root B only → promote globally → fault injection → rollback to verified LKG (built-in Safe Baseline if invalid).

- Epoch design baseline distinguishes Scope Activation, Root Authorization, and Security; avoid improperly revoking Root A's old credential during Root B canary.
- Safety priorities: human Break-glass, Gateway fail-closed, pre-authorized rollback, and deadline termination of HOLD/MONITORING.
- Verification outline: finite model checking, DDL/DB contention, commit-unknown behavior, and CI observation of Receipts. LLM explanations and dummy signatures are not passing evidence.
- The historical outline is not proof that any component/test exists or ran.

## G. References

[decisions.md](decisions.md) · [Issues.md](Issues.md) · [method.md](method.md) · [rules/](rules/) · [THREAT_MODEL.md](THREAT_MODEL.md)
