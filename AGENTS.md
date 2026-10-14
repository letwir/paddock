# PADDOCK / LRF-1 bootstrap

## B-01 — Bootstrap and authority
- **Subject:** Every agent acting in PADDOCK.
- **Scope:** Bootstrap policy and its routed records.
- **Modality:** MUST.
- **Condition:** Before action, and after task classification.
- **Action:** READ+COMPILE [SIGMA](rules/BOOTSTRAP.lrf); then load matching records from [MANUAL](rules/MANUAL.lrf) and [LOAD](rules/LOAD.lrf).
- **Outcome:** The authority source is only the `decisions.md` **ACCEPTED register (D-001–D-017)** and LRF records routed from it. `DESIGN_BASELINE` is not ACCEPTED; recommendations in `OPEN` are not decisions. Existing `.HARNESS` (`letwir/config`) is **reference-only**: PADDOCK does not implicitly inherit its execution rules, credentials, authority, host environment, or agent-dispatch policy.

## B-02 — Required reading and design lint
- **Subject:** Agent selecting work.
- **Scope:** Design documents and work selection.
- **Modality:** MUST.
- **Condition:** Before selecting work.
- **Action:** Read, in order, `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`; run `python3 scripts/lint_design.py` to mechanically check IDs, the subgoal DAG, OPEN resolution targets, and Cursor consistency.
- **Outcome:** Work selection follows the defined source documents and checked design references.

## B-03 — Cursor evidence precedence
- **Subject:** Agent reconciling Issues state.
- **Scope:** `Issues.md` Cursor versus observed repository and verification evidence.
- **Modality:** MUST.
- **Condition:** Cursor conflicts with observed state.
- **Action:** Treat Cursor as a hint, not as higher priority than actual Git state or verification Receipts; observe the actual files, Git, and verification logs and report the discrepancy.
- **Outcome:** Reported state is grounded in observation, not Cursor alone.

## B-04 — Effect classification and approval
- **Subject:** Agent considering an action.
- **Scope:** Action effects.
- **Modality:** MUST.
- **Condition:** Before acting.
- **Action:** Classify the effect: `RO_LOCAL` = local read/inspection; `RO_PUBLIC` = public read-only; `LW_SCOPE` = requested reversible workspace edits and proportionate checks. `EXT_WRITE`, `RELEASE`, `LIVE_WRITE`, `VCS_WRITE`, `DESTRUCT`, `CRED`, `CHARGE`, and `PROD_DEP` each require explicit approval for that task. If the effect cannot be classified, STOP and ask.
- **Outcome:** Only effects allowed by their classification proceed.

## B-05 — Verification evidence
- **Subject:** Agent reporting verification or advancing an Issue.
- **Scope:** Verification claims and `[x]` status.
- **Modality:** MUST.
- **Condition:** Before claiming success or marking `[x]`.
- **Action:** Do not treat Worker or Verifier self-report as evidence. The Runner must independently execute the acceptance checks and record actual observations: Exit Code, Hash, and target Revision. An independent review must be by trusted CI/Verifier **or** a Verifier subagent distinct from the implementer; the Verifier reviews the diff and acceptance criteria independently. Main compares the review report with Runner observations and reconciles and resolves findings. Do not report unverified or unrun checks as successful.
- **Outcome:** `[x]` is allowed only after acceptance conditions are met and independent verification is confirmed. If CI is absent or unused, explicitly disclose that absence. Local results are not CI attestation. Self-report alone is not evidence.

## B-06 — Restart contract
- **Subject:** Agent resuming after communication or conversation interruption.
- **Scope:** Continuation state.
- **Modality:** MUST.
- **Condition:** On restart or when leaving work resumable.
- **Action:** Follow `method.md` `CONTINUE/1` (Preflight → Reconcile → Execute); leave state readable from the `continue` instruction in Cursor and Git.
- **Outcome:** Work can be safely reconciled and resumed from durable state.

## B-07 — Write boundary and ownership
- **Subject:** Agent writing files.
- **Scope:** Repository files and concurrent writers.
- **Modality:** MUST.
- **Condition:** Before and during a write.
- **Action:** Write only within the PADDOCK repository; do not write to `.HARNESS` or the parent repository. Keep one Writer per file.
- **Outcome:** Changes stay within the repository boundary and each file has a single writer.

## B-08 — Invalid policy links
- **Subject:** Agent following SIGMA or a linked rule.
- **Scope:** The applicable action.
- **Modality:** STOP.
- **Condition:** SIGMA/link is missing, unreadable, invalid, structurally unclear, or has an equal-rank conflict.
- **Action:** Stop the affected action and ask.
- **Outcome:** No action proceeds under ambiguous or unusable policy.

## B-09 — Issue state vocabulary
- **Subject:** Agent updating an Issue state.
- **Scope:** Issue lifecycle.
- **Modality:** MUST.
- **Condition:** Any state transition.
- **Action:** Use `[ ] TODO` → `[-] WIP` → `[~] IMPLEMENTED` → `[*] TESTED` → `[x] DONE`; apply the `[x]` gate in B-05.
- **Outcome:** State reflects the actual work and verification status.

## B-10 — Document role and sources of truth
- **Subject:** Reader or agent using this file.
- **Scope:** Document authority.
- **Modality:** MUST.
- **Condition:** Interpreting project guidance.
- **Action:** Treat this file as an **agent bootstrap entrypoint and procedure**, not the source of design decisions. Use `decisions.md` as the design-decision source of truth, `method.md` for procedures and the restart contract, and `Issues.md` for work and state; `README.md` is the entrypoint for humans and general readers.
- **Outcome:** Each document is used only within its defined role.
