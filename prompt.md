@meta=text/POLYGLYPH×SIGMA/1
@codec=nearest_ancestor(POLYGLYPH.md);read_before_body=true
@authority=SIGMA/1+routed-LRF-only;PG=representation-only
@decode_failure=STOP;unknown=preserve;action=blocked;ask=true

# PADDOCK CONTINUE/1 — experimental prompt

§0 STATUS ∧ AUTHORITY
Status=EXPERIMENTAL∧NON_CANONICAL. This task prompt and the developing PADDOCK harness are not the canonical source of truth; their presence≠activation. Invoke only when the current user explicitly asks to run/use this prompt. Invocation is the user’s current-task delegation to continue Issues and automatically choose among honestly evaluated design options. It grants no effect.

Legend: `A`=decisions.md ACCEPTED register+routed LRF; `P`=DESIGN_BASELINE/OPEN/recommendation; `I`=Issue; `dep(I)`=explicit depends_on; `READY(I)`=all dep(I) DONE by observed evidence and all gates pass; `R`=distinct read-only evaluator; `V`=independent Verifier; `W`=Main Runner; `M`=Main; `E`=effect. `→`=ordered phase only; `∧`=AND; `∨`=OR; `¬`=NOT; `⇒`=requires; `≠`=distinct. Symbols are representation only: they grant no authority, approval, proof, or evidence.

Authority: follow system/developer/current-user instructions and PADDOCK routed LRF/ACCEPTED decisions in their defined precedence. `.harness`/`~/.harness` is reference-only where `method.md` permits; ¬canonical∧¬authority∧¬implicit policy inheritance. Do not treat it as PADDOCK truth. If asked to make it authoritative, disclose the conflict with PADDOCK bootstrap and follow the higher-priority source. `prompt.md`, `docs/develop.md`, `docs/handover.md`, memory and Worker/Verifier reports are informative/task aids, never accepted decisions.

このpromptは明示invokeされた現在タスクでだけ働く。選択範囲=design scope。効果承認≠設計選択であり、別途必要。

§1 START → RECONCILE → SELECT
1. Read active root AGENTS.md; READ+COMPILE `rules/BOOTSTRAP.lrf`; load only matching `rules/MANUAL.lrf`, `rules/LOAD.lrf`, and other routed LRF. For document work classify with `rules/PIDGEN-CASCADE.seq` and retrieve applicable `rules/HANDOFF-FORMAL.lrf` IDs.
2. Read `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`. Only `A` and routed LRF are accepted authority; do not promote `P`, Memory, reports, or handover prose.
3. If `docs/handover.md` exists, read as stale/non-authoritative snapshot; refresh by full-file overwrite only after new observations. Inspect actual branch/HEAD/upstream/divergence/index/status/history/Receipts; run design lint and `scripts/continue_plan.py`. Cursor≠higher truth than Git/Receipt.
4. Select only `READY(I)` from the small-Issue `depends_on` DAG. Parent/medium-goal order≠execution dependency. If all done, no READY Issue, lint fails, or a blocker applies, stop/report exact next action.

§2 MATERIAL CHOICE → INDEPENDENT EVALUATION → AUTO_SELECT
For each material unspecified choice before CODE, define exactly three distinct, honest, feasible options when three exist; if fewer than three are honest/feasible, explain why and STOP under the governing design-choice rule. Never invent an option/fact. Record tradeoffs and Main’s initial recommendation `rec`.

Dispatch `R≠implementer` as a read-only evaluator. Supply exact options, `A`, Issue acceptance/scope, current repository/API/dependency/platform constraints and available source evidence. `R` may not edit, test, access DB/live state/credentials/network, or perform VCS effects. Require feasibility analysis, ACCEPTED-decision compatibility, safety/correctness/compatibility/cost/scope comparison, assumptions/uncertainty, ranking, and whether an alternative is strictly superior to `rec`.

`SUPERIOR(x,rec) := feasible_in_actual_repo(x) ∧ satisfies_A_and_acceptance(x) ∧ preserves_safety(x) ∧ no_unapproved_scope_or_effect(x) ∧ evidence_supported(x) ∧ materially_better(x,rec)`.
Natural-language meaning: x must actually be implementable with available code/tools/platform, meet accepted requirements, preserve safeguards, add no unapproved scope/effect, have evidence, and be demonstrably better on a stated material criterion.

Because the user explicitly invoked this automatic prompt, `R+M` compare before CODE. This invocation is the current-task user delegation for design-option selection and may satisfy a lower-priority project-document choice prompt (including `formal.design-choice`) only to the extent current system/developer authority permits. If any `x` satisfies SUPERIOR, M selects the best-supported superior option automatically. If none does, M keeps `rec` and continues within it. Do not ask the same material-option question again during this explicitly activated task. This delegation does not change ACCEPTED decisions or approve effects; if higher-priority instructions require direct confirmation, STOP and ask.

STOP/ask only if no honest feasible option exists; `A` is missing/conflicting; `R` is unavailable or materially disagrees with M; evidence is insufficient; feasibility rests on an unknown fact; a new material choice appears; or safe implementation requires unapproved scope/effects. Do not majority-vote, fabricate certainty, or silently weaken a safeguard. Higher-priority system/developer/current-user instructions always win; a more specific current user direction may stop/replace this prompt.

Critical paraphrase: option ranking and selection are automatic only inside the user-invoked design task. DB/live/credential/network/production/dependency/charge/destructive/VCS effects still require their own current-task approval; formulas and this prompt cannot authorize them.

§3 PLAN → CODE → VERIFY
Before CODE record Issue ID, exact file allowlist, one writer/file, acceptance, dependencies, rollback/stop conditions, `D_pub`, effect gates and chosen design. Preserve all pre-existing dirty work. If Worker finds `D_worker>D_pub`, Worker stops; M replans before more CODE. Never edit `decisions.md` as an ordinary Worker.

Issue state=`[ ] TODO → [-] WIP → [~] IMPLEMENTED → [*] TESTED → [x] DONE`; no skipping. For DONE, `W` actually runs acceptance and records each command/Exit Code/Hash/target Revision; `V≠implementer` independently reviews acceptance and diff; M reconciles every clause/finding. Worker/Verifier self-report≠Runner evidence. Local evidence≠CI attestation; disclose CI absence. Source/unit/compile-only≠DB/persistent/network/production evidence. Failures/unrun checks are not PASS.

Classify each effect using current LRF. Design selection authorizes zero effects. Never infer public enrollment, HTTP/network, credential access, live DB, production, dependencies or TTL/threshold values. Unresolved safety anomaly ⇒ no related DB action until reconciled/approved. Preserve unrelated paths.

§4 VERIFIED DONE → MEMORY → VCS → NEXT
1. After `I=[x]` and M reconciliation, require fresh current-task `LIVE_WRITE` approval before ingesting only verified non-secret Issue outcome/Receipt to llm-memory. Report actual result/ID. Failure, unavailable tool, or no approval ⇒ STOP before next Issue.
2. After successful ingest, determine exact Issue-only files/hunks, upstream and commit range; present include/exclude paths, commits and target upstream. Require fresh exact `VCS_WRITE` approval before staging.
3. Stage/commit/push only the approved Issue plus necessary Issue/Receipt/generated-index updates. Verify every commit/path and upstream success. No force-push, remote change, history rewrite or unrelated staging. Isolation/write failure ⇒ preserve and STOP.
4. After VCS verification, refresh `docs/handover.md` by replacing the whole file, update Cursor/index, rerun lint/planner, then select next `READY(I)`.

`I DONE ∧ memory-approved+successful ∧ VCS-approved+exact+verified ⇒ next selection allowed`.
Gloss: all three gates are required; otherwise stop at current gate. The sequence grants no future write permission.

§5 STOP / PRESERVE
Missing/conflicting LRF, failed lint/planner, invalid Receipt, dependency gap, ambiguous ownership/effect, insufficient evidence, unresolved review, upstream ambiguity, or safety anomaly ⇒ STOP. Preserve all dirty/untracked work; report facts, failures, unknowns, owner, and one safe next action. Never present this prompt as canonical policy or CI/DB proof.
