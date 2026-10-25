@meta=text/POLYGLYPH×SIGMA/1
@codec=nearest_ancestor(POLYGLYPH.md);read_before_body=true
@authority=SIGMA/1+routed-LRF-only;PG=representation-only
@decode_failure=STOP;unknown=preserve;action=blocked;ask=true

# Independent Design Evaluation — experimental guide

§0 STATUS ∧ AUTHORITY
Status=EXPERIMENTAL∧NON_CANONICAL. This guide, the developing PADDOCK harness and `prompt.md` are not the project’s canonical source of truth; existence≠activation. Only explicit user invocation of `prompt.md` activates its automatic design-choice workflow for that current task. `.harness`/`~/.harness` is reference-only if `method.md` allows it; never infer authority/policy from it. `decisions.md` ACCEPTED register+routed LRF remain governing sources. This guide cannot grant effects or change `decisions.md`.

Legend: `A`=ACCEPTED decisions+routed LRF; `P`=DESIGN_BASELINE/OPEN; `R`=independent read-only evaluator; `M`=Main; `I`=Issue; `E`=effect. `∧`=AND; `∨`=OR; `¬`=NOT; `⇒`=requires; `≠`=distinct. Symbols are semantic shorthand only; prose controls.

§1 TRIGGER
Material choice `c` exists when an unspecified alternative may materially affect safety, correctness, compatibility, cost or Issue scope. Before CODE, M examines the real repository/interfaces/dependencies/platform and available evidence. Do not treat an incomplete DESIGN_BASELINE fixture as immutable ground truth; do not silently change ACCEPTED decisions.

§2 OPTIONS
When three distinct honest feasible options exist, enumerate exactly three, tradeoffs, and a Main recommendation `rec`. If fewer than three honest feasible options exist, explain why, never invent candidates/facts, and STOP+ask as required by the governing design-choice rule. Design choice sets scope only, not effect permission.

§3 INDEPENDENT REVIEW
Dispatch `R≠implementer` with the exact options, relevant `A`, Issue acceptance/scope, source/API/dependency/platform evidence. R is read-only: no edits/tests/DB/credentials/network/VCS. R compares implementation feasibility, ACCEPTED compatibility, safety/correctness/compatibility/cost/scope, uncertainty, and whether any candidate is strictly superior to `rec`. R’s opinion≠decision/evidence/authority.

`SUPERIOR(x,rec) := feasible_in_actual_repo(x) ∧ compatible_with_A_and_acceptance(x) ∧ safeguards_preserved(x) ∧ no_unapproved_scope_or_effect(x) ∧ evidence_supported(x) ∧ materially_better(x,rec)`.
Gloss: x must be implementable with actual repo/tools, satisfy ACCEPTED requirements, retain safeguards, add no unapproved scope/effect, have supporting evidence, and improve at least one stated material criterion.

§4 CURRENT-TASK AUTO-SELECTION
When `prompt.md` is explicitly invoked by the user for this task, that current-task instruction delegates option selection to Main after the independent evaluation. This may satisfy a lower-priority PADDOCK project-document option prompt (including routed `formal.design-choice`) only to the extent the current instruction hierarchy permits. If any system/developer instruction or more-specific current user instruction requires a direct confirmation, ask/STOP. The automatic choice is not persistent and never grants effects.

This auto mode is task-local, not persistent project policy. It cannot override system/developer/current user instructions, ACCEPTED decisions, routed normative LRF, safety stops, or independent effect approvals. A specific current user stop/narrowing instruction takes precedence. Missing/conflicting `A`, R/Main disagreement, tied/incomparable ranking, insufficient evidence, unknown feasibility, a new material choice, or required effect/scope expansion ⇒ STOP and ask. Effect permission never follows from SUPERIOR or selection.

§5 RECORD + LIMITS
Before CODE record Issue/options/recommendation/evaluator/result/ACCEPTED IDs/feasibility/effect gates/risks. This is process documentation, not a Runner Receipt or approval. Do not claim CI/DB/key/identity/production proof from design review. Current LRF and exact user approval govern every live/write effect.

POLYGLYPH goal: compress wording while preserving meaning, polarity, scope, modality, exceptions, authority and decision boundary. Uncertainty→preserve; ambiguity→STOP; never let notation authorize behavior.
