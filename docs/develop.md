# Development Guide — Independent Design-Choice Evaluation

> Status: user-directed workflow proposal for PADDOCK Main. This Markdown is not an ACCEPTED entry in `decisions.md` and is not a normative LRF rule. It grants no tool, database, network, credential, VCS, or other effect permission.
>
> Activation: the user explicitly requested this automatic design-choice workflow in the current conversation on 2026-10-25. Use it when that user directive applies; a later or more specific instruction may narrow, suspend, or replace it.

## Purpose and authority

This procedure lets Main resolve a material design choice without an extra user prompt when a distinct read-only evaluator finds a clearly superior feasible option to Main’s recommendation.

`A` = `decisions.md` **ACCEPTED** register plus its routed LRF rules. `P` = `DESIGN_BASELINE` or `OPEN` material, which is not an accepted decision. `R` = the independent read-only evaluator. `M` = Main/orchestrator. `≻` = demonstrably strictly preferable under the criteria below. These symbols are shorthand only; the accompanying prose controls.

- Compare options against `A` and the task’s recorded acceptance/scope. Never promote `P`, a recommendation, a memory entry, a Worker report, or a verifier report into an ACCEPTED decision.
- This procedure does not modify `decisions.md`; a change to ACCEPTED decisions follows the project’s explicit superseding process.
- Design selection sets implementation scope only. It does not approve DB, live, credential, external, production, dependency, charge, destructive, or VCS effects. Those effects still require their own current-task authorization.

## Procedure

### 1. Define the choice before CODE

Main records the task/Issue, why the choice materially affects behavior, safety, compatibility, cost, or scope, and the existing acceptance/effect boundary. State the candidate options and Main’s current recommendation, with concise tradeoffs.

Use exactly three **distinct, honestly feasible** options when three exist. Do not invent an option to reach three. If fewer than three honest options exist, explain the limit and STOP for user direction.

### 2. Obtain a separate read-only evaluation

Dispatch one evaluator invocation distinct from the implementer and Main Runner. Give it the exact candidate options, relevant `decisions.md` ACCEPTED entries, current Issue acceptance, constraints, and necessary source/API context. Its scope is comparison only: no edits, tests, live DB, credentials, network, or VCS effects.

Ask the evaluator to:

- assess every option against each relevant ACCEPTED decision and acceptance constraint;
- state compatibility, safety, correctness, implementation scope, cost/complexity, reversibility, and material risks;
- identify unsupported assumptions, missing evidence, hidden effect expansion, or unresolved sub-choices;
- rank feasible options and say whether any candidate is strictly superior to Main’s recommendation;
- distinguish a design opinion from implementation evidence, authority, or approval.

The evaluator may not create a fourth option, invent facts/permissions, or resolve an unrelated OPEN item as if accepted.

### 3. Apply the automatic selection rule

A candidate `X` is **strictly superior** to recommended option `Y` only when the evaluator’s reasoning and Main’s source/decision cross-check establish all of the following:

1. `X` is feasible within the current Issue acceptance and allowed design scope.
2. `X` conflicts with no relevant ACCEPTED decision and weakens no mandatory safety, integrity, compatibility, or fail-closed requirement.
3. `X` does not silently add effects, files, dependencies, external services, identity/key custody, thresholds, expiry values, or operational claims that are not selected.
4. `X` is no worse on the material safety and compatibility criteria for this choice, and is demonstrably better on at least one stated material criterion.
5. Its advantage does not depend on an unknown fact or unresolved choice.

Critical natural-language rule: **If one feasible option is clearly strictly superior to Main’s recommendation under all five conditions, Main adopts that option and proceeds without asking the same design question again. If no option is strictly superior, Main’s recommendation stands only because the user has enabled this automatic-evaluation workflow, and Main may proceed within that selected scope.**

The automatic choice fails closed: STOP and ask the user if evaluators materially disagree; the ranking is tied or incomparable; evidence is insufficient; feasibility depends on an unresolved assumption; a new material sub-choice appears; the best option conflicts with `A`; or the choice would require effect/scope authorization beyond the current task. Do not resolve such cases by majority vote or by treating the evaluator’s preference as an ACCEPTED decision.

### 4. Record before CODE

Before implementation, Main records in the active Issue/Cursor or other appropriate project record:

- the exact choice and selected option;
- Main’s original recommendation and the evaluator’s comparative conclusion;
- applicable ACCEPTED decision IDs and acceptance/effect constraints;
- why the superior-option test passed, or why the original recommendation stands;
- residual risks, deferred OPEN items, and separate effect approvals still required.

Keep the record factual and concise. A review/choice record is not a Runner Receipt, test result, CI attestation, key/identity proof, DB approval, or VCS approval.

## Stop conditions

STOP before CODE if the candidate set is dishonest or incomplete, ACCEPTED authority is ambiguous, required verification evidence is absent, no distinct evaluator is available when required, the evaluator’s report is not independently inspectable, or any selected option silently widens effects or ownership. Replan or ask; do not bypass the gate.
