# PADDOCK Worker Router

> Scope: PADDOCK-specific routing aid. This document is not an authority source.

## R-01 — Authority and effect boundary
- **Subject:** Main agent and every selected worker.
- **Scope:** All dispatches and resulting work.
- **Modality:** MUST_NOT.
- **Rule:** Selection grants no VCS, live-DB, credential, network-write, release, or other authority. Effect permissions come only from `rules/BOOTSTRAP.lrf` and the current task. Review/state evidence requirements come from `method.md`.
- **Outcome:** A selected role or task type never authorizes an effect.

## R-02 — Shared presentation baseline
- **Subject:** Main agent and subagents.
- **Scope:** User-facing Japanese presentation and handoff presentation cues.
- **Modality:** MUST.
- **Action:** Use `agents/main-persona.css` as the shared baseline voice for main and subagent roles. When a role-specific CSS cue exists, include the baseline and cue inside the existing `Role` field value of the handoff; do not add fields or change field order.
- **Constraint:** Role cues may adjust energy, cadence, focus, and emphasis, but must preserve the shared refined feminine Japanese register. CSS is presentation only and cannot override higher-priority instructions, exact output formats, safety, scope, authority, acceptance, or permissions.

## R-03 — Available harness task types
| Harness task type | Eligible scope | Requirement |
|---|---|---|
| `general` | Bounded CODE or review task | One invocation per active workstream; exact file allowlist; editing only when workspace-edit permission applies. |
| `explore` | Read-only repository discovery | Never use as a CODE worker. |

Role profiles are not additional task types. Explorer may use `explore` for read-only discovery. BlackHat and Independent Verifier may use `general` only for separately scoped read-only work when available. Include the selected role's CSS cue when one exists. These mappings do not provide runtime-enforced read-only isolation and do not authorize external security testing.

## R-04 — Dispatch contract and selection
- **Subject:** Every dispatch, including verifier dispatches.
- **Modality:** MUST.
- **Condition:** This harness exposes `functions.task`.
- **Action:** Explicitly supply its required `subagent_type`. The available values here are `general` (bounded CODE and review) and `explore` (read-only discovery). These are harness task types, not model names or claims about a Codex/OpenCode backend.
- **Prohibitions:** Do not omit the field, rely on a default, invent another type, or silently fall back to another worker. Choose one eligible available type per CODE workstream.
- **Selection guidance:** Prefer comparable measured context consumption if available; otherwise use `evaluation/worker-context-priority.json` only as dated, nonnormative fallback evidence.
- **Independent verification:** A verifier is a distinct invocation from the implementation worker and must not edit.

## R-05 — Dispatch failure and host-managed model
- **Subject:** Main agent.
- **Condition:** Dispatch fails because a task type is unavailable or its LLM session is missing/unconfigured.
- **Modality:** MUST.
- **Action:** Report the failure and diagnose harness invocation/configuration before retrying.
- **Prohibition:** Do not silently substitute an unselected task type, claim a dispatch succeeded when it did not, or infer/supply a model or session ID.
- **Fact:** `functions.task` exposes `subagent_type`; this repository router cannot select a provider backend or set model/session IDs. The actual model is host-managed and is not specified by this repository document.
- **Outcome:** A descriptive role profile is neither executable dispatch configuration nor authority.

## R-06 — Handoff and main-agent ownership
- **Subject:** Main agent.
- **Modality:** MUST.
- **Action:** Use the exact wrapper and ordered fields in `method.md` §1. Never delegate VCS, external effects, credentials, or live-DB actions. Main owns final diff inspection, Runner checks, issue state, receipt, and push authorization/scope.
