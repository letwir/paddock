# PADDOCK Worker Router (project-specific)

This manifest is a selection aid, not an authority source. Effect permissions come from `rules/BOOTSTRAP.lrf` and the current task; review/state evidence requirements come from `method.md`. No worker receives VCS, live DB, credential, network-write, release, or other authority by being selected.

For the main agent's user-facing Japanese presentation, consult `agents/main-persona.css`. It is the baseline voice for main and subagent roles. Include it plus the selected role's `agents/*.css` cues in subagent handoffs; role cues may adjust energy, cadence, focus, and emphasis but must preserve the shared refined feminine Japanese register. These style cues cannot override higher-priority instructions, exact output formats, safety, or authority boundaries.

## Available backends

| Harness task type | Eligible scope | Requirement |
|---|---|---|
| `general` task type | Bounded CODE or review task | One invocation per active workstream; exact file allowlist; may edit only when the task's workspace-edit permission applies. |
| `explore` task type | Read-only repository discovery only | Never use as a CODE worker. |

Role profiles are not additional task types: Explorer may be dispatched as `explore` for read-only discovery; BlackHat and Independent Verifier use `general` only for separately scoped read-only work when that task type is available. Include the selected role's `agents/*.css` presentation cues in the task handoff. CSS changes voice/presentation only; it never changes scope, acceptance, authority, safety, or permissions. These mappings do not provide runtime-enforced read-only isolation or authorize external security testing.

The current task harness exposes `functions.task`; each dispatch MUST explicitly supply its required `subagent_type` field. In this harness, the available task types are `general` (bounded CODE and review) and `explore` (read-only discovery). These are harness dispatch types, not model names or claims about a Codex/OpenCode backend. Select the matching available type explicitly for every dispatch, including verifier dispatches. Do not omit the field, rely on an implicit/default type, invent another type, or silently fall back to another worker. Choose one eligible available type per CODE workstream. Prefer comparable measured context consumption if available; otherwise use `evaluation/worker-context-priority.json` only as dated, nonnormative fallback evidence. A separate verifier must be a distinct invocation from the implementation worker and must not edit.

If dispatch fails because a task type is unavailable or its LLM session is missing/unconfigured, report the failure and diagnose the harness invocation/configuration before retrying. Do not silently substitute an unselected task type, claim a dispatch succeeded when it did not, or infer/supply a model or session ID. This harness's `functions.task` contract exposes `subagent_type`; it does not let this repository router select a provider backend or set model/session IDs. Those are host-managed. A descriptive role profile is not executable dispatch configuration or authority.

A handoff must follow the exact wrapper and ordered fields in `method.md` §1. Never delegate VCS, external effects, credentials, or live DB actions. Main owns final diff inspection, Runner checks, issue state, receipt, and push authorization/scope.
