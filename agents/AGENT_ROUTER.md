# PADDOCK Worker Router (project-specific)

This manifest is a selection aid, not an authority source. Effect permissions come from `rules/BOOTSTRAP.lrf` and the current task; review/state evidence requirements come from `method.md`. No worker receives VCS, live DB, credential, network-write, release, or other authority by being selected.

## Available backends

| Backend | Eligible scope | Requirement |
|---|---|---|
| `general` Codex subagent | Bounded CODE or review task | One invocation per active workstream; exact file allowlist; may edit only when the task's workspace-edit permission applies. |
| `explore` Codex subagent | Read-only repository discovery only | Never use as a CODE worker. |

Every `functions.task` dispatch MUST explicitly supply `subagent_type`. The currently available runtime values are `general` (bounded CODE and review) and `explore` (read-only discovery); select the matching type explicitly for every dispatch, including verifier dispatches. Do not omit the field, rely on an implicit/default backend, invent another type, or silently fall back to another worker. Choose one eligible available backend per CODE workstream. Prefer comparable measured context consumption if available; otherwise use `evaluation/worker-context-priority.json` only as dated, nonnormative fallback evidence. A separate verifier must be a distinct invocation from the implementation worker and must not edit.

If dispatch fails because the requested runtime/backend is unavailable or its LLM session is missing/unconfigured, stop and report the routing blocker. Do not take over the worker's task as the main agent, retry through an unselected backend, or infer/supply a model or session ID. `functions.task` requires `subagent_type`; it does not let this router set model/session IDs. Model selection and session lifecycle are host-managed. Host configuration documentation recommends leaving a subagent model unset to inherit the parent model; therefore this repository router cannot force, create, or repair a model/session configuration. A descriptive role profile is not executable dispatch configuration or authority.

A handoff must follow the exact wrapper and ordered fields in `method.md` §1. Never delegate VCS, external effects, credentials, or live DB actions. Main owns final diff inspection, Runner checks, issue state, receipt, and push authorization/scope.
