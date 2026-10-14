# 🧭 PADDOCK Worker Router

> `[SPR/PIDGIN::ρ→bounded]` 🧭 main · 🧩 task type · 🎯 dispatch
> Routing aid, not authority. `agents/main-persona.css` is shared baseline; role CSS is presentation-only and cannot alter authority or behavior.

## 🧭 Legend
`T`=harness task type; `E`=effect domain, exactly the BOOTSTRAP set `{RO_LOCAL, RO_PUBLIC, LW_SCOPE, EXT_WRITE, RELEASE, LIVE_WRITE, VCS_WRITE, DESTRUCT, CRED, CHARGE, PROD_DEP}`; `E_requested`=effects requested for delegation; `F`=effects forbidden to subagents, exactly `{EXT_WRITE, RELEASE, LIVE_WRITE, VCS_WRITE, DESTRUCT, CRED, CHARGE, PROD_DEP}`; `A`=authority; `V`=verifier invocation; `I`=implementation invocation. `∈`=membership, `∩`=overlap, `∅`=empty, `⇒`=implies, `≠`=distinct, `∀`=for every. Symbols grant no permission. `E_requested ∩ F = ∅`: if requested effects intersect `F`, STOP before dispatch and do not perform them; if they do not, all other effects still require their normal explicit authorization under BOOTSTRAP/current task. `V≠I` requires separate verifier invocation.

## R-01 · 🔐 Authority
Selection never grants `A`. Effects derive only from `rules/BOOTSTRAP.lrf` and current task; review/state evidence from `method.md`. Role/task selection does not authorize VCS, live DB, credentials, network writes, release, or other effects. Main may perform an otherwise-forbidden-to-subagents effect, including an approved VCS push, only when the current task explicitly authorizes it.

## R-02 · 🎨 Presentation
Use `main-persona.css` baseline. If role CSS exists, include baseline and cue inside existing `Role` value; add no fields/reorder none. Cues may alter energy/cadence/focus/emphasis only—not instructions, output formats, safety, scope, authority, acceptance, or permissions.

## R-03 · 🧩 Task types
`T∈{general, explore}` only. These are the only listed harness types, not model names.
- `general`: bounded CODE or review; one invocation per active workstream; exact allowlist; edit only where workspace permission applies.
- `explore`: read-only repository discovery; never CODE worker.
Profiles are not task types. Explorer may use `explore`; BlackHat/Verifier may use `general` only for separately scoped read-only work. Mapping is not runtime-enforced isolation or external security authorization.

## R-04 · 🎯 Explicit dispatch
When harness exposes `functions.task`, explicitly provide required `subagent_type∈{general,explore}` and choose one eligible available type per CODE workstream; never omit type or rely on default. No invented type, silent fallback, or model/backend inference. Prefer comparable measured context use when available; otherwise `evaluation/worker-context-priority.json` is dated, nonnormative fallback evidence.
Verifier: `V≠I`; prompt requires no-edit boundary; no runtime sandbox guarantee.

## R-05 · 🛑 Failure + host-managed session
Type unavailable or LLM session missing/unconfigured ⇒ report failure and diagnose harness invocation/configuration before retry. For known `LLM session not configured`, retry only already-selected `general` after diagnosis; a successful general probe authorizes no fallback or model claim. No silent substitution, false success, or invented/supplied model/session ID. Model/session/backend are host-managed; repository does not select them.

## R-06 · 📦 Handoff + ownership
Use exact `method.md` §1: `<Γ>`, `SIGMA/1: PIDGEN/text`, exact ordered fields `Role`, `Target`, `Acceptance`, `Scope`, `Known facts`, final payload `SIGMA/1`, `</Γ>`. Preserve wrapper, field names, order. Never delegate effects in `F`. Main owns final diff inspection, Runner acceptance checks, issue state, and receipt; any Main VCS push requires explicit current-task authorization and scope.
