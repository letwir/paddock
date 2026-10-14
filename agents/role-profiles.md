# PADDOCK role profiles

These profiles are inspired by the role-description / metadata split observed in `.harness/agents`, which is a **read-only format reference only**. They are PADDOCK-local documents, not imported policy.

- Main agent presentation: [`main-persona.css`](main-persona.css), adapted from the read-only `~/.harness/persona/PERSONA.css` reference.

- Implementation: [`work-order-worker.md`](work-order-worker.md), metadata [`work-order-worker.toml`](work-order-worker.toml).
- Read-only discovery: [`explorer.md`](explorer.md).
- Defensive security assessment: [`blackhat.md`](blackhat.md).
- Independent review: [`independent-verifier.md`](independent-verifier.md), metadata [`independent-verifier.toml`](independent-verifier.toml).

Presentation-only persona cues are stored separately: [`explorer.css`](explorer.css), [`blackhat.css`](blackhat.css), and [`independent-verifier.css`](independent-verifier.css). The main agent should apply `main-persona.css` to its user-facing Japanese responses. It is also the baseline for subagent voices: a role CSS may adjust energy, cadence, focus, and emphasis, but must not replace the shared refined feminine Japanese register. The main dispatcher should include both the main baseline and selected role cues in the handoff. CSS changes voice/presentation only, never scope, acceptance, authority, or safety.

The Markdown files define task behavior and return format; the TOML files are descriptive metadata only. This repository/runtime does **not** load them as executable agent configuration, select models from them, enable a backend, or grant permissions. Current backend availability remains exactly what `agents/AGENT_ROUTER.md` lists. In particular, these profiles do not fix an `LLM session not configured` dispatch failure.

The worker, Explorer, BlackHat, and Verifier are distinct roles. A verifier must be separately invoked and receive no-edit instructions; runtime sandbox enforcement must not be claimed unless the selected backend actually provides it. `explore` remains discovery-only and is not a replacement verifier. BlackHat is bounded defensive analysis guidance, not authorization to exploit or interact with external systems. These profiles adapt role descriptions from the user's `~/.harness/agents`; they do not import that harness's routers, models, permissions, commands, or executable configuration.
