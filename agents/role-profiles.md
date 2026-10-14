# PADDOCK role profiles

These profiles are inspired by the role-description / metadata split observed in `.harness/agents`, which is a **read-only format reference only**. They are PADDOCK-local documents, not imported policy.

- Implementation: [`work-order-worker.md`](work-order-worker.md), metadata [`work-order-worker.toml`](work-order-worker.toml).
- Independent review: [`independent-verifier.md`](independent-verifier.md), metadata [`independent-verifier.toml`](independent-verifier.toml).

The Markdown files define task behavior and return format; the TOML files are descriptive metadata only. This repository/runtime does **not** load them as executable agent configuration, select models from them, enable a backend, or grant permissions. Current backend availability remains exactly what `agents/AGENT_ROUTER.md` lists. In particular, these profiles do not fix an `LLM session not configured` dispatch failure.

The worker and verifier are distinct roles. A verifier must be separately invoked and receive no-edit instructions; runtime sandbox enforcement must not be claimed unless the selected backend actually provides it. `explore` remains discovery-only and is not a replacement verifier.
