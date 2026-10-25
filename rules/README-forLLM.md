# PADDOCK LRF Navigation

This file is navigation only, not an authority source. Authority and effect boundaries come from `rules/BOOTSTRAP.lrf`, matching PADDOCK LRF records, current-task instructions, and the ACCEPTED register as scoped by `AGENTS.md`.

For task work: read the active project bootstrap, classify task/effects, hydrate only matching records from `rules/MANUAL.lrf` and `rules/LOAD.lrf`, then follow `method.md` §§3–5. Missing/invalid links, unclassified effects, unresolved decision choices, or ambiguous target state require STOP and clarification.

- Project code work: `rules/engineering.lrf`, `agents/AGENT_ROUTER.md`, `agents/SUBAGENTS.lrf`, and `evaluation/worker-context-priority.json`.
- Skill contract scan/repair only: `rules/SKILL.lrf`.
- State vocabulary and durable cursor: `rules/state.lrf`, `Issues.md`.
- Run `python3 scripts/lint_design.py` before selecting work and after document changes. Generated dependency index is emitted only by `python3 scripts/lint_design.py --emit-summary`.
- This project has no trusted CI attestation unless a concrete CI receipt is observed. Do not infer verification from issue prose or worker reports.
