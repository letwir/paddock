# PIDGEN CSS-like supplement (NON-NORMATIVE)

This file is a separate display, wording, and retrieval aid. It has **no effect** on behavior, authority, permission, acceptance, or decision state. Normative contracts, prohibitions, permissions, and authority reside only in atomic SIGMA/1 LRF records.

## Display vocabulary

- **Contract** — display label for normative obligations; consult `formal.contracts-lrf` and the applicable contract records.
- **Process** — display label for ordered procedures; consult the applicable LRF records before interpreting a sequence.
- **Reference-state** — display label for status, decisions, or descriptive state; the label itself does not establish a decision.
- **Handoff** — display label for a task envelope or transfer; the wrapper and notation do not grant authorization.
- **Display** — presentation-only wording, typography, and retrieval cues.

## CSS-like notation

The following is illustrative presentation vocabulary only; each nature is a nonnormative presentation label, not a permission or contract source. This is not a stylesheet language, parser contract, or normative syntax:

```text
nature: contract | process | reference-state | handoff | skill-like | display
attention: text-label + optional emoji overlays
retrieval: multilingual aliases → same locally declared canonical concept
```

English, Japanese, Chinese, and Spanish terms may serve as lexical/retrieval variants where their scope is declared. Math relation symbols require local definitions and prose for critical meaning. Emoji are additive, non-exclusive discovery overlays; neither symbols nor visual styling carry hidden authority or exclusive meaning.

### HANDOFF binding display cue (NON-NORMATIVE)

Display an explicitly declared word or emoji binding as `bind(name;type;meaning;value;scope=HANDOFF)` and later references as `ref(name)`. Immutable, HANDOFF-local semantics—including allowed scope, provenance, and prohibited rebinding or cross-HANDOFF use—are defined only by the normative `formal.handoff.bindings` record; this display cue adds no variable behavior. Keep the SIGMA/1 envelope and field order unchanged.

## Category lens (NON-NORMATIVE display aid)

Category, functor, and natural-transformation cues may be used only to display the record-stage path and its comparison with the Acceptance-schema path. The stable normative source is `formal.category-handoff`; this vocabulary does not add semantics to that record. In particular, a diagram or natural-transformation cue cannot imply PASS, evidence, approval, authority, identity, or effects. It describes mappings only; Runner observations and independent review remain separate.

## Budget ledger delta display (NON-NORMATIVE)

For display and retrieval, an explicit-delta budget journal row may be presented per account with `operation` / `event_seq`, the signed counter deltas `granted_delta`, `spent_delta`, `reserved_delta`, and `delegated_delta`, and optional `allocation_id`. Use this vocabulary to help readers find and inspect the journal representation; it is not a schema definition or a complete row specification.

This section is a display/retrieval aid only. The SQL schema and the normative LRF record [`persistence.ledger-deltas`](engineering.lrf) define the canonical representation and reconstruction requirement. This Markdown section cannot specify or change behavior, acceptance criteria, permissions, or authority.

## Related normative records

- `formal.llm-docs` — LLM-primary document style and multilingual lexical base.
- `formal.doc-structure` — parseable document structure.
- `formal.attention`, `formal.pidgen.emoji` — attention and emoji discovery cues.
- `formal.pidgen.lexicon`, `formal.pidgen.relations` — lexical and relation notation.
- `formal.contracts-lrf`, `formal.no-authority` — normative source and authority boundary.
- `formal.category-handoff` — normative lifecycle category lens; category/functor/natural-transformation display cues here remain NON-NORMATIVE and cannot imply PASS, evidence, approval, or authority.
- `formal.handoff.bindings` — normative HANDOFF-local immutable bindings; this file's display cue is NON-NORMATIVE only.
- `formal.skill-style` — SKILL.md-like formatting cues are NON-NORMATIVE, style-only inspiration; they import or grant no authority or policy.

The cascade is discover-only: [PIDGEN cascade sequence](PIDGEN-CASCADE.seq). Normative records are in [HANDOFF-FORMAL.lrf](HANDOFF-FORMAL.lrf).

L|css.formal|file:rules/HANDOFF-FORMAL.lrf|MUST|RO_LOCAL|[normative PIDGEN notation rules](HANDOFF-FORMAL.lrf)
L|css.cascade|file:rules/PIDGEN-CASCADE.seq|MUST|RO_LOCAL|[discover-only PIDGEN cascade](PIDGEN-CASCADE.seq)
