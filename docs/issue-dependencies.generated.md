# PADDOCK — Generated Issue Dependency Index

> AUTO-GENERATED. **DO NOT EDIT**. Source: `Issues.md`.
> Generator: `python3 scripts/lint_design.py --emit-summary`.
> 中目標への集約は表示専用。**依存DAGは小目標IDでのみ成立**。
> Issues.md SHA-256: `be39a1c75ee19a1c773ef4147c6791a68595f35efed4b48602e2908dda4db38a`

**小目標: 89件 / 依存辺: 152本 / 中目標: 16領域。**

| 中目標 | 小目標数 |
|---|---:|
| M00 | 8 |
| M01 | 6 |
| M02 | 6 |
| M03 | 6 |
| M04 | 6 |
| M05 | 5 |
| M06 | 8 |
| M07 | 7 |
| M08 | 5 |
| M09 | 4 |
| M10 | 5 |
| M11 | 4 |
| M12 | 5 |
| M13 | 3 |
| M14 | 4 |
| M15 | 7 |

| Issue | 状態 | `depends_on` |
|---|---|---|
| `PDK-M00-S01` | `[x]` | none |
| `PDK-M00-S02` | `[x]` | `PDK-M00-S01` |
| `PDK-M00-S03` | `[x]` | `PDK-M00-S02` |
| `PDK-M00-S04` | `[x]` | `PDK-M00-S03` |
| `PDK-M00-S05` | `[x]` | `PDK-M00-S01` |
| `PDK-M00-S06` | `[x]` | `PDK-M00-S05` |
| `PDK-M00-S07` | `[ ]` | `PDK-M00-S02`, `PDK-M00-S06` |
| `PDK-M00-S08` | `[x]` | `PDK-M00-S01` |
| `PDK-M01-S01` | `[x]` | `PDK-M00-S02` |
| `PDK-M01-S02` | `[x]` | `PDK-M01-S01` |
| `PDK-M01-S03` | `[x]` | `PDK-M01-S01` |
| `PDK-M01-S04` | `[x]` | `PDK-M01-S02` |
| `PDK-M01-S05` | `[x]` | `PDK-M00-S05`, `PDK-M01-S06` |
| `PDK-M01-S06` | `[x]` | `PDK-M01-S01`, `PDK-M00-S06` |
| `PDK-M02-S01` | `[x]` | `PDK-M01-S05`, `PDK-M02-S05` |
| `PDK-M02-S02` | `[x]` | `PDK-M02-S01` |
| `PDK-M02-S03` | `[x]` | `PDK-M02-S01` |
| `PDK-M02-S04` | `[x]` | `PDK-M02-S02`, `PDK-M02-S03`, `PDK-M02-S06` |
| `PDK-M02-S05` | `[x]` | `PDK-M00-S02`, `PDK-M00-S06` |
| `PDK-M02-S06` | `[x]` | `PDK-M02-S01`, `PDK-M01-S06` |
| `PDK-M03-S01` | `[x]` | `PDK-M01-S02`, `PDK-M02-S06` |
| `PDK-M03-S02` | `[x]` | `PDK-M03-S01`, `PDK-M02-S02` |
| `PDK-M03-S03` | `[x]` | `PDK-M03-S01` |
| `PDK-M03-S04` | `[x]` | `PDK-M03-S02`, `PDK-M05-S01` |
| `PDK-M03-S05` | `[x]` | `PDK-M03-S01`, `PDK-M06-S07` |
| `PDK-M03-S06` | `[x]` | `PDK-M03-S01` |
| `PDK-M04-S01` | `[x]` | `PDK-M03-S02`, `PDK-M03-S04`, `PDK-M04-S02`, `PDK-M06-S01`, `PDK-M06-S02` |
| `PDK-M04-S02` | `[x]` | `PDK-M03-S05`, `PDK-M03-S02` |
| `PDK-M04-S03` | `[~]` | `PDK-M04-S01`, `PDK-M04-S02` |
| `PDK-M04-S04` | `[x]` | `PDK-M04-S01` |
| `PDK-M04-S05` | `[~]` | `PDK-M04-S02`, `PDK-M04-S04` |
| `PDK-M04-S06` | `[ ]` | `PDK-M04-S05`, `PDK-M03-S03` |
| `PDK-M05-S01` | `[x]` | `PDK-M02-S01` |
| `PDK-M05-S02` | `[x]` | `PDK-M05-S01` |
| `PDK-M05-S03` | `[x]` | `PDK-M05-S02`, `PDK-M03-S01` |
| `PDK-M05-S04` | `[x]` | `PDK-M05-S03` |
| `PDK-M05-S05` | `[x]` | `PDK-M05-S01`, `PDK-M00-S08` |
| `PDK-M06-S01` | `[x]` | `PDK-M01-S01`, `PDK-M02-S01`, `PDK-M06-S07`, `PDK-M06-S08` |
| `PDK-M06-S02` | `[x]` | `PDK-M06-S01` |
| `PDK-M06-S03` | `[x]` | `PDK-M06-S02` |
| `PDK-M06-S04` | `[x]` | `PDK-M06-S02`, `PDK-M06-S03` |
| `PDK-M06-S05` | `[~]` | `PDK-M00-S06`, `PDK-M02-S06` |
| `PDK-M06-S06` | `[x]` | `PDK-M06-S05`, `PDK-M06-S01` |
| `PDK-M06-S07` | `[x]` | `PDK-M00-S06` |
| `PDK-M06-S08` | `[x]` | `PDK-M00-S06` |
| `PDK-M07-S01` | `[x]` | `PDK-M04-S01`, `PDK-M06-S02` |
| `PDK-M07-S02` | `[x]` | `PDK-M07-S01`, `PDK-M06-S03` |
| `PDK-M07-S03` | `[~]` | `PDK-M07-S02`, `PDK-M07-S06` |
| `PDK-M07-S04` | `[~]` | `PDK-M07-S03`, `PDK-M07-S07`, `PDK-M06-S06` |
| `PDK-M07-S05` | `[x]` | `PDK-M07-S04` |
| `PDK-M07-S06` | `[x]` | `PDK-M07-S02`, `PDK-M03-S06` |
| `PDK-M07-S07` | `[~]` | `PDK-M01-S06`, `PDK-M07-S01`, `PDK-M06-S05`, `PDK-M02-S06` |
| `PDK-M08-S01` | `[x]` | `PDK-M01-S03`, `PDK-M03-S02` |
| `PDK-M08-S02` | `[x]` | `PDK-M08-S01` |
| `PDK-M08-S03` | `[x]` | `PDK-M08-S02` |
| `PDK-M08-S04` | `[~]` | `PDK-M08-S03` |
| `PDK-M08-S05` | `[x]` | `PDK-M08-S03`, `PDK-M03-S06` |
| `PDK-M09-S01` | `[x]` | `PDK-M08-S01` |
| `PDK-M09-S02` | `[x]` | `PDK-M09-S01` |
| `PDK-M09-S03` | `[x]` | `PDK-M08-S03`, `PDK-M09-S01` |
| `PDK-M09-S04` | `[ ]` | `PDK-M09-S01`, `PDK-M08-S04` |
| `PDK-M10-S01` | `[x]` | `PDK-M06-S01` |
| `PDK-M10-S02` | `[~]` | `PDK-M10-S01`, `PDK-M08-S03` |
| `PDK-M10-S03` | `[x]` | `PDK-M10-S01` |
| `PDK-M10-S04` | `[x]` | `PDK-M10-S03`, `PDK-M11-S02` |
| `PDK-M10-S05` | `[x]` | `PDK-M10-S01`, `PDK-M00-S05` |
| `PDK-M11-S01` | `[x]` | `PDK-M06-S01`, `PDK-M10-S03` |
| `PDK-M11-S02` | `[x]` | `PDK-M11-S01` |
| `PDK-M11-S03` | `[x]` | `PDK-M11-S02`, `PDK-M06-S02` |
| `PDK-M11-S04` | `[-]` | `PDK-M11-S03` |
| `PDK-M12-S01` | `[ ]` | `PDK-M10-S03` |
| `PDK-M12-S02` | `[ ]` | `PDK-M12-S01`, `PDK-M11-S02` |
| `PDK-M12-S03` | `[ ]` | `PDK-M12-S02` |
| `PDK-M12-S04` | `[ ]` | `PDK-M12-S03`, `PDK-M01-S03` |
| `PDK-M12-S05` | `[ ]` | `PDK-M00-S05`, `PDK-M12-S02` |
| `PDK-M13-S01` | `[~]` | `PDK-M08-S02` |
| `PDK-M13-S02` | `[ ]` | `PDK-M12-S03`, `PDK-M08-S01` |
| `PDK-M13-S03` | `[ ]` | `PDK-M13-S01`, `PDK-M14-S01` |
| `PDK-M14-S01` | `[ ]` | `PDK-M05-S01` |
| `PDK-M14-S02` | `[ ]` | `PDK-M14-S01` |
| `PDK-M14-S03` | `[ ]` | `PDK-M14-S01` |
| `PDK-M14-S04` | `[ ]` | `PDK-M00-S07`, `PDK-M14-S01` |
| `PDK-M15-S01` | `[ ]` | `PDK-M02-S04`, `PDK-M04-S01`, `PDK-M15-S06` |
| `PDK-M15-S02` | `[ ]` | `PDK-M15-S01`, `PDK-M07-S01` |
| `PDK-M15-S03` | `[ ]` | `PDK-M15-S02`, `PDK-M07-S04` |
| `PDK-M15-S04` | `[ ]` | `PDK-M15-S03`, `PDK-M04-S06`, `PDK-M05-S04`, `PDK-M15-S07` |
| `PDK-M15-S05` | `[ ]` | `PDK-M15-S04`, `PDK-M14-S04`, `PDK-M01-S05` |
| `PDK-M15-S06` | `[x]` | `PDK-M02-S05`, `PDK-M03-S01`, `PDK-M00-S08` |
| `PDK-M15-S07` | `[ ]` | `PDK-M15-S03`, `PDK-M15-S06` |
