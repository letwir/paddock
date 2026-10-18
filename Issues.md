# PADDOCK — Issues.md

> SIGMA/1: PIDGEN/text · Work Queue / Durable Resume State
> Snapshot: 2026-10-12 · Revision: design-review/2 · Repo: PADDOCK (independent) · State vocabulary: `[ ] [-] [~] [*] [x]`
> **注意:** 以下は新リポジトリの実装計画。過去の会話で提示されたGo/DDLを実装済みと扱わない。

## 0. 状態と更新規則

- `[ ]` TODO: 未着手、証拠なし。
- `[-]` WIP: 対象と作業者を記録して着手済み。中断時は未検証の可能性。
- `[~]` IMPLEMENTED: 期待する変更は存在するが検証がまだ不十分。
- `[*]` TESTED: 受け入れ検証がPASSしたが独立レビュー/終端記録が残る。
- `[x]` DONE: 受入条件、検証証拠、影響範囲を確認して確定。
- `BLOCKED`はチェックボックスの代わりにしない。対応する小目標に `blocker:` を書き、Cursorを`BLOCKED`にする。
- 各小目標のIDは不変。実装手段が変わっても同じ成果目的ならIDを保持し、目的が変われば新IDを発行。既存IDは使い回さない。
- 各小目標の`depends_on`は小目標IDで指定する。依存が完了していない場合は別のREADYな小目標を選ぶ。
- `evidence_expected`は**将来必要な証拠**であり現在存在する証拠ではない。
- 詳細設計の追補はReview時点で**DESIGN_BASELINE / 提案**。各Issueは実装済みではなく、確定Decisionの追加を意味しない。
- 中目標の表に書いたものを依存DAGと解釈してはいけない。**`depends_on`の小目標有向DAGだけが実行順序の正本**。`python3 scripts/lint_design.py --emit-summary`で集約結果を生成する。
- 高リスクな外部変更（Remote Push・本番DB・秘密情報・課金・公開）は、このIssueだけを根拠に実行しない。作業時の許可境界を別に確認する。

## 1. Durable Cursor（continueの唯一の案内位置）

```yaml
cursor_schema: paddock.cursor/1
snapshot_date: 2026-10-12
project: PADDOCK
repository_root: .
phase: MAIN_DESIGN_REVISION
active_goal: M14
active_issue: PDK-M14-S01
issue_state: TODO
execution_state: NOT_STARTED
current_branch: main
verified_commit: NONE
last_receipt: NONE
last_verified_test: "PDK-M05-S05 completed under D-016 local Runner and separate read-only source review. Receipt: receipts/PDK-M05-S05/2026-10-18-local-verification.json. CI attestation absent."
next_action: "The requested completed-Issue commit/push is prepared from a curated snapshot excluding M13-S01 WIP and .build/nested-repository artifacts; M08-S04 remains [~] with only its explicitly authorized shared dependency subset. After remote push verification, begin dependency-ready PDK-M14-S01 design/effect-scope preflight. Do not change protected-branch/CODEOWNERS settings without separate exact approval."
confidence: "PDK-M05-S03/S04/S05 are DONE under D-016 local Runner, independent review, and Main reconciliation. Branch HEAD remains unchanged; worktree has broad tracked/untracked changes. No commit/push has been performed; CI attestation absent."



```

**Cursorは作業の検索ヒントであり、観測したGit/ファイル/Receiptより優先されない。** `verified_commit`は**Cursor自身を含む現在の書込みより前に、外部検証で確定したCommit**しか指せない。自己参照のHashは書かない。 通信断・プロセス停止後の再開手順は[method.md](method.md)の`CONTINUE/1`を正本とする。新しい作業を始める前にCursorを更新し、実装の途中で止まれば`[-]`を維持。最後に本当に実行した検査とHash/Commitだけを記載する。

## 2. 中目標一覧（**依存DAGではない**）

| 中目標 | 領域 | Phase | 優先 | 再開の入口 |
|---|---|---|---|---|
| M00 | 独立Repo・Decision保護・Threat Model | P0 | P0 | S01, S05 |
| M01 | Domain・Epoch・状態モデル検査 | P0 | P0 | S01, S05, S06 |
| M02 | DB環境・Migration・Role/制約 | P0 | P0 | S05 → S01 |
| M03 | pgx Repository・DB時刻 | P0 | P0 | S01 |
| M04 | Command・Application・Negative Receipt | P0 | P0 | S02, S05 |
| M05 | Event・Outbox/Inbox・保持規則 | P0/P1 | P0 | S01, S05 |
| M06 | Safety Plane・署名・Kernel・Approval | P0 | P0 | S05, S07, S08 |
| M07 | Epoch・Canary・Liveness・Rollback | P0 | P0 | S01, S06, S07 |
| M08 | WorkOrder DAG・Pull・Lease/DB時刻 | P1 | P1 | S01 |
| M09 | Escrow Budget・Checkpoint | P1 | P1 | S01 |
| M10 | Open Enrollment・Credential・DoS | P1 | P1 | S01, S05 |
| M11 | Evidence Graph・Trust Engine | P1 | P1 | S01 |
| M12 | Sandbox・SKILL Supply Chain | P2 | P1 | S01, S05 |
| M13 | NAYA・Steward・GUI/CUI | P2 | P2 | S01 |
| M14 | Audit・Trusted CI Receipt | P0/P1 | P1 | S01, S04 |
| M15 | PoC Harness・E2E・Fault Injection | P0 | P0 | S06, S01 |

**依存関係の正本:** 各小目標の`depends_on`。中目標単位に集約すると逆向きの辺が存在し得るため、表から中目標DAGを推測しない。`docs/issue-dependencies.generated.md`は `scripts/lint_design.py --emit-summary` によって生成する**派生物**で、依存関係の手編集は禁止する。

---

## 3. 詳細設計ごとの中目標・小目標

### M00 / P0 / 独立リポジトリ・設計の正本

**中目標:** `.HARNESS`から独立したPADDOCKのDecision/Queue/Methodを再現可能に保つ。

- [x] `PDK-M00-S01` — 3正本+READMEの初期内容を用意する。
  - `depends_on`: none
  - `acceptance`: D-001〜D-014が記載され、レビュー追補はDESIGN_BASELINEとして識別でき、READMEから脅威モデル・Issues・Methodへ到達できる。
  - `evidence_expected`: Markdownの存在、リンク検査、Decision ID重複検査、内容Hash。
  - `current_evidence`: 2026-10-13のローカル検証でD-001〜D-014の14件、DESIGN_BASELINE区分、README内リンク、89件/148辺の依存Lintを確認。ユーザー承認のローカル検証方式により別プロセスから `python3 -m unittest discover -s tests -v` (6/6 PASS), `python3 scripts/lint_design.py` (PASS, 89 issues/148 edges), `git diff --check` (PASS) を再実行し、文書受入条件を確認。HEAD `3be9c43b5d7f16bc8e68dda81d36e1c3d14459dd`、作業ツリー変更: `Issues.md`, `docs/issue-dependencies.generated.md`, `tests/test_lint_design.py`、テストファイルSHA-256 `ead4f28595d199473ee9e7cf826ba009793d012691b79932e4538d978ea9086d`。これはローカル検証でありTrusted CI/remote attestationではない。
- [x] `PDK-M00-S02` — PADDOCKが独立したGit Rootであることを再現可能に確認する。
  - `depends_on`: PDK-M00-S01
  - `acceptance`: PADDOCK自身が`git rev-parse --show-toplevel`で独立Git Rootとして識別され、そのRootのパス文字列が明示した親Repo Root配下ではないことを確認する。既存`.HARNESS`の状態は未観測であり、受入条件の対象外。
  - `evidence_expected`: PADDOCKでの`git rev-parse --show-toplevel`結果と`tests/test_s02_repo_boundary.py`のルート同定・パス関係テスト。
  - `current_evidence`: `tests/test_s02_repo_boundary.py` confirms `git rev-parse --show-toplevel` resolves to PADDOCK root and path-string ancestry check is false for the configured parent boundary. Focused tests 3/3 PASS; full Python suite 18/18 PASS; design lint 89 issues/148 edges PASS; `git diff --check` PASS. Independent read-only source review confirmed implementation and scope; the verifier could not independently execute commands in its environment. `.HARNESS` state remains unobserved and outside acceptance after user-authorized criteria revision.
- [x] `PDK-M00-S03` — 文書を変更する時の追跡契約を導入する。
  - `depends_on`: PDK-M00-S02
  - `acceptance`: Decision IDは重複せず、supersedes参照は既存の異なるDecision IDを指す。Issue ID/DAG/Cursorの整合を検査し、last_receiptがNONEか許可Root内の存在するpaddock.receipt/1文書でactive Issue IDと一致することを再実行可能に検査する。Receipt構造のLintは発行者や結果の信頼性を証明しない。
  - `evidence_expected`: malformed supersede、Issue ID/DAG、欠落/escape/不正Schema/wrong Issue receipt、Cursor fixtureの負例テストとLint Exit Code。
  - `current_evidence`: `scripts/lint_design.py` checks append-only sequential unique D IDs, section-scoped supersedes targets (rejecting unknown and self-targets), Cursor↔Issue state (including missing state), and structural Receipt path/schema/active-Issue references with resolved in-repository path containment while explicitly not authenticating receipts. `tests/test_s03_tracking_contract.py` adds twelve clean/negative mutation tests including missing/invalid/escaped/symlink Receipt references, unregistered/mismatched receipt issue, missing state, and supersedes failures. Full local Python suite 30/30 PASS; `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `git diff --check` PASS. Independent read-only review checked current sources; an initial reported receipt mismatch was disproved by rereading the actual active cursor (S04 matches the fixture). Receipt validation is structural only, not authenticity or complete schema proof.
  - `current_evidence_addendum`: After current Issue records gained local receipt links and localized README routes, the disposable mutation fixture was corrected to copy exact referenced local Markdown targets before linting. Main Runner `python3 -m unittest tests.test_lint_design -v` PASS (8/8); full `python3 -m unittest discover -s tests -q` PASS (184/184). Separate read-only Verifier reviewed the four tracking/resume test fixtures and current linter anchors; no actionable findings. This is local test-fixture behavior only, no DB/runtime claim.
- [x] `PDK-M00-S04` — `CONTINUE/1`を模擬通信断で演習する。
  - `depends_on`: PDK-M00-S03
  - `acceptance`: `tests/test_s04_continue_resume.py` must simulate interruption in a disposable fixture, then launch a fresh subprocess with no session memory; it selects the same active WIP Issue, and rejects changing unverified WIP to DONE. No claim of actual network/process crash is required.
  - `evidence_expected`: Test-captured before/after Cursor snapshots, controlled unverified-work diff, and subprocess command/stdout/exit-code log in disposable fixture; test report and local verifier review.
  - `current_evidence`: `tests/test_s04_continue_resume.py` uses a disposable temp repository, captures identical before/after Cursor text, creates a controlled unverified WIP artifact and unified diff, then executes `continue_plan.py` in a fresh subprocess and records command/stdout/exit status in temporary JSON; it asserts S04 remains WIP and is selected. Independent verifier confirmed this meets the revised simulated-interruption acceptance and independently ran focused tests 5/5, full suite 35/35, design lint PASS (89 issues/148 edges), planner CLI exit 0 (active S04), and `git diff --check` PASS at HEAD `9d6296b17c9b569e7f010fe7c30755a94ff0042f`. Local simulation only; not a real crash or CI attestation.

  - `current_evidence_addendum`: Restart fixture now sets `execution_state=IMPLEMENTING_SOURCE_ONLY_MAIN` when its synthetic Cursor is WIP, avoiding the invalid `NOT_STARTED`+WIP combination; it copies linked receipt/README targets for isolated lint. Main Runner full Python unittest suite PASS (184/184). Separate read-only Verifier reviewed the restart fixture and reported no actionable findings.
- [x] `PDK-M00-S05` — 脅威モデルの設計とTrust Boundaryのレビュー。
  - `depends_on`: PDK-M00-S01
  - `acceptance`: [`THREAT_MODEL.md`](THREAT_MODEL.md)を入力として、Prompt Injection、SKILL/Go依存Supply Chain、Open Enrollment DoS、Sybil、権限/DB/時刻/鍵喪失を資産・入口・境界・緩和・残余リスクに分離する。全Threat行で各要素と受入Issue参照を明示する。
  - `evidence_expected`: Threat Model差分、脅威ID参照の整合検査、Verifierレビュー。
  - `current_evidence`: Threat Model全15行に資産・入口/Trust Boundary・緩和・残余リスクを追加し、Issue参照を保持。`tests/test_lint_design.py`に表構造・列検査を追加。別プロセスで`python3 -m unittest discover -s tests -v` 7/7 PASS、`python3 scripts/lint_design.py` PASS (89 issues/148 edges)、`git diff --check` PASS。独立ローカルレビューで全15行の欄とIssue参照を確認。HEAD `3be9c43b5d7f16bc8e68dda81d36e1c3d14459dd`。ローカル検証のみ（Trusted CI/remote attestationではない）；緩和策の実装有効性・ペンテストは未検証。
- [x] `PDK-M00-S06` — Bootstrap信頼根・O-002/O-003・Safety Plane方針の設計Gate。
  - `depends_on`: PDK-M00-S05
  - `acceptance`: PoC鍵の範囲・DBセットアップ条件・Emergency Stopの発火/解除経路・組込みSafe Baselineの境界を設計基準として記録。未決の運用値はOPENのまま残す。
  - `evidence_expected`: Bootstrap設計レビュー、対応するO-002/O-003/O-010の解決Issueリンク。
  - `current_evidence`: `docs/bootstrap-safety.md` defines disposable PoC-only approval key scope; isolated non-production DB boundary and fail-closed behavior; human Emergency Stop trigger/enforcement/release; embedded Safe Baseline; and explicit OPEN links O-002→PDK-M06-S08, O-003→PDK-M02-S05, O-010→PDK-M06-S05. README links the baseline. `tests/test_lint_design.py::test_s06_bootstrap_safety_boundaries` checks key clauses and unresolved links. Independent local verifier confirmed all stated dimensions and ran `python3 -m unittest discover -s tests -v` (8/8 PASS), `python3 scripts/lint_design.py` (PASS, 89 issues/148 edges), `git diff --check` (PASS), HEAD `3be9c43b5d7f16bc8e68dda81d36e1c3d14459dd`. Local-only verification; no CI/remote attestation. Design does not grant production DB access or credentials.
- [ ] `PDK-M00-S07` — `decisions.md`の承認証拠と保護を確立する。
  - `depends_on`: PDK-M00-S02, PDK-M00-S06
  - `acceptance`: CODEOWNERS、保護Branch、署名・人間承認者とDecision supersedeの履歴を確定。初期転記を人間が検査し署名付きCommitへ関連付ける。WorkerによるACCEPTED直書きを認可しない。
  - `evidence_expected`: Git設定/CIログ/承認Commit SHA・日時・署名者照合。リモート機能未設定ならBLOCKED。
  - `blocker`: Current user has authorized push but not GitHub branch-protection/CODEOWNERS setting mutations. Protected branch, authorized reviewers, and signed human approval commit cannot be evidenced from PADDOCK-local source. Resume when user explicitly authorizes the exact remote settings action or a repository-local prerequisite can be completed without claiming protection.
- [x] `PDK-M00-S08` — Issue小目標DAGと文書参照の再現可能Lint。
  - `depends_on`: PDK-M00-S01
  - `acceptance`: Issue ID重複・Dangling Dependency・Cycle・OPEN解決Issue欠落・Markdown参照・Cursor不整合を検出。中目標一覧を手作業の依存グラフ扱いしない。
  - `evidence_expected`: `scripts/lint_design.py` のExit Code、生成集約表、故障Fixture。
  - `current_evidence`: `tests/test_s08_acceptance.py` adds mutation fixtures for duplicate Issue ID, dangling dependency, cycle, OPEN without concrete resolver, broken Markdown link, Cursor status mismatch, and derived summary/hash behavior. Independent local verifier reran full unittest suite (15/15 PASS), `python3 scripts/lint_design.py` (PASS, 89 issues/148 edges), and `git diff --check` (PASS), HEAD `3be9c43b5d7f16bc8e68dda81d36e1c3d14459dd`. Local-only verification; no remote CI attestation.


### M01 / P0 / Go Domain型・実行契約

**中目標:** DB/LLMに依存しない状態機械をContract Firstで実装する。

  - `current_evidence_addendum`: The broken-link mutation now edits the route README link `README-en.md` rather than assuming the root README links directly to THREAT_MODEL; fixture copies referenced local link files. Main Runner full Python unittest suite PASS (184/184). Separate read-only Verifier reviewed the mutation and current link checker; no actionable findings.
- [x] `PDK-M01-S01` — `Digest`, `Epoch`, `Scope`, `Rollout`, `RolloutState`とエラー型を定義。
  - `depends_on`: PDK-M00-S02
  - `acceptance`: `SHADOW → CANARY → MONITORING → COMPLETED`と`CANARY/MONITORING → ROLLING_BACK → ROLLED_BACK/SAFE_STOPPED`を表現。HOLDは監視結果/保留状態であり無期限待機にしない。
  - `evidence_expected`: Domain型、Go unit tests、`go test` Exit Code。
  - `current_evidence`: `internal/governance/domain/types.go` defines SHA-256 Digest parsing/validation, overflow-safe Epoch increment, Scope/Rollout identifiers and values, accepted rollout states, and separate finite monitoring decisions (HOLD is not a state). Local Runner observed `GO111MODULE=off go test ./internal/governance/domain -count=1` exit 0; Python suite `python3 -m unittest discover -s tests -q` 35/35 PASS; `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `git diff --check` exit 0; `gofmt -d` produced no output. Independent read-only review found no concrete acceptance gaps. Source SHA-256: types.go `d9272e2467d994af60a3c89017a59672665a65ef6fbfd8aa9df20bc3d8064224`, types_test.go `d2e3500f831a3ef9c63b702382da544a0888cbd1ac4cefa5b00c0515a4e622d7`. Observed base HEAD `0f46640f3a5c9b6e86abb5894187d7d416d57fc9`; local tests/review only, no remote CI attestation.
- [x] `PDK-M01-S02` — `StartCanary/EffectivePolicy/Promote/Rollback`の純粋遷移。
  - `depends_on`: PDK-M01-S01
  - `acceptance`: Scope Epoch 40→41→42→43のFixtureに加え、Root A/B別の認可EpochとSecurity Epochが独立。Rollback/Freezeが正しく反映される。
  - `evidence_expected`: Table-driven Tests、差分。
  - `current_evidence`: `internal/governance/domain/rollout.go` implements pure Scope-scoped Canary, Promote, and two-phase rollback. Main Runner verifies Scope Activation Epoch 40→41→42→43; Root B Canary preserves Root A policy/authz epoch; Security Epoch is independent and stale Security/Scope/Root snapshots are rejected; rollback freezes without epoch changes and final switch advances Scope and affected Root epochs once; invalid/unavailable LKG selects Safe Baseline; DB unavailable and Safe Baseline scopes fail closed; pure transitions preserve input snapshots. Runner commands: `GO111MODULE=off go test ./internal/governance/domain -count=1` PASS; `GO111MODULE=off go vet ./internal/governance/domain` PASS; `gofmt -d` empty; `git diff --check` PASS. Independent source review found and prompted fixes for stale Security Epoch and Safe Baseline promotion. SHA-256: rollout.go `693129a8bf89e2382a788a6673e4cccf4c3291874a56d919d215ac8169f098fd`, rollout_test.go `55319e442fe7dcc5f6eace07ef66c4500d0eeec2437ea35bc7df486eb74f1dec`. Earlier Python run failed on stale generated index; final suite status recorded after regeneration below. LKG usability remains an outer trusted-verifier input, not cryptographically established by this Domain package.
- [x] `PDK-M01-S03` — WorkOrder/Attempt/DependencyのDomainとDAG制約。
  - `depends_on`: PDK-M01-S01
  - `acceptance`: 所属Treeと実行DAGが分離、異RootのDependency・循環を拒否。
  - `evidence_expected`: Domain Test、禁止例Fixture。
  - `current_evidence`: `internal/governance/domain/work_order.go` separates parent-based WorkOrder ownership Trees from execution Dependency DAG edges. Tree validation checks unique WorkOrder IDs, valid Root IDs, parent existence and same-Root membership, exactly one top-level WorkOrder per Root, and that all parent chains terminate at their Root tree top. Dependency validation separately rejects invalid/duplicate node IDs, unknown endpoints, cross-Root edges, self/duplicate edges, and cycles, while allowing independent tasks and execution edges that differ from parent ownership. `Attempt.Validate` checks non-empty trimmed attempt ID, valid WorkOrder ID, and positive attempt number. Main Runner commands: `GO111MODULE=off go test ./internal/governance/domain -count=1` PASS; `GO111MODULE=off go vet ./internal/governance/domain` PASS; `gofmt -d` empty; `git diff --check` PASS; `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `python3 -m unittest discover -s tests -q` PASS (35/35). Independent source review found no concrete acceptance gap. SHA-256: work_order.go `7d3e37bfb25a6ee9df33150e320bccc0ce6122da64241842c918974bd250ba66`, work_order_test.go `684cdff608f331756aefef380f2ef1434c275fb6bb563747806c5e7c977f1027`. Evidence is local to the reviewed source revision; no CI/CD claim.
- [x] `PDK-M01-S04` — DomainとStorageの依存禁止を検査。
  - `depends_on`: PDK-M01-S02
  - `acceptance`: `internal/*/domain`はpgx/HTTP/LLMライブラリをimportしない。
  - `evidence_expected`: 静的検査/Go Test。
  - `current_evidence`: `tests/test_domain_dependency_boundary.py` scans Go files under `internal/**/domain` without traversing symlinks; tokenizes import declarations, aliases, comments, raw/quoted literals and Go string escapes; rejects listed database/SQL, network/HTTP, pgx/gRPC, and common LLM/provider SDK imports. Fixtures cover standard imports, forbidden single/grouped/aliased imports, comments, parentheses in paths, escaped forbidden `net/http`, arbitrary nested discovery, symlink exclusion, and dependency-edge synthetic cases. Main Runner focused unittest 5/5 PASS; full Python suite 40/40 PASS; `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `git diff --check` PASS. SHA-256: `tests/test_domain_dependency_boundary.py` `325fdbbcff339c6f233e0e2064daee86e61506fc9c73a4efd6bb7dd0d15b29ed`. Limitation: static denylist is not an exhaustive catalog of all future third-party providers or a full Go compiler/parser; CI/CD pipeline is not asserted available.

- [x] `PDK-M01-S05` — Rollout × Root/Scope/Security Epoch × Leaseを有限状態モデル検査。
  - `depends_on`: PDK-M00-S05, PDK-M01-S06
  - `acceptance`: INV-01/02/03/06、Rollback、Emergency Stop、HOLD/Monitoringの公平性仮定と限界をTLA+/Alloy等で明示。CounterexampleはIssueへ返す。
  - `evidence_expected`: Model Source、tool version、モデル探索ログ、Safety/Liveness結果。
  - `current_evidence`: `tests/test_rollout_model_check.py` explores the finite transition system (lease generation saturated to its two behaviorally distinct values) and checks INV-01/02/03/06, Root B Canary isolation, two-phase rollback epoch freeze/switch, human-only Emergency Stop, DB outage deny-progress, conditional bounded Monitoring/HOLD liveness under explicit fairness assumptions, and an unfair/stalled lasso counterexample. Mutants for stale-lease acceptance and agent-controlled stop are caught. Local Runner: `python3 -m unittest tests.test_rollout_model_check -v` PASS (6/6; 292 states/735 transitions; Python 3.14.6); `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `git diff --check` PASS. Full suite intentionally not rerun due prior OOM concern. Local Runner + separate verifier subagent + Main reconciliation satisfy D-016; CI attestation/Verifier-of-Record is absent and is not claimed. Conditional liveness is demonstrated by bounded traces under explicit fairness assumptions, not a universal temporal proof. Local model is Python, not TLA+/Alloy, and does not prove implementation correctness. CI attestation/Verifier-of-Record is absent; D-016 local verification path used: Runner executed focused tests and a separate verifier subagent independently reviewed the Issue acceptance, model, and evidence; Main reconciled the review and added the requested outage→human-stop deny-all assertion. Final Runner: focused suite 6/6 PASS, 292 states/735 transitions, Python 3.14.6; design lint PASS (89 issues/148 edges); `git diff --check` PASS. SHA-256 `tests/test_rollout_model_check.py`: `ae34dce65487aae6fccb1ce5b9cab2ecf2958fd5226a844dee8da488e6c0049c`; target repository revision: `c38b818578702bbc0bc40240dcd03341952c852e`. Conditional liveness is demonstrated by bounded traces under explicit fairness assumptions, not a universal temporal proof.
- [x] `PDK-M01-S06` — Epoch 3層・二相Rollback・Safety Modeの純粋状態契約。
  - `depends_on`: PDK-M01-S01, PDK-M00-S06
  - `acceptance`: `scope_activation_epoch`, `root_authz_epoch`, `security_epoch`を区別し、`ROLLING_BACK`はFreezeを開始、最終Policy切替時にScope/該当Root Epochを1回進める。LKG不可→Safe Baseline、DB断→Gateway denyをモデル化。
  - `evidence_expected`: Root A非波及、切替・凍結・再開の状態表/Unit Fixture。
  - `current_evidence`: `internal/governance/domain/safety.go` implements pure three-epoch AuthorityState transitions, Scope Freeze at rollback start without generation change, final LKG/Safe Baseline switch advancing Scope and only the target Root epoch exactly once, Emergency Stop advancing only Security Epoch, and fail-closed EffectivePolicy/Authorize on freeze, safe-stop, stale epoch/digest, or unavailable DB. `LKGAssessment` explicitly models the outer trusted verifier boundary; unavailable, invalid, malformed, or unknown status selects embedded Safe Baseline. Tests cover epoch independence, Root A/B isolation, freeze, finalized rollback, fallback, emergency stop, stale grants, and DB outage. Local Runner: `GO111MODULE=off go test ./internal/governance/domain -count=1` PASS; `GO111MODULE=off go vet ./internal/governance/domain` PASS; Python suite 35/35 PASS; design lint PASS (89 issues/148 edges); gofmt and `git diff --check` PASS. Independent read-only review found no acceptance gap after the LKG boundary correction. SHA-256: safety.go `694a323a0827e615b7c96f25bce55f9f932fb0b538a783af8515ec921a57d553`, safety_test.go `d8e435343337eccbe89bf3ce18703e1fa26480ec30b004a04f933029cf42be4`. Limitation: domain models the trusted verifier's LKG assessment but does not perform cryptographic verification or DB persistence; Android/arm64 Go race detector unavailable.


### M02 / P0 / PostgreSQL Migration・DDL

**中目標:** 初期状態から一発適用できるDDLとDB制約を提供する。

- [x] `PDK-M02-S01` — 初期Governance Migration (up/down)を設計・適用。
  - `depends_on`: PDK-M01-S05, PDK-M02-S05
  - `acceptance`: `policy_bundles`, `policy_scopes`, `roots`, `policy_rollouts`, `rollout_targets`, `governance_approvals`, `command_receipts`, `domain_events`, `event_outbox`, `event_inbox`, `security_generation`を整合した順序で作成/撤去。
  - `evidence_expected`: 専用DB `psql -v ON_ERROR_STOP=1` / migration runner Exit Code、Schema dump。
  - `current_evidence`: Existing `sql/init.sql` creates 11 base tables in FK-compatible order, including the deferred composite live-rollout FK; `sql/down.sql` drops that FK then all 11 tables in reverse dependency order, with exact paddock_test guard, ON_ERROR_STOP, transaction, no CASCADE/schema/database drop. Static tests expanded to cover all source FK edges, qualification, guard-before-DDL, and transaction/stop flags; `python3 -m unittest tests.test_m02_initial_migration -v` PASS 5/5. Live operation, explicitly authorized for current PADDOCK_DB_URL target after read-only inventory (paddock_test PG18.6, 11 tables, 14 indexes): down command exit 0/COMMIT; read-only post-down confirmed raw base-table count 0; guarded up command exit 0/COMMIT; read-only post-up confirmed all 11 expected raw base tables, missing=NONE; guarded --check reports raw_relations=25. Schema-only dump pipeline exit 0, digest `5fa0b4643eddf99ce2018dfe1681f674da9c03875d886225122184b4e2f80001`. Detailed non-secret Runner Receipt: `receipts/PDK-M02-S01/2026-10-13-pg18-up-down.json`. Data in the 11 tables was deleted and recreated as explicitly authorized; schema/database itself was not dropped. Current files: init.sql SHA-256 `31be5c80afe447a0a9eb7f88b3ec32b94c0bf463ff629d7df245c47f69427ec3`; down.sql `8aa6fd4bf04fca0673a7600eaf5774e7cabe0ade4d31feeb51cec9e87e65104a`; offline test `tests/test_m02_initial_migration.py` `3a1074c6a72253b2beede3d4253206ead98948985f31e9bdca299ab7c92a6a73`. Separate verifier subagent reviewed the durable Runner receipt and SQL source, confirmed hashes/commands/scope, and found no unmet acceptance clause. Main reconciled the review; [x] assigned under D-016. Residuals: worktree dirty (diff hash unavailable), schema dump hashed but not retained, no CI attestation; none is claimed.
  - `next_action`: User explicitly authorized down/recreate of current `PADDOCK_DB_URL` target after confirming it is `paddock_test`. Run the transaction-guarded down migration, verify empty `raw`, run guarded up migration, then verify all 11 base tables and schema dump. No database/schema drop; exactly the 11 named tables and their data are in scope.
- [x] `PDK-M02-S02` — Scope複合FK・Partial Unique Index・State制約。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: 違うScopeへのTarget、ScopeあたりActive Rollout二件をDB側が拒否。
  - `evidence_expected`: SQL負例/陽例テスト結果。
  - `current_evidence`: User selected HOLD remains a monitoring decision while persisted rollout state remains MONITORING; the active slot therefore remains occupied. Existing base composite FKs prevent cross-scope rollout/root targets. After explicit authorization and read-only duplicate preflight (0 conflicts), `sql/governance_constraints.sql` applied to paddock_test PG18.6 with exit 0/COMMIT. `tests/integration_m02_constraints.sql` demonstrated allowed multiple SHADOW and terminal rows, rejected second active rollout with unique_violation and cross-scope target with foreign_key_violation; script ended ROLLBACK, exit 0. Read-only postcheck confirmed index present and zero fixture rows remained. Offline tests 3/3 PASS; lint 89/148 and diff-check PASS. Receipt: `receipts/PDK-M02-S02/2026-10-13-constraints.json`. Separate verifier subagent reviewed the live receipt, migration, and integration fixture under D-016 and found the acceptance satisfied; Main reconciled that review with Runner evidence. Residuals: dirty diff hash unavailable and no CI attestation/Verifier-of-Record; neither is claimed. Database behavior is evidenced by Runner receipt, not rerun by independent verifier.
  - `next_action`: PDK-M02-S02 is DONE under D-016. PDK-M02-S03 is now DONE; continue with dependency-ready PDK-M02-S04 source/preflight review.
- [x] `PDK-M02-S03` — 不変Bundle/Eventと最小権限DBロール。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: 通常App RoleのUPDATE/DELETEを拒否。Migration Roleを分離。
  - `evidence_expected`: 権限テスト、トリガー/GRANT一覧。
  - `selected_scope`: User selected `jockey` as a trusted external DB administrator exception. Its observed `raw` schema USAGE/CREATE, `policy_scopes` SELECT/INSERT/DELETE, `roots` SELECT/INSERT/DELETE/REFERENCES, column UPDATE on `policy_scopes.scope_id`, and ownership of the seven named SECURITY INVOKER M02 trigger helper functions are accepted as external-admin privileges. `jockey` remains distinct from `paddock_app` and `paddock_migrator`, with no membership involving either. This is an acceptance interpretation, not permission for further ACL/role changes.
  - `current_evidence`: `sql/governance_roles.sql` requires exact pre-provisioned role names, rejects elevated attributes/memberships, transfers `raw` and all 11 baseline tables to `paddock_migrator`, revokes app relation/column ACLs, then grants app `USAGE` plus SELECT/INSERT only on `policy_bundles` and `domain_events`. Main Runner on 2026-10-17 observed `paddock_test` PostgreSQL 18.6 in explicit READ ONLY transactions: both roles are LOGIN/non-elevated, no memberships involving app/migrator, raw and all 11 baseline tables are migrator-owned, app raw CREATE=false, and app effective UPDATE/DELETE/TRUNCATE=false on all baseline tables. App relation ACLs are only SELECT/INSERT on the two named tables; app/PUBLIC column ACL count is zero. Current raw schema ACL also lists `jockey=USAGE,CREATE`; further readback found direct grants by migrator to jockey: policy_scopes SELECT/INSERT/DELETE, roots SELECT/INSERT/DELETE/REFERENCES, and column UPDATE on policy_scopes.scope_id. User accepted these as an external DBA exception. A later read-only function-owner query found seven SECURITY INVOKER trigger helper functions owned by `jockey` rather than `paddock_migrator`; all have fixed `search_path=pg_catalog`. The user subsequently accepted this function ownership as part of the jockey external-admin exception; no ownership change was made. Trigger inventory includes the two enabled frozen-rollback constraint triggers plus later M08/M09 append-only/integrity triggers; no bundle/event immutability triggers were observed, so the accepted app immutability boundary is privilege-enforced. `python3 -m unittest tests.test_m02_roles -v` PASS 10/10; `scripts/lint_design.py --emit-summary && scripts/lint_design.py` PASS 89/148. `sql/governance_roles.sql` was not applied in the catalog observation session. During a later isolated M02-S04 runner attempt, psql 18.6 rejected its old `\\error` missing-variable prelude before the roles file's BEGIN/DDL; the temporary cluster was cleaned and existing paddock_test was not targeted. The source now uses fail-closed `\\set` sentinels, `python3 -m unittest tests.test_m02_roles -v` PASS 11/11, and a separate source reviewer found no gap; corrected SQL has not been applied to DB.
  - `independent_review`: Separate source/security and final receipt review found no actionable acceptance gap after Main reconciled the selected jockey ACL/function-owner exception. A subsequent read-only review of the sentinel psql guard found no source gap; no psql apply of the corrected roles script is claimed. Verifiers did not access the database or reproduce live privileges.
  - `runner_receipt`: `receipts/PDK-M02-S03/2026-10-17-role-catalog-verification.json`
  - `d016_reconciliation_receipt`: `receipts/PDK-M02-S03/2026-10-17-d016-reconciliation.json`
  - `psql_guard_source_receipt`: `receipts/PDK-M02-S03/2026-10-17-psql-guard-source-fix.json`
  - `runtime_attempt_receipt`: `receipts/PDK-M02-S04/2026-10-17-runner-attempt.json`
  - `remaining_gate`: `NONE` for selected S03 acceptance under D-016 local verification. Residuals: jockey's ACLs and function ownership are accepted external-admin exceptions; official roles SQL was not applied in this run; no CI attestation; dirty diff hash unavailable.
  - `next_action`: PDK-M02-S03 is DONE locally. Next dependency-ready candidate is PDK-M02-S04 source/preflight review; no up/down/reset/drop DB execution without separate explicit scope.
- [x] `PDK-M02-S04` — 全Schemaの再構築・巻戻しを検証。
  - `depends_on`: PDK-M02-S02, PDK-M02-S03, PDK-M02-S06
  - `acceptance`: 空DBにup→down→upし、整合性エラーなし。テストDB以外は変更しない。
  - `evidence_expected`: Migrationログ、SQLSTATE、Exit Code。
  - `source_review`: The current populated `paddock_test` must not be used for `down.sql`; S03 append-only checkpoint/budget fixtures remain retained. `sql/down.sql` only drops the 11 M02 base tables after a database-name guard. The M02 safety down drops its two triggers/functions/check; the S02 partial index disappears with the base table. The roles/ownership migration has no down and role/schema ACL state persists through a same-database rebuild.
  - `selected_test_scope`: User selected a temporary local PostgreSQL cluster with a private Unix socket and an internal database named `paddock_test`; include M02-S01 `init.sql`, M02-S02 `governance_constraints.sql`, M02-S03 `governance_roles.sql`, and M02-S06 `governance_safety_constraints.sql`, then reverse S06 and the 11-table base, then reapply the M02 chain. M08/M09 migrations and fixtures are OUT OF SCOPE.
  - `runner_source`: Added `scripts/m02_s04_rebuild_test.sh` (mode 0700) and offline static contracts `tests/test_m02_rebuild_runner.py`. The runner defaults/help to no effects; `--run` uses only a private `.build/m02-s04.*` PostgreSQL cluster, Unix socket/no TCP, local trust, and explicit M02 migration order. It unsets PADDOCK DSNs/password/PG connection variables, asserts exact catalog/ACL state after first and second up, verifies down state, streams non-secret logs and Exit Codes, and cleans only its exact temporary cluster after confirmed shutdown.
  - `runner_source_receipt`: `receipts/PDK-M02-S04/2026-10-17-runner-source.json`
  - `current_evidence`: Static checks PASS: runner contracts 10/10, roles SQL contracts 11/11, `bash -n`, direct help/no-op, mode 0700, lint 89/148. One earlier unapproved `--run` attempt failed before role DDL/down and is disclosed in its own receipt. After the roles psql guard was corrected and a renewed one-run approval obtained, the final isolated runner completed all M02 up/down/up steps with Exit Code 0 and all catalog assertions passing.
  - `current_evidence`: Main Runner on 2026-10-17 executed the corrected `scripts/m02_s04_rebuild_test.sh --run` under explicit approval in a private Unix-socket PostgreSQL cluster with internal DB `paddock_test`. M02 init→constraints→roles→safety-up passed; safety-down→11-table base-down passed; re-up→roles→safety passed; every recorded step Exit Code 0 and both first/final catalog assertions passed. The runner stopped and removed only `.build/m02-s04.ouS6o6XBSd`; read-only search found no remaining temp cluster. Existing populated `paddock_test`/M09 fixtures were not targeted. The prior unapproved failed attempt is separately disclosed and did not reach role DDL or down. Receipt: `receipts/PDK-M02-S04/2026-10-17-runtime-verification.json`; CI absent, dirty diff hash unavailable.
  - `runner_attempt_receipt`: `receipts/PDK-M02-S04/2026-10-17-runner-attempt.json`
  - `source_independent_review`: A separate read-only Verifier found no source defect in the isolated runner or corrected role sentinel guard; no runtime reproduction.
  - `runner_runtime_receipt`: `receipts/PDK-M02-S04/2026-10-17-runtime-verification.json`
  - `runtime_independent_review`: A separate read-only Verifier reviewed the final runtime Receipt, source hashes, M02 step Exit Codes, temp-cluster isolation/cleanup, and prior failed-attempt disclosure; found no actionable acceptance gap. The Verifier did not rerun the database sequence.
  - `execution_boundary`: One prior `--run` attempt occurred without separately recorded approval; it was isolated, failed before role DDL/down, and its temp cluster was cleaned. After fixing psql `\\error`, the user explicitly approved exactly one corrected run; all work stayed in a private `.build/m02-s04.*` cluster, excluded M08/M09, and cleanup removed the exact temp cluster. Existing populated `paddock_test` and retained M09 data were not targeted. No additional runner invocation is authorized.
  - `main_reconciliation`: Main compared the Runner's per-step Exit Codes and postconditions, the corrected source hash, and the separate Verifier report. The explicitly approved corrected up/down/up pass satisfies the selected M02-only acceptance. The earlier unapproved attempt is disclosed separately and did not touch the existing DB or reach down.
  - `remaining_gate`: `NONE` for selected M02 up/down/up acceptance under D-016 local verification. Residuals: one earlier unapproved temp-cluster attempt failed before role DDL/down and is disclosed; no CI attestation; dirty diff hash unavailable.
  - `next_action`: PDK-M02-S04 is DONE under D-016 local verification. Do not rerun or target the existing database; the temporary cluster was removed. Continue with the next dependency-ready Issue after Cursor selection.

- [x] `PDK-M02-S05` — PoC Test DB・PostgreSQL版・Migration Runnerを確定（O-003解決）。
  - `depends_on`: PDK-M00-S02, PDK-M00-S06
  - `acceptance`: PG版、DSN secretの注入経路、テスト用Isolation、Migration実行コマンド、再作成/破棄ガードを決める。本番接続でテストを走らせない。
  - `evidence_expected`: テストDB起動/接続の実測、版表示、Migration Runner設定、環境変数名（秘密値なし）。
  - `current_evidence_addendum`: User selected “このPoC構成で確定”. O-003 configuration is resolved: observed PoC DB PostgreSQL 18.6; canonical operator-injected variable `PADDOCK_DB_URL`; psql-native guarded runner with read-only `--check` and explicit `--apply`; no automated drop/recreate; populated `raw` schema is refused. This is not a general PostgreSQL compatibility promise. `tests/test_init_test_db_script.py` passed 7/7 with fake `psql`, including read-only mode, wrong-database, existing-relations, invalid-version, no-action, help, and success-path guards. Runner re-executed tests 7/7; `scripts/init_test_db.sh --check` PASS (paddock_test, PostgreSQL 18.6, raw_relations=25). Separate read-only catalog query confirmed all 11 expected raw base table names present. `bash -n`, `--help`, no-action refusal, design lint, and `git diff --check` passed. The `--apply` path against an empty database was not run; the current database is populated and the runner refuses it. This is an additional residual, not an unmet acceptance clause. No automated drop/recreate path exists. Local Runner + separate verifier subagent + Main reconciliation satisfy D-016; CI attestation/Verifier-of-Record is absent and is not claimed.
  - `current_evidence`: Runner used the operator-injected `PADDOCK_DB_URL` without displaying it. Read-only query returned `current_database=paddock_test`, PostgreSQL `18.6 (Debian 18.6-1.pgdg13+2)`, `raw` exists, and 11 base tables exist. After explicit user authorization, `psql "$PADDOCK_DB_URL" -X -v ON_ERROR_STOP=1 -f sql/init.sql` began a transaction, passed the database guard and schema statement, then failed on existing `raw.policy_bundles`; follow-up read-only query confirmed 11 tables remained. Exact process Exit Code was not captured. No DROP or teardown occurred. `PADDOCK_DB_URL` is now the canonical test connection variable in `docs/database-test-environment.md`, `sql/init.sql`, `sql/create_database.sql`, and `scripts/init_test_db.sh`; `create_database.sql` refuses existing databases, while the initializer has no drop/recreate action and refuses a populated raw schema. A clean empty-database initialization run remains unverified. Same server/port as llm-memory is acceptable only with the separate `paddock_test` database.
- [x] `PDK-M02-S06` — Root別認可Epoch・Scope Freeze・Safe Baseline対応のDDL。
  - `depends_on`: PDK-M02-S01, PDK-M01-S06
  - `acceptance`: DB schema enforces Root/Scope/Security Epoch representation and local integrity, Scope Freeze/Safe Baseline modes, and same-scope Rollout/Root composite relationships. `FROZEN` is valid only for a same-scope `ROLLING_BACK` rollout; `SAFE_STOPPED` represents embedded deny-all without an extra Scope baseline column. Application CAS, stale-state comparison, and atomic epoch/state increments are owned by `PDK-M03-S02` / `PDK-M04-S01`, not this DDL issue.
  - `evidence_expected`: Migration and live positive/negative SQL tests for schema constraints plus controlled concurrent freeze/rollback integrity test; application CAS evidence is expected under M03/M04.
  - `current_evidence`: User selected D-017: SAFE_STOPPED represents embedded deny-all Scope baseline; no extra Scope baseline column. FROZEN is rollback-only and must reference a same-scope ROLLING_BACK rollout. Existing init.sql supplies root authorization_epoch, Root Safe Baseline/digest checks, Scope mode/live-rollout FK, global security_generation, and rollout epoch columns. S06 up migration adds an immediate FROZEN/live-rollout CHECK plus deferred cross-row triggers with Scope→Rollout row locks; application CAS is intentionally deferred to M03-S02/M04-S01 per user's explicit acceptance-scope choice. After read-only preflight (paddock_test PG18.6, frozen=0, no pre-existing objects), explicitly authorized migration exit 0/COMMIT. Sequential positive/negative fixture passed 0/ROLLBACK after two corrected harness attempts (details in receipt). Two-session race harness passed after one output-format failure; both workers updated before barrier, one transaction committed and one aborted, final state matched winner, cleanup verified. Final read-only check: check=1, triggers=2, fixtures=0. Offline static tests 6/6, concurrency dry test 1/1, full Python suite 77/77, lint 89/148, diff-check PASS. Receipt: `receipts/PDK-M02-S06/2026-10-13-safety-race.json`. D-016 independent verifier reviewed the revised acceptance, receipt, dependencies and source; found no remaining S06 acceptance gap. Main reconciled and marked [x]. Receipt limitations remain: dirty diff hash unavailable, raw race-session output not retained, exact winning session/SQLSTATE not surfaced, PGPASSWORD exists in child environment, no CI attestation or Verifier-of-Record. CAS implementation/tests remain explicitly assigned to M03-S02/M04-S01.
  - `next_action`: PDK-M02-S06 is DONE under D-016. PDK-M02-S04 is now dependency-ready; CAS and stale-update evidence remain M03-S02/M04-S01 acceptance.


### M03 / P0 / pgx Native Repository Adapter

**中目標:** `GovernanceTx` Interfaceを実DBの1 Transactionへマップする。

- [x] `PDK-M03-S01` — `Transactor`、`GovernanceTx`、Port境界を定義。
  - `depends_on`: PDK-M01-S02, PDK-M02-S06
  - `acceptance`: Domainにpgxが漏れず、1つのUse Caseが1 Transactionを共有。
  - `evidence_expected`: Goコンパイル、Interface検証。
  - `current_evidence`: Commit `b2be8c65fef9fbd0c0136863872080c7b8a77224` contains the pgx-free `Transactor`/`WithinTransaction` and `GovernanceTx` contracts plus fake tests; module metadata is included so the contract builds from this commit. Runner on that exact commit: `go test ./internal/governance/port ./internal/governance/domain -count=1` PASS; `go vet ./internal/governance/port ./internal/governance/domain` PASS; `git diff --check` PASS. Separate verifier reviewed transaction-lifetime contract and the limitation that interfaces/fakes do not prove a real adapter or DB transaction. No live DB test or CI attestation claimed. Verification used local Runner + separate Verifier.
  - `next_action`: M03-S01 is DONE; M03-S02 and M03-S03 are dependency-ready independent workstreams with disjoint Go files.
- [x] `PDK-M03-S02` — `LockScope/LockRollout/ValidateTargets`と保存CAS。
  - `depends_on`: PDK-M03-S01, PDK-M02-S02
  - `acceptance`: `FOR UPDATE`、Scope所属照合、`scope_activation_epoch` / `root_authz_epoch` / `security_epoch` / Rollout state をexpected値とするCAS、0-row stale拒否、一貫したロック順序を実装。Freeze/rollback trigger競合は40P01/40001をwhole-transaction retryへ返す。
  - `evidence_expected`: pgx Integration Tests、競合ログ。
  - `current_evidence`: Commits `904ed4eb3afcd7c8eac9600cbd1647fbeccf5414` (pgx adapter) and `61cef15c5c65b0ebd1753fe5a8a9881f14020d2a` (integration lifecycle/concurrency coverage). Runner on exact HEAD `61cef15c5c65b0ebd1753fe5a8a9881f14020d2a`: `go test ./internal/storage/postgres ./internal/governance/application ./internal/governance/port ./internal/governance/domain -count=1` PASS; matching `go vet` PASS; `scripts/init_test_db.sh --check` PASS (paddock_test, PostgreSQL 18.6, raw_relations=26); `go test -tags=integration ./internal/storage/postgres -count=1` PASS (11.960s); post-run fixture counts for bundles/scopes/roots/rollouts/targets all 0; `git diff --check` PASS. Integration covers Scope/Rollout/Root/target/security stale CAS rollback and Scope row-lock blocking via `pg_blocking_pids`. Separate Verifier reviewed source/hash `77bf93bf92a080301ed9745fded52d237400ace9f62953aa3fb556a35b7910f6` and approved Runner execution. No CI attestation claimed; external-writer race and live trigger-induced retry remain untested.
  - `next_action`: Continue with next dependency-ready Issue selected by `scripts/continue_plan.py`; M03-S02 implementation commits are pushed.
- [x] `PDK-M03-S03` — `SERIALIZABLE`再試行(40001/40P01)と取消。
  - `depends_on`: PDK-M03-S01
  - `acceptance`: 業務CallbackはDB内だけ。Retry時に外部副作用なし。Context Cancelで停止。
  - `evidence_expected`: リトライ注入テストと競合試験。
  - `current_evidence`: Commit `2d8274ef695c3d550c6bd2d4393bc32059d72e7f` is pushed to `origin/main`. Runner: `go test ./internal/governance/application -count=1` PASS; `go vet ./internal/governance/application` PASS; `git diff --check` PASS. `retryableSQLState` uses `errors.As`; `%w`-wrapped 40001 and 40P01 each retry whole callback/transaction, with nonretryable, max-attempt, and cancellation tests. Separate Verifier reviewed that exact commit and found no actionable defect. Evidence is fake/unit level; no live PostgreSQL/pgx contention test or CI attestation claimed.
  - `next_action`: M03-S03 is DONE; proceed by dependency DAG.

- [x] `PDK-M03-S04` — Transaction内Receipt/Event/Outbox保存。
  - `depends_on`: PDK-M03-S02, PDK-M05-S01
  - `acceptance`: 一つ失敗すればScope/Receipt/Event/Outboxが全Rollback。
  - `evidence_expected`: 故障注入SQLと最終RowCount。
  - `work_owner`: Main implementation in the current workspace.
  - `selected_design`: User selected extending existing `SafetyService.Stop/Release`; append the safety Event via the existing transaction-bound `GovernanceTx`. User selected minimal metadata only: record the transition event type and before/after Scope Activation Epoch and Security Epoch; do not store signer IDs, signature bytes, or full AuthorityState snapshots. User selected a Scope aggregate (`aggregate_kind=scope`, `aggregate_id=ScopeID`) versioned by the transition's new Security Epoch, event ID `safety/<commandID>`, and schema `paddock.safety-event/1`; no event-sequence migration is in scope.
  - `selected_database_boundary`: User selected M09-preserving app-only `SECURITY DEFINER` APIs for Scope/Root/Security Epoch read-lock/CAS and Receipt lookup/insert, invoked by the Safety-specific `NewSafetyTransactor` within one app-session PostgreSQL transaction. The general `NewTransactor`/`GovernanceTx` path remains unchanged for existing non-Safety callers/tests. Keep `paddock_app` function-only on `raw.roots`; do not grant direct table/column privileges. Reuse the existing app-only Event+Outbox function. Every new function must be migrator-owned, fixed `search_path=pg_catalog`, fully raw-qualified, reject `session_user <> 'paddock_app'`, and grant EXECUTE only to `paddock_app` (PUBLIC and other explicit grantees denied).
  - `effect_boundary`: This design selection alone did not authorize DB writes. The user separately authorized one exact `paddock_test` preflight, one application of `sql/governance_safety_api.sql`, one named SafetyService integration test, and final readback. No other DB operation, commit, or push is authorized.
  - `current_evidence`: Final local Runner: `go test ./... -count=1`, `go vet ./...`, tagged PostgreSQL compile-only (no body), 18 targeted SQL static tests, design lint 89/148, and `git diff --check` PASS. DB Runner: read-only preflight PASS on `paddock_test`/PostgreSQL 18.6; migration preconditions confirmed migrator ownership, isolated app/migrator roles, Event function owner/path/app-only EXECUTE, app Event SELECT-only/no Outbox access, and no direct app Root grants. `sql/governance_safety_api.sql` applied once as `paddock_migrator` (Exit 0); readback verified 8/8 expected functions migrator-owned SECURITY DEFINER/fixed-path, app EXECUTE true, PUBLIC/other-role EXECUTE false, and zero direct app table/column privileges. Named `TestPostgresGovernanceIntegration/SafetyService_receipts_in_rollback-only_transaction` PASS (Exit 0); log: post-rollback receipts=0, events=0, outbox=0. Parent fixture cleanup/readback PASS. Exact commands, outputs, and hashes are in the Receipt. CI is absent.
  - `verification_receipt`: `receipts/PDK-M03-S04/2026-10-17-local-verification.json`
  - `independent_review`: Final separate read-only Verifier reviewed the isolated Safety adapter, SQL migration, and rollback/readback fixture. It reported one concern about app Event SELECT; Main reconciled it against the existing M05 `GRANT SELECT ON raw.domain_events` and fresh preflight `app SELECT=true`, `Event INSERT=false`. No actionable gap remains. Verifier did not access the DB; Main compared its finding with Runner observations.
  - `remaining_gate`: NONE for selected acceptance under D-016 local Runner + independent review. Residuals: no CI attestation; worktree remains broadly dirty with full diff hash unavailable; no commit or push. No broader integration suite or production behavior is claimed.

- [x] `PDK-M03-S05` — Canonical Request/Bundle DigestのRepository受け渡し。
  - `depends_on`: PDK-M03-S01, PDK-M06-S07
  - `acceptance`: 署名用途別バイト列とRequest DigestをGo Domain入力に固定し、JSON Key順/空白/数表現の相違でIdempotencyが破綻しない。
  - `evidence_expected`: 同値/非同値Payload FixtureとDigest Test。
  - `difficulty_assignment`: Main publishes `D_pub=HARD` because work crosses JCS/security-domain envelopes, Domain/Port/Application/Postgres persistence, command replay and Bundle storage. Every Worker MUST report comparable `D_worker` before CODE.
  - `selected_design`:
    - `canonical_owner`: Domain owns immutable canonical Request and Bundle values; use the concrete RFC 8785 `JCSCodec`, no identity fallback. Values expose defensive copies of canonical content, domain-separated signing bytes, and typed `domain.Digest`.
    - `bundle_digest`: `bundle_digest = SHA-256(JCS canonical payload bytes)` (content-addressed and stable across signature context). To make the signature input reconstructible from the existing `policy_bundles` row without adding a DB column/migration, Bundle context is deterministic: `request_id = lowercase_hex(bundle_digest)`; `nonce = lowercase_hex(SHA-256(UTF8("PADDOCK-BUNDLE-NONCE-v1\\0") || raw_bundle_digest_bytes))`; `schema_version` is the persisted row value; audience is fixed `governance`. The separate `DomainBundle` Envelope signs that content plus reconstructible context. No caller-supplied Bundle ID or nonce is part of the Bundle canonical API. Command nonce remains explicit caller input.
    - `command_digest`: `RequestDigest = SHA-256(DomainCommand Envelope bytes)`; `request_id` is the existing `CommandID`; the nonce is an explicit stable Domain input reused byte-for-byte on retry; audience is fixed to `governance`, command schema to `paddock.command/1`. Approval/signature bytes use the distinct `DomainApproval` Envelope with `paddock.approval/1`, same command ID and nonce. No ambient clock/randomness enters the context.
    - `bundle_context`: derived solely from the JCS content digest and persisted schema version using the exact formula above; same content/schema always yields same Bundle signing bytes and can be verified after reload. A different schema version changes signing bytes, not content digest. This selected refinement supersedes the earlier explicit Bundle submission-id/nonce choice; command nonce semantics are unchanged.
    - `repository`: Add `GovernanceTx.InsertPolicyBundle` so canonical content bytes/digest/schema/signer/signature persist in the existing transaction capability. `CommandReceipt.RequestDigest` becomes a validated `domain.Digest`; PostgreSQL persists the lowercase hex text in the existing column. No database schema migration is selected or needed.
    - `crypto_boundary`: Domain exposes approval/bundle signing bytes but performs no private-key custody or signature generation. This Issue does not claim signed-key verification or external-effect authorization.
    - `typed_api`: `domain.NewCanonicalRequest(commandID,nonce string,payload []byte)` fixes DomainCommand, schema `paddock.command/1`, audience `governance`, and request_id=CommandID; its `PayloadBytes()` are JCS payload bytes, `SigningBytes()` are the DomainCommand Envelope, and `Digest()` is SHA-256 of that envelope. `domain.NewCanonicalBundle(schemaVersion string,payload []byte)` computes the content digest and derived signing context above; it exposes canonical bytes, content Digest, reconstructible BundleID/nonce metadata, and separate DomainBundle Envelope signing bytes. `Validate()` recomputes fields and byte bindings. Both values expose defensive copies and have no mutable exported fields.
    - `safety_use`: `SafetyService.Stop/Release` and Domain `SafetyQuorum` signatures receive an explicit nonce; command `request_id=CommandID`, audience `governance`, fixed schema `paddock.command/1` for RequestDigest and `paddock.approval/1` for signature bytes. Same command retry MUST reuse identical nonce/context/payload; changed nonce or request changes digest/signing bytes.
    - `code_scope`: exact allowlist: `internal/governance/domain/canonical_input.go` (new), `internal/governance/domain/canonical_input_test.go` (new), `internal/governance/domain/safety_quorum.go`, `internal/governance/domain/safety_quorum_test.go`, `internal/governance/domain/safety_test.go`, `internal/governance/port/transaction.go`, `internal/governance/port/transaction_test.go`, `internal/governance/application/safety.go`, `internal/governance/application/safety_test.go`, `internal/governance/application/safety_gate_test.go`, `internal/storage/postgres/governance_tx.go`, `internal/storage/postgres/governance_event_test.go`, and call-site updates in `internal/storage/postgres/integration_test.go`. No SQL/migration/schema/DB files or other targets.
  - `continuation_status`: Initial monolithic CODE dispatch stopped with `LLM session not configured` after leaving a partial Domain file. Main resumed with sequential file ownership, completed the allowlisted Domain, Port/Postgres, and Application slices, then ran the local verification below. No database, migrations, external signing keys, network, or external effects were used.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: `go test ./... -count=1` PASS; `go vet ./...` PASS; integration+paddock_test PostgreSQL compile-only PASS (no test bodies); 62 focused M02/M09 static tests PASS; design lint PASS (89 issues/148 edges); gofmt/whitespace checks PASS. Separate read-only Verifier review found no actionable source finding after the Bundle signing context was made reconstructible from persisted content digest/schema with the user-selected deterministic request ID/nonce formula. No DB/runtime or signature-key verification is claimed; no SQL/schema change was made.
  - `verification_receipt`: `receipts/PDK-M03-S05/2026-10-17-d016-local-verification.json`
  - `remaining_gate`: `NONE` for selected source-level M03-S05 acceptance under D-016 local verification. Residuals: no DB migration/runtime or external cryptographic signature verification; no CI attestation; dirty worktree/full diff hash unavailable.
  - `next_action`: PDK-M03-S05 is DONE locally. Continue with the next dependency-ready Issue selected from the explicit DAG; no push or llm-memory registration is authorized.
- [x] `PDK-M03-S06` — DB時刻の正本・Timeout照合契約。
  - `depends_on`: PDK-M03-S01
  - `acceptance`: Lease/Monitoring/HOLDの期限比較に使う時刻源はDBのみとし、Worker時計を期限判定の権威にしない。`GovernanceTx.DatabaseTime`はtransaction内で`clock_timestamp()`を取得する。`now()`がTransaction開始時刻で固定され、`clock_timestamp()`が実時間とともに進むことをテストする。TTL値・HOLD/Monitoring期限値・延長主体/上限はO-006のOPENとして本Issueでは決めない。
  - `evidence_expected`: DB clock contract unit/integration tests; transaction内now()/clock_timestamp()比較と未来のWorker timestampがDB時刻判定を延長しないfixture。
  - `current_evidence`: Commit `1a77a5fe833edba1983327330983679e12858f7a` pushed to `origin/main`. Runner exact HEAD: `go test ./internal/governance/port ./internal/storage/postgres -count=1` PASS; matching `go vet` PASS; `scripts/init_test_db.sh --check` confirmed paddock_test PostgreSQL 18.6/raw_relations=26; `go test -tags=integration ./internal/storage/postgres -count=1` PASS (12.293s); post-run fixture counts for bundles/scopes/roots/rollouts/targets all 0; `git diff --check` PASS. Separate Verifier reviewed the matching source hashes and confirmed the scoped clock-source contract. No CI attestation claimed. Residual: no Lease/HOLD/Monitoring deadline consumer exists yet; TTL values and extension policy remain OPEN under O-006.
  - `next_action`: Continue with next dependency-ready Issue; any deadline consumer must use DatabaseTime and separately resolve O-006 policy.


### M04 / P0 / Application Use Cases・Command冪等性

**中目標:** `StartCanary`などの業務操作を一意に確定させる。

- [ ] `PDK-M04-S01` — `Propose`, `StartCanary`, `Promote`, `Rollback` Application Services。
  - `depends_on`: PDK-M03-S02, PDK-M06-S02
  - `acceptance`: 承認検証後だけ遷移し、Commitまで状態が外部に見えない。
  - `evidence_expected`: Service Test、DB Integration Test。
- [x] `PDK-M04-S02` — `command_id` + 正規化`request_digest`のReceipt契約。
  - `depends_on`: PDK-M03-S05, PDK-M03-S02
  - `acceptance`: 同ID同引数は同結果、同ID異引数は拒否、Commit応答喪失後に再送してもEpoch不変。
  - `evidence_expected`: DB-backed duplicate/replay/conflict fixture, explicit Exit Code and RowCount/result log, plus stateful unit fault injection for simulated lost acknowledgement.
  - `selected_design`: Reuse M03-S05 `domain.Digest`/RFC 8785 canonical RequestDigest and the existing SafetyService command receipt contract; do not add a new Receipt schema or DB column. For commit-ack-loss proof, user selected one named PostgreSQL integration fixture using SafetyService.Stop: commit one valid Stop under the normal app transaction, return a synthetic lost-ack error only after the underlying PostgreSQL commit succeeds, then retry identical command_id/request and assert the stored response is returned with no second Scope/Security Epoch CAS. Cleanup command Receipt/Event/Outbox and fixture Scope/Root rows, but never decrement Security Epoch; the dedicated paddock_test global Security Epoch is expected to advance by exactly +2 (Stop plus cleanup Release) and remains monotonic. This selection authorizes design scope only, not DB test execution.
  - `effect_boundary`: The design selection itself did not authorize DB writes. User later separately approved exactly one named paddock_test commit-ack-loss integration run and its fixture cleanup; global Security Epoch was not rewound and remains +2. No production DB, reset/down, commit, or push.
  - `current_evidence`: Runner: `go test ./... -count=1`, `go vet ./...`, tagged `integration paddock_test` compile-only, 18 M03-S04/M05 SQL static tests, design lint 89/148, and `git diff --check` PASS. Under separate exact approval, `TestPostgresSafetyReceiptReplayAfterCommitAcknowledgementLoss` PASS (Exit 0): first Stop committed, wrapper returned synthetic lost ACK after commit, same-ID/same-request retry returned the stored Receipt response without changing Scope/Security Epoch, and changed request was rejected. Cleanup Release restored Scope; Security Epoch stayed monotonic at baseline+2. Final Receipt/Event/Outbox counts were 0/0/0, and parent fixture absence readback passed. See runtime Receipt for commands/hashes.
  - `verification_receipt`: `receipts/PDK-M04-S02/2026-10-17-runtime-verification.json`
  - `independent_review`: Final separate read-only Verifier reported one Medium cleanup-readback concern; Main resolved it by checking `cleanupFixtures` source (`internal/storage/postgres/integration_test.go:966-969`) which verifies exact fixture rows absent after cleanup. No unresolved findings remain; reviewer did not access DB or run tests.
  - `remaining_gate`: NONE for selected local acceptance under D-016. Residuals: ACK loss is simulated by returning an error after a real successful `Commit`; no network fault proxy/actual driver-level ambiguous commit was exercised. Only the named fixture ran. CI absent; no production deployment/effect claim.
- [ ] `PDK-M04-S03` — Scope別Active Rollout競合とLock順序。
  - `depends_on`: PDK-M04-S01, PDK-M04-S02
  - `acceptance`: Coordinator2プロセスから競合同時開始して片方だけ成功。
  - `evidence_expected`: 二重プロセスIntegration Test、DB状態。
- [ ] `PDK-M04-S04` — エラー型とFailure Modeの正規化。
  - `depends_on`: PDK-M04-S01
  - `acceptance`: STALE / BUSY / FORBIDDEN / INVALID / RETRYABLE / UNKNOWN_COMMITを区別。
  - `evidence_expected`: 表駆動テスト、APIエラー契約。

- [ ] `PDK-M04-S05` — Negative ReceiptとIdempotency保持期間を定義・実装。
  - `depends_on`: PDK-M04-S02
  - `acceptance`: VALIDATION_DENIED/FORBIDDENの確定拒否を保存し、TRANSIENT/UNKNOWN_COMMITを区別。保持期間・ID再利用防止/expiryと監査Retentionの関係を規定。
  - `evidence_expected`: 同ID拒否再送、改変Payload拒否、Expiry境界テスト。
- [ ] `PDK-M04-S06` — Commit-unknownの同Command調停と副作用重複防止。
  - `depends_on`: PDK-M04-S05, PDK-M03-S03
  - `acceptance`: Connection断でCommit結果不明でもCommand ID再利用により状態を重複変更しない。別IDによる無条件再実行は禁止。
  - `evidence_expected`: Toxiproxy等の接続断Fixture・DB Readback。


### M05 / P0→P1 / Event・Outbox・Inbox

**中目標:** 状態とイベントの原子性を保ち、少なくとも1回の配送に耐える。

- [x] `PDK-M05-S01` — Event EnvelopeとAppend Event+Outbox。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: Aggregate Version一意。Event+Outbox appendは同一Transaction。状態遷移+Receipt+Event+Outboxの複合原子性はPDK-M03-S04の受入であり、本Issueでは主張しない。
  - `evidence_expected`: SQL Integration Test、Eventサンプル。
  - `current_evidence`: `internal/governance/domain/event.go` defines an immutable validated envelope with defensive payload copies. `GovernanceTx.AppendEvent` validates the event then makes one function call inside the caller's transaction; the guarded SECURITY DEFINER function inserts the Event and matching Outbox row. Current `sql/init.sql` declares `schema_version NOT NULL` and a unique aggregate-kind/id/version constraint. Fake transaction tests verify exact call/argument binding and rollback on function/callback failure. The app-role PostgreSQL fixture checks identity/privileges, envelope/outbox readback, SQLSTATE 23505 duplicate aggregate-version denial, callback rollback, and exact cleanup; the Scope-CAS/Event composition case was removed from this M05 test scope because state+Receipt+Event atomicity belongs to M03-S04. Main applied the selected migration and ran the named fixture under renewed approval; all checks passed. Separate source Verifier found no actionable gap. No broader integration parent suite is claimed. O-001 dispatcher choice is not needed for this append contract.
  - `selected_schema_repair`: User selected a guarded additive migration for the existing paddock_test schema. It MUST run only as paddock_migrator on exact paddock_test; require raw.domain_events owned by migrator; if schema_version is absent, require zero domain_events rows before adding `schema_version text NOT NULL CHECK(schema_version <> '')`; if any old rows exist, DENY without changes and require a separate legacy event-version policy. If the column already exists, require exact compatible text/NOT NULL/check state and no-op; partial/incompatible states DENY. No data backfill, destructive DDL, down/reset, role change, production/llm-memory access.
  - `selected_write_boundary`: User selected a narrow `SECURITY DEFINER` `raw.append_domain_event_and_outbox(...)` function owned by paddock_migrator, requiring `session_user='paddock_app'`, fixed `search_path=pg_catalog`, raw-qualified inserts, and app EXECUTE only. The applied migration revokes app direct INSERT on `raw.domain_events` and all app/PUBLIC privileges on `raw.event_outbox`; app retains Event SELECT. `GovernanceTx.AppendEvent` invokes this function inside its transaction.
  - `scope_split`: M05-S01 claims atomic Event+Outbox append only; state-transition+Receipt+Event/Outbox atomicity remains PDK-M03-S04. The M05 app-role fixture runs the Event subtest only; state-CAS composition is not included.
  - `execution_boundary`: The user subsequently authorized a read-only preflight, one guarded migration application only if domain_events was empty, and only the named app-pool Event/Outbox fixture. The guards passed, migration committed, fixture ran once, and exact cleanup was verified. No down/reset/drop, production, credential output, or M09 fixture mutation occurred.
  - `schema_migration_scope`: `sql/governance_domain_events_schema.sql` now contains the guarded schema_version repair and app-only append function/ACL changes; the equivalent named schema_version check is in `sql/init.sql`. The migration no-ops only on compatible existing column/check state; if missing, it acquires ACCESS EXCLUSIVE and adds only when the Event table is empty. It fails closed on any preexisting Event row without backfill. The function requires `session_user=paddock_app`, is migrator-owned/fixed-path, and is the sole app Event+Outbox write path; app direct Event INSERT and all Outbox access are revoked.
  - `code_scope`: `internal/governance/domain/event.go`, `internal/governance/domain/event_test.go`, `sql/governance_domain_events_schema.sql`, `sql/init.sql`, `tests/test_m05_events_schema_migration.py`, `internal/storage/postgres/governance_tx.go`, `internal/storage/postgres/governance_event_test.go`, and the app-pool-only M05 Event fixture in `internal/storage/postgres/integration_test.go`. State-CAS composition is out of this fixture and belongs to M03-S04. No generic role changes or unrelated files.
  - `current_evidence`: Prior M06-S05 integration observed SQLSTATE 42703 on an older live schema. At the renewed preflight, `paddock_test/raw.domain_events` was migrator-owned, lacked schema_version, and had zero rows. Main applied the selected schema/function/ACL migration once as paddock_migrator, then read back the named validated check, migrator-owned SECURITY DEFINER function/fixed search_path, app-only EXECUTE, app Event SELECT-only/no INSERT, and no app Outbox privileges. The named app-pool integration subtest PASSed event envelope/readback, matching Outbox, duplicate aggregate-version SQLSTATE 23505, callback-error rollback, and exact cleanup; post-run Event/Outbox fixture counts were zero. 12 migration static tests, Go tests/vet, and tagged compile-only pass. No broader parent integration suite is claimed.
  - `source_receipt`: `receipts/PDK-M05-S01/2026-10-17-schema-repair-source.json`
  - `runtime_receipt`: `receipts/PDK-M05-S01/2026-10-17-runtime-verification.json`
  - `remaining_gate`: `NONE` for the selected Event+Outbox scope under D-016 local verification. Residuals: no CI attestation; dirty diff hash unavailable; populated legacy Event rows intentionally fail closed and need a separate policy.
  - `independent_review`: Separate read-only Verifier reviewed the final M05 runtime receipt and current source; no actionable gap. Verifier did not independently access or reproduce the DB.
  - `d016_reconciliation_receipt`: `receipts/PDK-M05-S01/2026-10-17-d016-reconciliation.json`
  - `next_action`: PDK-M05-S01 is DONE locally. State-transition+Event atomicity remains M03-S04. Preserve M09 append-only fixtures; no further DB or ACL action is authorized.
- [x] `PDK-M05-S02` — Dispatcher方式O-001の正式選択。
  - `depends_on`: PDK-M05-S01
  - `acceptance`: Polling/NOTIFY/Brokerの選択理由、契約、障害時方針をdecision追記。
  - `evidence_expected`: 更新済みDecision IDと設計レビュー。
  - `selected_design`: User selected Polling+NOTIFY; D-018 resolves O-001. PostgreSQL Outbox remains durable truth; NOTIFY carries no Event/secret payload and is only a wake-up hint; periodic Polling recovers missed/coalesced notifications and listener reconnect/startup gaps; at-least-once delivery and Inbox dedupe remain. Transactional NOTIFY is delivered only after commit; abort means no notification. Queue exhaustion can fail commit, rolling back State/Event/Outbox together; same Command ID is used to reconcile commit uncertainty. Long listener transactions are avoided/monitored. External Broker is not selected.
  - `current_evidence`: `decisions.md` adds D-018 without modifying D-001..D-017, resolves/removes O-001 from the OPEN backlog, and updates the earlier dispatcher DESIGN_BASELINE statement. The selected semantics match official PostgreSQL 18 NOTIFY/LISTEN transaction and startup-race documentation. `python3 scripts/lint_design.py` PASS (89 issues/149 edges); `git diff --check` PASS. A broad Python mutation-test attempt failed in pre-existing temp-fixture setup because it copied neither the referenced README/receipt targets nor current README anchor text; its stale O-001 test anchor was updated to current OPEN O-002. No dispatcher code or DB runtime was part of this Issue.
  - `verification_receipt`: `receipts/PDK-M05-S02/2026-10-17-d018-local-verification.json`
  - `independent_review`: Separate read-only Verifier reviewed D-018, OPEN O-001 resolution, PostgreSQL semantics and Issue scope; No findings. Verifier did not run DB or modify files. Main reconciled against the fetched official PostgreSQL docs.
  - `remaining_gate`: NONE for M05-S02 design selection under D-016 local Runner + review. Dispatcher implementation/performance and runtime validation remain in M05-S03/S04 with their own scopes and approvals; CI is absent.
- [x] `PDK-M05-S03` — Outbox Claim/Ack/Retry/Dead Letter。
  - `depends_on`: PDK-M05-S02, PDK-M03-S01
  - `acceptance`: Coordinator2体のClaim競合で重複配信しても無害、配送途中落ちても再回収。
  - `evidence_expected`: 失敗注入Integration Test、再配信ログ。
  - `selected_design`: User selected D-018 Polling+NOTIFY plus explicit per-Event lease/token claim. Atomically claim pending rows with `FOR UPDATE SKIP LOCKED`, generate a per-row UUID claim token, persist a 5-minute lease, commit before dispatch, and require the current token for Ack/Retry so a stale dispatcher cannot finish a reclaimed lease. Claim batch maximum is 100 Events per transaction. `attempt_count` is cumulative and never reset; each retry cycle allows 20 claims with exponential backoff from 5 seconds capped at 1 hour. After 20 claims set `dead_lettered_at` and exclude from ordinary claims. User selected one automatic redrive after 24 hours: increment `redrive_count` to 1, clear DLQ state, retain cumulative attempts; after total claim 40, terminal DLQ with no more automatic or manual redrive in this Issue. `available_at` is poll/retry readiness; `published_at` means successful Ack. DLQ/retry diagnostics store bounded sanitized error codes only, not raw error text/secrets. New lease/DLQ fields and app-only SECURITY DEFINER APIs require a guarded additive migration; no direct app Outbox privileges.
  - `effect_boundary`: Local Go/SQL/test source edits only. Applying the new migration or executing DB test bodies requires separate exact current-task approval; no live Broker, credential use, production dependency, direct app ACL, commit, or push.
  - `open_design_choice`: NONE for selected M05-S03 state/retry/redrive policy; no automatic/indefinite redrive beyond the selected single 24-hour cycle. Implementation must preserve token fencing, bounded claims, terminal DLQ, and Outbox as durable truth.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: after repairs, `go test ./... -count=1`, `go vet ./...`, tagged PostgreSQL compile-only (`-run '^$'`), 25 targeted M03/M05 static tests, `gofmt -d`, design lint (89 issues/149 edges), and `git diff --check` PASS. The first approved migration attempt failed Exit 3 on an incorrect redrive-index predicate expectation and rolled back; read-only catalog readback confirmed no artifacts. After renewed exact approval, the corrected guarded migration applied once to `paddock_test` as `paddock_migrator` (Exit 0). Readback confirmed all four dispatch columns and validated constraints, both valid indexes with correct normalized predicates, four migrator-owned fixed-search-path SECURITY DEFINER functions, app EXECUTE only, no direct app Outbox ACL, and zero pending rows. The first approved execution of the named integration test failed at the prior fixture's immediate-claim expectation after redrive housekeeping; cleanup readback confirmed no fixture/pending rows. The fixture was corrected to assert the housekeeping-only batch then claim attempt 21 on the next poll. Under renewed exact approval, the corrected named test PASSed (2.315s; events=2, outbox=2, published=1, total_attempts=40, redrives=1, terminal=true). Final readback confirmed zero fixture-prefix Events/Outbox and unpublished rows, with migration schema/indexes still valid. A separate Verifier independently read the complete M05 implementation source files and current M05 acceptance; no actionable findings. Most implementation files are untracked additions, so their reviewed full contents constitute the source additions; the Verifier did not inspect Git diff/status. Main inspected the observed target file status and reconciled the Issue transition and Runner receipt. CI is absent; no CI attestation is claimed.
  - `verification_receipt`: `receipts/PDK-M05-S03/2026-10-18-local-verification.json`
  - `independent_review`: A separate read-only Verifier independently read all listed M05 implementation files, Receipt, and Issue acceptance/selected policy; no actionable findings. It confirmed the corrected redrive predicate and the housekeeping-then-next-poll fixture. Verifier did not run tests, access DB, or inspect Git diff/status. Main reconciled Runner results, observed source-file status (M05 implementation files are untracked additions), current M05 Issue changes, and all acceptance clauses. No unresolved findings remain.
  - `remaining_gate`: NONE for selected M05-S03 acceptance under D-016 local Runner + independent source review + Main reconciliation. CI attestation is absent and not claimed; worktree is broadly dirty and no full-worktree diff hash is available.
- [x] `PDK-M05-S04` — Consumer Inboxによる冪等効果。
  - `depends_on`: PDK-M05-S03
  - `acceptance`: 同Event3回配送でもDB側の業務効果は1回。外部APIのExactly-onceと混同しない。
  - `evidence_expected`: Retry Fixture、Consumer RowCount。
  - `effect_boundary`: User separately authorized one guarded `paddock_test` migration application and one execution of only `TestPostgresConsumerInboxAppliesEventOnce`, conditional on read-only preflight. Both authorized operations passed. No reset/down/other DB test, external API/Broker action, or external exactly-once claim.
  - `difficulty_assignment`: Main publishes `D_pub=HARD` because the chosen work crosses PostgreSQL transaction atomicity, dedupe concurrency, app table/column ACLs, additive migration, and Go port/application/storage layers. Worker MUST self-report `D_worker` on the same EASY<MEDIUM<HARD scale after bounded inspection and before CODE; if above HARD/incomparable, stop and replan.
  - `selected_design`: User selected A — Go consumer `pgx.Tx` plus narrowly scoped direct DML. Within the same pgx transaction, first verify `event_id` exists in readable durable `raw.domain_events`, then insert `raw.event_inbox(consumer_id,event_id,processed_at) ON CONFLICT DO NOTHING`; if one row is inserted, increment a DB-side per-consumer processed-event projection counter; if duplicate, skip the effect. An effect failure rolls back Inbox and projection together. A commit error may have unknown outcome; retry the same `(consumer_id,event_id)` so the PK reconciles without a second effect. Use `raw.event_consumer_projection(consumer_id,processed_event_count)` as the concrete PoC DB effect; `paddock_app` gets only Inbox column INSERT and projection SELECT/INSERT on `(consumer_id,processed_event_count)` plus UPDATE on `processed_event_count`. The Inbox insert uses targetless `ON CONFLICT DO NOTHING` to avoid granting SELECT on Inbox keys; the guarded migration verifies the PK is the Inbox's only valid unique index. Never grant direct Outbox access. Three deliveries of one Event must yield one Inbox row and counter=1. Add a failure/retry fixture proving a failed effect leaves no Inbox marker and a later retry applies once.
  - `open_design_choice`: NONE for transaction/privilege boundary; user selection is scope only, not approval to apply migration or run an integration-test body.
  - `routing_observation`: Two `subagent_type=general` invocations stopped before CODE: the first misread the selected task as requiring nested dispatch; after clarifying that the task invocation itself was the Worker dispatch, the second refused writes because its workspace is rooted at nested `paddock/crabcode` and treats PADDOCK as a parent repo. Main verified PADDOCK root via `git rev-parse --show-toplevel`. User then explicitly authorized Main to implement only the selected source/offline-test scope; this is not DB approval.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: final `go test ./... -count=1`, `go vet ./...`, tagged PostgreSQL compile-only (`-run '^$'`, no body), 29 targeted M03/M05 static tests, `gofmt -d`, design lint (89 issues/149 edges), and `git diff --check` PASS. An earlier local attempt failed before correction (undefined test variable and unused import); both source errors were fixed and final checks passed. Read-only preflight confirmed paddock_test PostgreSQL 18.6, valid migrator/app identities, baseline Inbox shape with PK as sole unique index, no consumer projection, app no Inbox ACL, append/domain-event access ready, no direct Outbox ACL, and pending Outbox rows=0. The guarded `sql/governance_consumer_inbox.sql` migration applied once as `paddock_migrator` (Exit 0); readback confirmed expected Inbox/projection schema and narrow app grants, with Outbox ACL still absent. `TestPostgresConsumerInboxAppliesEventOnce` ran once and PASSed (4.497s): three same-Event deliveries produced one effect, a second consumer independently applied once, forced counter overflow left no Inbox marker, and same-key redelivery applied once. Final read-only readback confirmed zero fixture Event/Outbox/Inbox/projection rows and pending Outbox rows=0. Receipt records command results, hashes, migration and cleanup.
  - `verification_receipt`: `receipts/PDK-M05-S04/2026-10-18-local-verification.json`
  - `independent_review`: A separate read-only Verifier independently reviewed all current M05-S04 source files and found no actionable findings. A prior specific finding in the overflow fixture (wrong counter consumer reset) was fixed; a separate follow-up confirmed the corrected reset and same-key retry. Verifier did not access DB or run tests. Main reconciled the exact Issue acceptance, Runner test output, migration/ACL readback, fixture cleanup, and source review under D-016. CI attestation absent and not claimed.
  - `remaining_gate`: NONE for selected PDK-M05-S04 acceptance under D-016 local Runner + independent source review + Main reconciliation. Residual: the implemented projection counter is a PoC DB effect, not arbitrary consumer logic or external API exactly-once; CI absent; broad worktree/full diff hash unavailable.


- [x] `PDK-M05-S05` — Event/Policy DSL/ReceiptのSchema VersionとEvent保存・Partition方針（D-019）。
  - `depends_on`: PDK-M05-S01, PDK-M00-S08
  - `acceptance`: 未知Major Versionの扱い、Event・Outbox・Inbox retention、DLQ後の監査保存とReplay窓、Partition/Archive方針を記録。
  - `evidence_expected`: Version互換Fixture、expiry/replay境界テスト、更新Decision。
  - `effect_boundary`: Local decision/policy source and offline-test edits only until separately scoped authorization; no database migration, cleanup, or test body without exact current-task approval.
  - `difficulty_assignment`: Main publishes `D_pub=HARD` because the Issue crosses schema compatibility, Event/Outbox/Inbox/DLQ retention interactions, replay/idempotency boundaries, and potential partition/archive key constraints.
  - `selected_design`: User selected D-019 bounded unpartitioned policy, D-020 consumer-side replay with immutable Outbox, D-021 trusted Coordinator service-only authorization/audit, and D-022 explicit distinction from Outbox redrive. Consumer-side replay is permitted within 30 days after terminal DLQ/quarantine, after current handler support is confirmed, using the same Event ID and existing Inbox gate; it does not claim/requeue or mutate Outbox or its attempt/redrive state. Quarantine is uniquely keyed `(consumer_id,event_id)`, payload-free, retains schema major/sanitized error/first quarantined_at, and references source Event retained 365d. Replay audit records a unique replay_request_id, consumer/event/version/source, DB time, sanitized outcome, and session_user; denied requests are recorded. No human actor attribution is claimed; only trusted `paddock_app` Coordinator can request replay. Replay eligibility is strict before 30d; at/after the boundary or after source retention expires it is denied.
  - `open_design_choice`: NONE after D-019–D-022; selection is policy scope only, not DB effect approval.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: focused `go test ./internal/governance/domain -run 'EventSchema|CompatibilityQuarantine|Retention|ConsumerReplay' -count=1` PASS; full `go test ./... -count=1` PASS; `go vet ./...` PASS; tagged PostgreSQL compile-only `go test -tags='integration paddock_test' -run '^$' ./internal/storage/postgres -count=1` PASS with no body; `gofmt -d`, `python3 scripts/lint_design.py` (89 issues/149 edges), and `git diff --check` PASS. Added pure policy contracts/tests for canonical schema parsing/fail-closed unknown major, quarantine key/first timestamp, 7/90/365-day retention bounds/holds, trusted-service replay audit identity and sanitized outcomes, and replay source/support/expiry strict 30-day boundaries. A separate Verifier reviewed the S05 acceptance, D-019–D-022 and both complete source/test files; no actionable findings. No database migration, cleanup worker, quarantine/replay API, or DB test body was implemented/executed; no runtime enforcement is claimed. Receipt records commands, hashes and residual risks.
  - `verification_receipt`: `receipts/PDK-M05-S05/2026-10-18-local-verification.json`
  - `independent_review`: Separate read-only Verifier reviewed `Issues.md` M05-S05 acceptance, D-019–D-022, and both complete pure Go policy source/test files; no actionable findings. It confirmed canonical schema parsing/fail-closed behavior, quarantine identity/anchor, retention holds/deadlines, replay boundary/support checks, trusted-service audit contract, and separation from Outbox mutation. It did not run tests, inspect Git diff/status, or access DB. Main reconciled the review with Runner observations and the recorded policy. CI attestation absent.
  - `remaining_gate`: NONE for the selected D-019–D-022 policy-recording and pure-domain boundary-test acceptance under D-016. Residual: no DB quarantine/replay/retention-worker enforcement is implemented or claimed; CI absent; worktree broadly dirty/full diff hash unavailable.
  - `next_action`: PDK-M05-S05 is DONE. Before new implementation work, reconcile the requested push/commit scope against the broadly dirty worktree; the next dependency-ready Issue is PDK-M14-S01.

### M06 / P0 / Governance Kernel・Policy検証・Approval

**中目標:** 自律改善できるPolicyと不変の信頼境界を分離。

- [ ] `PDK-M06-S01` — Immutable Bundle、Digest、署名、Version Pin。
  - `depends_on`: PDK-M01-S01, PDK-M02-S01, PDK-M06-S07, PDK-M06-S08
  - `acceptance`: 改竄Digest、署名不正、期限切れを拒否。ダミー署名を受け入れない。
  - `evidence_expected`: 正/負の署名テスト、固定公開鍵Fixture。
- [ ] `PDK-M06-S02` — G0/G1限定のKernel Boundary/ApprovalVerifier。
  - `depends_on`: PDK-M06-S01
  - `acceptance`: 新Policyが自分を承認しない。Issuer上限/固定Kernel違反は拒否。G2/G3は未実装ならFail Closed。
  - `evidence_expected`: Unit Test、Fixture、検証Digest。
- [ ] `PDK-M06-S03` — Shadow Replay / Semantic Diff / Attack Fixture。
  - `depends_on`: PDK-M06-S02
  - `acceptance`: DENY→ALLOW差分・Sybil/偽評価・Evidence欠落を分類し、PASS/FAIL/HOLD/ABORTを返す。
  - `evidence_expected`: 再現可能なPolicy/Evidence FixtureとExit Code。
- [ ] `PDK-M06-S04` — Policy Activation CertificateとRevision照合。
  - `depends_on`: PDK-M06-S02, PDK-M06-S03
  - `acceptance`: Base Epoch/Policy Digest/Kernel Digest/Issuer Revisionが更新されれば旧承認を再利用できない。
  - `evidence_expected`: TOCTOU競合テスト。

- [x] `PDK-M06-S05` — 人間Break-glass / Emergency StopとSafety Plane。
  - `depends_on`: PDK-M00-S06, PDK-M02-S06
  - `acceptance`: PoC境界はトランザクション内SafetyGateによるローカルdispatch/Grant/高リスク操作直前の認可検査とする。自律Policy系から独立した2-of-3人間認証、停止時のSecurity Epoch昇格、独立した解除手続き、停止/frozen/権限読出し・transaction error時のFail Closedを検証する。配備済みnetwork Gateway/Schedulerへの強制、外部side effectとの原子性・TOCTOU解消、物理オフライン端末停止は保証・受入範囲外。DB outageはtransaction/read error注入で検証し、実サーバ切断試験とは主張しない。
  - `evidence_expected`: 誤署名・権限不足・transaction/read error注入・停止解除のunit/integration試験。
  - `current_evidence`: User selected 2-of-3 stop and release with externally injected PoC public-key sets; production trust-root custody/bootstrap/rotation remain OPEN under O-002/O-010. Commit `c38b818578702bbc0bc40240dcd03341952c852e` is pushed as IMPLEMENTED. At exact commit Runner: related domain/port/application/postgres `go test -count=1` PASS; matching `go vet` PASS; design lint 89/148 PASS; diff-check PASS. Fresh guarded preflight identified paddock_test PostgreSQL 18.6/raw_relations=26; verbose `TestPostgresGovernanceIntegration` PASS (1.302s), including rollback-only DB-backed Stop/Release, receipt replay/conflict, fresh SafetyGate denial/allow checks, stale CAS and global epoch lock contention. Post-run fixture and safety receipt counts all zero. Separate verifier reviewed final source and allowed push as [~], not DONE. No CI attestation. Residual: this is a reusable transaction-backed local gate, not a deployed Gateway/Scheduler; TOCTOU before external side effect remains; production key lifecycle remains OPEN. `go test -race` unavailable on android/arm64. Current Runner observation on worktree overlay at HEAD `1dbebbfc8585ab312f69a1985a64156a61852df6`: `go test ./internal/governance/domain ./internal/governance/port ./internal/governance/application -count=1` PASS; matching `go vet` PASS; `python3 scripts/lint_design.py` PASS (89/148); `git diff --check` PASS. Guarded DB preflight PASS, database=`paddock_test`, PostgreSQL 18.6, raw_relations=26. Isolated `go test -tags=integration ./internal/storage/postgres -run '^TestPostgresGovernanceIntegration/SafetyService_receipts_in_rollback-only_transaction$' -count=1 -v` PASS (0.617s; test body 0.32s), confirming actual PostgreSQL SafetyService stop/release and SafetyGate integration in rollback-only transaction. Broader integration parent test was also attempted and FAILED in adjacent `AppendEvent envelope...` case: existing `raw.domain_events` table lacks `schema_version` (SQLSTATE 42703); SafetyService subtest and remaining stale-CAS/lock cases passed in that run. This unrelated failure is disclosed, not treated as M06-S05 PASS. Tested-source SHA-256: `safety_gate.go` `3599bde4c1e88dc8c23e39350c08cd6141a4b9fcc0ed2c0e57f6fcbf0588bf54`; `safety_gate_test.go` `a9d84dce03c89e47510f4aeca511627e43274f5b5c0cc4576d96d3043be4c55a`; `safety.go` `ed6ee836923663e5e75f39a0e42a48957684b0220f2f85301659bf646f3dd8b1`; `governance_tx.go` `4d31684961ef42df7295778b36fac75e3b4761d96516654017621c13dea79b05`; integration test `42ae538cd2dca9228d36f7028d85ab6d9955f3194b6cd0a0de1264db86868b27`. Separate verifier reviewed the revised acceptance and source at this boundary; it confirmed the local gate claim while retaining the external Gateway/TOCTOU and production key lifecycle limitations. No CI attestation or live DB-disconnect test is claimed.
  - `next_action`: PDK-M06-S05 is DONE for the user-selected local transaction-backed SafetyGate boundary. Continue with READY PDK-M08-S01. Retain residuals: deployed Gateway/Scheduler, external-effect TOCTOU, production key lifecycle, real DB-server disconnect, and adjacent failing event schema test are not claimed as completed by this issue.
- [ ] `PDK-M06-S06` — LKG失効時の組込みSafe Baseline。
  - `depends_on`: PDK-M06-S05, PDK-M06-S01
  - `acceptance`: LKG署名失効/不整合/不在ならdeny-allへ安全に退避。通常Approval待ちなしでRollbackでき、復帰には人間認証・新規Activationが必須。
  - `evidence_expected`: 失効/破損LKG Fixture、SAFE_STOPPEDとGateway拒否検証。
- [*] `PDK-M06-S07` — Canonicalizationと署名用途分離（O-008）。
  - `depends_on`: PDK-M00-S06
  - `acceptance`: JCS等の確定Byte Codec/型制限、Bundle・Approval・Commandの用途タグ、署名対象schema_versionとanti-replay文脈を仕様化し検証。
  - `evidence_expected`: Golden Vector、Key順/Unicode/数値Fixture、cross-protocol署名拒否。
  - `current_evidence`: Concrete `*JCSCodec` backed by pinned `github.com/deszhou/jcs v1.1.0` (Apache-2.0); arbitrary Codec injection is not accepted by Envelope. Fixed canonical-byte vectors cover UTF-16 key ordering, escaping, Unicode, number notation/rounding/negative zero; input tests cover malformed JSON, invalid UTF-8/surrogates, escaped-equivalent duplicate keys and ±(2^53−1) integer boundary. Domain/schema/audience/request/nonce are included in the envelope. Table-driven Ed25519 checks cover Bundle→Approval, Bundle→Command and Approval→Command rejection. Runner receipt `receipts/PDK-M06-S07/2026-10-14-jcs-tests.json`: Go test suite and vet PASS, integration-tag compile-only PASS (no DB), portability compile PASS for Windows/Linux/Android arm64 (no target runtime claim), design lint 89/148 PASS and diff-check PASS; exact source hashes are recorded. Separate verifier reviewed implementation and matrix; no blocking defect. Local-only evidence; no CI attestation.
  - `remaining_risks`: Only one direction per unordered domain pair is tested; focused vectors are not exhaustive RFC Appendix B coverage or an independent cryptographic audit; platform checks compile only; worktree is dirty and tested source is not committed.
  - `next_action`: Reconcile the Issue/cursor record and isolate the S07 files from unrelated dirty work before proposing the tested unit for commit/push; do not claim CI or target-OS runtime validation.
- [x] `PDK-M06-S08` — PoC専用署名鍵・Fixture/Trust Root配置（O-002）。
  - `depends_on`: PDK-M00-S06
  - `acceptance`: テスト専用公開鍵の配置、秘密鍵の非Git・非ログ、期限/失効/回転の検証経路と本番鍵との差を固定。
  - `evidence_expected`: Key provenance・test-only labeling・不正Keyでの拒否Fixture。秘密鍵内容は記録しない。
  - `current_evidence`: RFC 8032 §7.1 Test 1 public Ed25519 vector stored without private key bytes; README and JSON explicitly test-only and disclaim production authority. `internal/testkeys/poc_fixture_test.go` verifies the vector and rejects tampered message/signature; fixed-time pure fixture cases cover valid, expired, revoked, rotation successor accepted, and old non-revoked key rejected by active fingerprint mismatch. O-002 algorithm/custody remain OPEN. Independent local verifier: `GO111MODULE=off go test ./internal/testkeys` PASS; full unittest 15/15 PASS; design lint PASS (89 issues/148 edges); `git diff --check` PASS. Local evidence only, not CI attestation.


### M07 / P0 / Hybrid Epoch・Scoped Canary・Rollback

**中目標:** Root隔離を維持し、安全にPolicyを更新・戻す。

- [ ] `PDK-M07-S01` — `EffectivePolicy(scope, root)`とCanary Overlay。
  - `depends_on`: PDK-M04-S01, PDK-M06-S02
  - `acceptance`: Root Bのみv2、Root Aはv1、全体Security失効だけ横断適用。
  - `evidence_expected`: Root A/Bの40→41 Fixture。
- [ ] `PDK-M07-S02` — Canary 4結果とGateの自動判定。
  - `depends_on`: PDK-M07-S01, PDK-M06-S03
  - `acceptance`: PASS/FAIL/HOLD/ABORTを区別。証拠不足は絶対PASSにしない。
  - `evidence_expected`: 分岐テストとDecision Receipt。
- [ ] `PDK-M07-S03` — Promote / MONITORING / Single Active Slot。
  - `depends_on`: PDK-M07-S02, PDK-M07-S06
  - `acceptance`: v2が両Rootに適用、Epoch42。Monitoring中の次Rollout反映拒否。
  - `evidence_expected`: Transaction Integration Test。
- [ ] `PDK-M07-S04` — LKG Rollback + Credential/Attemptの再評価。
  - `depends_on`: PDK-M07-S03, PDK-M07-S07, PDK-M06-S06
  - `acceptance`: Digest=v1に戻りEpoch43。古いEpochの模擬操作拒否。戻せない外部副作用は報告。
  - `evidence_expected`: Rollback Fixture、失効/監査Event。
- [ ] `PDK-M07-S05` — Policy Bundle同期とWorker Stale取扱い。
  - `depends_on`: PDK-M07-S04
  - `acceptance`: 古いWorkerはローカル計算条件付き続行可、高リスクGateway操作は最新Epoch確認まで拒否。
  - `evidence_expected`: 通信断・古いManifestテスト。

- [ ] `PDK-M07-S06` — MONITORING/HOLDの期限・出口・強制終端。
  - `depends_on`: PDK-M07-S02, PDK-M03-S06
  - `acceptance`: 観測期限+検証PASSで`MONITORING→COMPLETED`、HOLDにはDB時刻ベースの最大Deadline。超過はABORT→ROLLING_BACK/SAFE_STOPPED。slotは故障条件を除き永久占有しない。
  - `evidence_expected`: Freeze Clock/Deadline/Reaper/DB停止のState Test。
- [ ] `PDK-M07-S07` — 3層Epochと二相RollbackをGateway/DBへ適用。
  - `depends_on`: PDK-M01-S06, PDK-M07-S01, PDK-M06-S05, PDK-M02-S06
  - `acceptance`: CanaryでRoot AのGrantを誤失効しない。`ROLLING_BACK`開始でScope Freezeし、最終切替時にScope/変更Root Epochを各1回だけ増やす。Security Stopは全Rootへ伝播。
  - `evidence_expected`: Root A/BのToken/Grant隔離試験、Rollback競合とEpoch Assertion。


### M08 / P1 / WorkOrder DAG・Pull Scheduler・Lease

**中目標:** Active-Active Schedulerでも仕事の実行権が一意になる。

- [x] `PDK-M08-S01` — WorkOrder/Dependency/Attempt永続化。
  - `depends_on`: PDK-M01-S03, PDK-M03-S02
  - `acceptance`: 親子Tree・Root内DAG・Attempt試行履歴が追跡可能。
  - `evidence_expected`: DDL・DAG循環・cross-root拒否テスト。
  - `current_evidence`: Added one-Root `WorkOrderGraph` validation, atomic pgx `PersistGraph`/repeatable-read `LoadRoot`, guarded additive up/down SQL for ownership/dependency/attempt tables, same-Root composite FKs, positive unique attempt sequence, advisory-lock serialized cycle triggers, immutable identity/contents on UPDATE while DELETE is permitted for retention cleanup, integration test, and static SQL contract tests. Runner on worktree overlay at HEAD `9c9910f5b8682a8ef7debe37e1474293e3a6aa0a`: `go test ./internal/governance/domain ./internal/storage/postgres -count=1` PASS; matching `go vet` PASS; `go test -tags=integration ./internal/storage/postgres -run '^TestWorkOrderStorePostgresIntegration$' -count=1 -v` PASS (6/6: READ COMMITTED concurrent reverse-edge serialization, REPEATABLE READ rejected with 40001, dependency-cycle rejection, cross-root rejection, ownership-cycle rejection, unique attempt sequence); integration-tag compile-only PASS; Python schema tests 5/5 PASS; design lint PASS 89/148; `git diff --check` PASS. Dedicated migration `sql/governance_work_orders.sql` applied to `paddock_test` PostgreSQL 18.6 after read-only identity/privilege/object preflight and explicit user approval. DB verifier confirmed four fixture categories (`wo_it_` Scope, Root, WorkOrder, Attempt) all have zero remaining rows; applied objects present. First DB run surfaced a cleanup-trigger conflict; with explicit user approval, the two history triggers were changed to reject UPDATE only and only the identified failed test fixture was removed. Final integration rerun passed and confirmed cleanup. Source SHA-256: graph.go `13bdae497607d8cd9607e7878e02ca63d05935ee8419ce4d3c1be4969adbe4ba`; work_order_test.go `038911c6065a9c9c0efba0458ea425d5be0841feb366e84746193784bf71d56c`; store.go `cf824406b5cbd850bd10308b269a35917f72281b885e4780a03aedabc985f2a6`; integration_test.go `7a46816a6d6bab9bdee1ee94130f27e85ccdcb7e655e96dc17316577267dc9e0`; up.sql `499d3be1715adb5c6b84a8e908cbb0302f9788cbf77149ad03765e33b728cfac`; down.sql `c6411073cb828023f5d280dbf3b7c5e31fd3735ee04d00234a01b9a72a1348e3`; schema test `127cc10b2ff8e2881dedf5d5714786d11da8c147397ea315d5483e60d9bbea3f`. No CI attestation claimed.
- [x] `PDK-M08-S02` — Worker Pull/Capability Filter/Slot予約。
  - `depends_on`: PDK-M08-S01
  - `acceptance`: Hard条件適合後にAuthority/Trust/Budget検査し、一つのSlotを原子的確保。
  - `evidence_expected`: Concurrent Pull Integration Test.
  - `current_evidence`: The local implementation persists canonical WorkOrder capability requirements with a configured bit; explicit empty config means unconstrained and requires empty candidate/evidence. Config is allowed only while QUEUED and unconfigured; readiness requires config and DONE predecessors. PullStore locks the row, loads canonical requirements, matches them against Candidate and Worker Evidence, then atomically reserves slot/Attempt after opaque permit and mandatory injectable Authority/Trust/Budget gates. Runner final: `python3 -m unittest tests.test_m08_pull_sql -v` PASS (5/5); `python3 scripts/lint_design.py --emit-summary` and lint PASS (89 issues/148 edges); `git diff --check` PASS; `go test ./internal/governance/scheduler ./internal/storage/postgres -count=1` PASS; matching `go vet` PASS; `go test -tags=paddock_test -run '^$' ./internal/storage/postgres` compile-only PASS; two-connection `go test -tags=paddock_test ./internal/storage/postgres -run '^TestPullReservationConcurrentOneWinner$' -count=1 -v` PASS. Setup/app identities were `paddock_test/current_user=paddock_migrator` and `paddock_test/current_user=paddock_app`. Up migration plus separately approved guarded `CREATE OR REPLACE` repair for only `raw.configure_work_order_capabilities(text,jsonb)` applied on paddock_test; read-only function-definition readback confirmed `jsonb_object_keys` present, obsolete helper absent, and both Pull tables present. Final read-only cleanup verified zero `pull_it_` scope/root/WorkOrder/dependency/attempt/slot/capability rows. Independent scoped source review PASS; Main reconciled source, Runner output, DB identity/object/readback, and cleanup. No down migration, role change, or ownership change; no CI attestation. Source SHA-256: pull.go `893b651cac2c2348ac96872936603fe6e931b36806f8aa6d97755c75ef3f5b5a`; pull_test.go `24f14de2d618f1656a5520019ce80c0855786b4d329652d0bc09b9a08b36a5f7`; pull_store.go `177f4fb744d3b0d7879ae266153898478136dc524f328b09c45483ecd05012f3`; pull_integration_test.go `1c0fc987755cc98fa14fcdd1c4d5d5442a3446509301187a962f1f600002f4bb`; up migration `27591bb90b7e473c8cc8b0ac7a22a1da17c7a2940ea71ee55136bd92f30c2bce`; guarded repair `3992999419c3b1672899427405324bb393eb134eac01da4adaab330a13098bc1`; down `b8ea56752adeef37b2e0619b2e0f266869ec4d2af6af4832fa358dd1ef534920`; SQL tests `eae647b1108d5743002178200d5196230e03318cf64290c50bfa3df11bea4c13`; DB guide `c543489ea07cb71fd348c42f7d8526183a578261a63554aa3389ee7933d312d6`. No CI attestation.
  - `residual_risk`: The database function does not itself enforce Coordinator Authority/Trust/Budget/Permit gates; the trusted Coordinator boundary and credential confinement to the Coordinator remain as explicitly accepted for this PoC. Lease/completion APIs are out of scope.
- [x] `PDK-M08-S03` — Lease TTL/Heartbeat/Reaper/Fencing。
  - `depends_on`: PDK-M08-S02
  - `acceptance`: 古いEpochのAttempt結果を拒否し、新Attemptへ安全に移行。
  - `evidence_expected`: Worker停止・再起動・遅延応答Fixture。
  - `current_evidence`: S03 source is implemented within the named lease/pull Go and SQL files. The trusted Coordinator supplies per-operation TTL/heartbeat extension; Worker has no TTL field; SQL rejects null/non-finite/non-positive intervals and uses PostgreSQL `clock_timestamp()`. A unique current lease per WorkOrder references the matching immutable Attempt, WorkOrder `lease_epoch` advances on every issue, heartbeat and completion bind WorkOrder/Attempt/worker/session/epoch, reaper locks WorkOrder first and only requeues expired leases while preserving Attempts, and the app's S02 lease-free reserve is revoked. Integration source covers concurrent Pull, heartbeat, worker-stop expiry/reap/reissue, monotone epoch/attempt number, stale heartbeat/completion rejection, current completion and cleanup. Runner at worktree HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: `python3 -m unittest tests.test_m08_lease_sql -v` PASS (6/6); `python3 -m unittest tests.test_m08_pull_sql -v` PASS (5/5); `go test ./internal/governance/scheduler ./internal/storage/postgres -count=1` PASS; matching `go vet` PASS; `go test -tags=paddock_test -run '^$' ./internal/storage/postgres` compile-only PASS; `python3 scripts/lint_design.py` PASS (89 issues/148 edges); `git diff --check` PASS. Independent scoped source review PASS. The approved `sql/governance_lease.sql` up migration applied on `paddock_test` as `paddock_migrator`. Runner identity checks passed for setup (`paddock_test/paddock_migrator`) and app (`paddock_test/paddock_app`). The two-connection `go test -tags=paddock_test ./internal/storage/postgres -run '^TestPullReservationConcurrentOneWinner$' -count=1 -v` PASS (19.71s); final fixture readback reported zero scopes, roots, WorkOrders, dependencies, attempts, slots, capabilities, and leases. Post-run DB readback confirmed all four lease functions are SECURITY DEFINER with `search_path=pg_catalog` and owned by migrator, lease table present, legacy S02 lease-free reserve not executable by app, and no active leases. No down migration, role changes or ownership changes; no CI attestation. Source SHA-256: pull.go `7ee57fe1c21b9fa6496cff537465e827b4923fc0d666ff8eaad1d0b69b0d5bfb`; pull_test.go `50dcc612034ece3cf85e66542d0c6c5a66b14f79a49b523d5fc782818a6dca6f`; pull_store.go `6c060f315c0cc7da5e853f12dae15bfefe56d254b22080c1a8deb79270a525f0`; pull_integration_test.go `10dd08511e1a6aaaa9d6e54ce384fd70c522ce1958f4f77dcd998b89b84ed16c`; up migration `197bedc916fe6b1d3fa50ec09bfdcd07274f4eb4d9c0cab81d859435b081a198`; down `fc9bb41bb83a29aff08c9b589509838422c2b09f545b28a8f27641b04a79f695`; lease SQL tests `14ef1d30532e11fdc8a74c730d4d26455a3e3e8fbde0b4d566a7bbb2df447ebc`; Pull SQL tests `5423ab29dab34209a81f4bfad23cd2fffe2ebbbf2173810a0516044808ea8111`. No CI attestation.
  - `next_action`: PDK-M08-S03 is DONE; PDK-M08-S04 is the next dependency-ready issue. Do not run down migration. Production TTL/heartbeat/reaper timing bounds remain OPEN under O-006/M08-S05.
  - `residual_risk`: No production TTL, heartbeat or reaper schedule/bounds are selected; Coordinator-supplied positive finite TTL may be long until M08-S05/O-006 defines policy, and reaper liveness depends on Coordinator scheduling calls. SQL matches opaque Worker/session values but does not authenticate them; app credential confinement to the trusted Coordinator remains required. No CI attestation or dedicated commit; keep `verified_commit: NONE`.
- [~] `PDK-M08-S04` — WorkOrder Policy別Offline運用。
  - `depends_on`: PDK-M08-S03
  - `acceptance`: 投機ローカル計算と外部副作用を区別。オフライン中のGateway操作は不可。
  - `evidence_expected`: Offline Grant/Fencing Test。
  - `current_evidence`: Decisions.md D-005/§4–5 says classify work by `ONLINE_REQUIRED`/`OFFLINE_COMPUTE` plus `CHECKPOINTABLE`; offline allowance is preallocated and permits only local computation/checkpoint, while publishing, Git push, secrets and every external side effect are forbidden. Reconnect artifacts must be fenced by current Attempt/`lease_epoch`; L1 local checkpoints are candidates, not automatically durable/verified. No pre-existing OfflineGrant or Gateway implementation existed. User selected a PoC-only pure domain policy/fencing seam and then authorized a new Coordinator-side Gateway facade; actual external-adapter wiring is explicitly to remain unverified. Implemented `offline_policy.go`: a Coordinator-verified claim binds GrantID, Root/WorkOrder, Attempt, Worker/session, nonzero LeaseEpoch, policy digest, policy axis and checkpointability; invalid/missing verifier, policy/identity mismatch, invalid monotonic time, TTL expiry, unknown/duplicate/external operation claims fail closed. Session stores unexported process-local state; offline authorization permits only claimed local compute/checkpoint (checkpoint requires CHECKPOINTABLE); external effects always deny. Added `application/offline_gateway.go`: offline session denies without calling ports; otherwise a required online authorizer must allow before the external adapter is invoked once. Invalid requests/missing dependencies fail closed; adapter errors map to an unknown-outcome sentinel. Fake-port tests cover offline denial, authorization, dispatch, sanitization and payload isolation. The facade explicitly cannot block direct network bypasses; no concrete authorizer/adapter is wired. A local checkpoint produces only an opaque in-memory L1 candidate; reconnect predicate requires exact current lease and policy. Runner at worktree HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`: `go test ./internal/governance/domain ./internal/governance/application ./internal/governance/scheduler ./internal/storage/postgres -count=1` PASS; matching `go vet ./internal/governance/domain ./internal/governance/application ./internal/governance/scheduler ./internal/storage/postgres` PASS; `go test -tags=paddock_test -run '^$' ./internal/storage/postgres` compile-only PASS; lease SQL contract 6/6 and Pull SQL contract 5/5 PASS; design lint PASS (89 issues/148 edges); `git diff --check` PASS. `go test -race ./internal/governance/domain -run '^TestOffline' -count=1` could not run because race detector is unsupported on android/arm64. Independent final static source review PASS. No S04 DB operation or external-adapter integration ran. Source SHA-256: `internal/governance/domain/offline_policy.go` `8deb7fa2aa71a5d1e99f669f64f2f955bd70cdecac8b06c5576343f565afa0e6`; `internal/governance/domain/offline_policy_test.go` `43f8e8a92bb5a395c60d537e0361a4d1640413efff231f1bcb42562bb3e89dd6`; `internal/governance/application/offline_gateway.go` `cb4d2ad757c9514d2be35e259c94e48c2f4c41dae1230c65c0313e7df47d2b4b`; `internal/governance/application/offline_gateway_test.go` `e7f0a3640153170a7daff7cd62f1df2e3bb174da9daaebb60c0cf1704b7abf9d`. Cross-issue boundaries: M06-S08 has only test-key fixture and O-002 production anchor remains OPEN; M08-S05 owns O-006 timing bounds; M09-S01 escrow; M09-S03 durable checkpoint; M09-S04 budget reservation/reconciliation.
  - `design_proposal`: User-selected scope is a PoC-only pure policy/fencing seam plus a new Coordinator-side in-process Gateway facade. TTL is Coordinator-configured and checked against a per-process monotonic clock captured before verifier work; clock rewind fails closed and invalidates the session; process restart needs a fresh Worker SessionID and re-verification. The verifier implementation must authenticate claims, check policy digest against the complete binding, and prevent replay; this repository supplies only the interface. The facade denies external effects when an OfflineSession is present and otherwise requires an OnlineAuthorizer before dispatch. Per user instruction, no concrete external adapter is connected here; real-environment enforcement remains unverified. This task selection is not a new ACCEPTED entry in decisions.md.
  - `next_action`: Resume only after scoped approval for guarded `paddock_test` migration/runtime verification and an exact external-effect operation contract; otherwise retain source-only implementation with DB runtime/end-to-end Gateway enforcement unverified.
  - `push_scope_note`: User authorized including the shared M08-S04 domain policy and application Gateway facade source/tests as dependencies for completed M08-S05/M09 source. These files remain associated with an M08-S04 `[~]` Issue; the concrete external adapter, deployed Gateway enforcement, and end-to-end effect atomicity are still unverified. M13-S01 WIP source remains excluded.
  - `continuation_contract`:
    - `task_id`: `PDK-M08-S04`
    - `approval`: `user_selected=DB_POLICY_PERSISTENCE`; `source_code_and_tests=IN_SCOPE`; `DB_RUNTIME=NOT_RUN`; `CREDENTIALS=FORBIDDEN`
    - `authority`: `D-005`; this schema is a bounded implementation proposal, **not** a new ACCEPTED decision.
    - `policy`:
      - `mode ∈ {ONLINE_REQUIRED, OFFLINE_COMPUTE}`
      - `checkpointability ∈ {CHECKPOINTABLE, NOT_CHECKPOINTABLE}`
      - `online_external_actions`: explicit Unicode-capable action-ID allowlist; wildcard/implicit-all forbidden.
      - `low_risk_actions`: [~] future M08-S05 extension; explicit subset of `online_external_actions`; omission means HIGH; list must be included in canonical policy digest before any cache can use LOW.
      - `canonical`: SQL constructs/verifies exact RFC 8785 JCS bytes from typed axes + actions + explicit `low_risk_actions` (empty array when none); all action arrays use UTF-16 code-unit order.
      - `digest`: PostgreSQL computes SHA-256 over those exact JCS bytes and rejects caller mismatch; no extension dependency.
      - `configure`: once, while WorkOrder is `QUEUED`; immutable after execution starts.
    - `online_authorize`: match DB-current Root/WorkOrder/Attempt/Worker/Session/LeaseEpoch + unexpired lease using DB clock + persisted digest/mode + allowlisted Action; missing/mismatch/error ⇒ DENY.
    - `effect_boundary`: policy persistence + authorization only; arbitrary SQL dispatch, concrete live-effect semantics, and TOCTOU/idempotency guarantees are OUT_OF_SCOPE.
    - `execution_boundary`: no DB connection/runtime, migration application, credential use, or production access in this slice.
  - `blocker`: The Coordinator-side facade and DB-backed policy/authorizer source exist; Runner package tests/vet, SQL static contracts, and independent source review pass, including JCS digest integrity and byte-exact action matching. SQL migration/runtime was not run; no concrete external adapter, signed grant verifier, durable checkpoint, or authorization-to-effect atomicity exists. Therefore the original end-to-end acceptance is unverified. Keep `[~]`, no DB runtime or CI attestation claimed.

- [x] `PDK-M08-S05` — Lease期限のDB Clock・Gateway staleness境界（O-006）。
  - `depends_on`: PDK-M08-S03, PDK-M03-S06
  - `acceptance`: 失効時間はDB Clockで評価し、Worker側の時刻変更でLease延長不能。Gatewayの最大stalenessを測定して高リスクは不明時deny。
  - `evidence_expected`: Clock skew・TTL・DB停止・Gateway再接続Fixture。
  - `selected_design`:
    - `gateway_staleness`: user-selected tiered policy; HIGH=0s cached staleness (synchronous DB reauthorization before every effect; DB error=DENY); LOW may continue from the last DB-authorized cache while DB is unavailable, with no fixed 5s cap, but only until the last DB-observed Lease expiry or Coordinator process restart; on DB recovery, synchronously reauthorize before the next effect.
    - `risk_source`: user-selected WorkOrder Policy `low_risk_actions` allowlist; an authorized Action in the list is LOW, all other/unknown/unclassified Actions are HIGH; Action outside the external allowlist=DENY.
    - `policy_binding`: `low_risk_actions` MUST be an explicit subset of `online_external_actions` and included in RFC 8785 JCS policy bytes/digest; missing/invalid classification defaults HIGH, never LOW.
    - `decision_read`: DB returns allowed/denied, risk tier, and remaining Lease lifetime computed using PostgreSQL DB clock in one read; malformed/missing snapshot=DENY.
    - `cache_clock`: Coordinator process monotonic clock only; Worker clock is never trusted. LOW decision cache is Coordinator-process local and may survive DB outage only until previously DB-observed Lease expiry or process restart (user-selected, no fixed 5s cap); on DB recovery, reauthorize synchronously before the next effect. HIGH always performs DB reauthorization and DB error=DENY. A fresh DB denial invalidates any cached LOW allow. Missing DB time/epoch/policy/lease evidence, clock rewind, or uncertainty in the bound=DENY/cache invalid.
    - `application_api`: `AuthorizationRisk ∈ {HIGH,LOW}`; `AuthorizationSnapshot{Allowed bool,Risk AuthorizationRisk,LeaseRemaining time.Duration}` from `AuthorizationSnapshotReader.ReadAuthorization(ctx,op)`; only typed `ErrAuthorizationUnavailable` permits LOW cache fallback, never fresh DENY, malformed response, policy mismatch, or caller-context cancellation.
    - `cache_api`: `CachedOnlineAuthorizer` is constructed with an `AuthorizationSnapshotReader` and process-local monotonic `Elapsed() time.Duration` clock; no global/shared/persisted cache.
    - `cache_key`: exact tuple `(RootID,WorkOrderID,AttemptID,WorkerID,SessionID,LeaseEpoch,PolicyDigest,Action)`; each fresh successful DB read replaces/refreshes that tuple; a fresh denial invalidates it.
    - `effect_boundary`: this design selection is not DB runtime/migration approval, credential approval, or external-effect approval; preserve M08-S04's explicit DB runtime gate.
  - `approved_continuation`: User selected DB runtime scope `M08-S04/S05 + M09-S01`, and explicitly authorized use of existing operator-injected connections only for `paddock_test`; no credential display/storage, production/llm-memory access, down migration, reset, or external effect dispatch.
  - `migration_observation`: `sql/governance_offline_policy.sql` and `sql/governance_budget.sql` applied to verified paddock_test as paddock_migrator, PostgreSQL 18.6; each first application COMMIT observed. A later duplicate full M09 apply rolled back on pre-existing `budget_unit_valid`; the corrected `budget_apply` body was applied separately with guarded CREATE OR REPLACE. Read-only postcheck confirmed S04 columns, M09 tables/functions, owners, app function EXECUTE, no app table SELECT, and no PUBLIC budget function EXECUTE.
  - `dispatch_diagnostic`: Earlier `Permission denied: Agent 'Plan' ... 'general'` was a separate caller-role authorization failure. Repeated `general` CODE dispatches failed with `LLM session not configured`; global Crabcode config was updated per user selection with backend-neutral role definitions, preserving provider/orchestrator and adding no model overrides or credentials (config SHA-256 `7763eaa01fdc3a2b75d5b6f733bcc8c27bc52c99dcde04c194dc76daa9e37051`). JSON/role/task-permission invariants passed. A bounded read-only `functions.task` probe has twice returned `GENERAL_SESSION_READY` (before and after config), but subsequent CODE dispatches still failed with `LLM session not configured`; therefore probe readiness does not imply CODE worker session availability and config causality is UNCONFIRMED. No credential values were read/printed; no provider endpoint/model was invoked. `functions.task` exposes no model selector.
  - `current_evidence`: Main Runner at dirty worktree overlay on target revision `2f1dcfe143c3ef66e33d82c003e2432256b11518`; full Go tests/vet PASS; related SQL source contracts 29/29 PASS; full tagged paddock_test PostgreSQL suite PASS (38.913s). M08 snapshot checks app policy configuration, LOW/HIGH/deny risk decisions, fencing and Lease expiry; M08 fixtures cleaned. Read-only postcheck confirms app function-only access and DB state. No external effect dispatch, down migration, or CI attestation.
  - `independent_review`: Separate Verifier reviewed the full source and M08 runtime receipt; hashes match all targets, no actionable discrepancy. Remaining effect atomicity is explicitly out of scope and is not claimed.
  - `receipt`: [M08-S05 local source-slice receipt](receipts/PDK-M08-S05/2026-10-16-source-slice.json)
  - `remaining_gate`: `[x]` under D-016 local verification: Runner acceptance and independent receipt/source review pass, with Main reconciliation complete. No M08-S04 external-effect enforcement is inferred.
  - `next_action`: PDK-M08-S05 is DONE under D-016 local verification. No M08-S04 external-effect atomicity or dispatch enforcement is claimed.


### M09 / P1 / 階層Budget・Checkpoint

**中目標:** 再帰的な自律作業で資源上限を守り、途中から復旧できる。

- [x] `PDK-M09-S01` — Budget Account / Escrow Ledger。
  - `depends_on`: PDK-M08-S01
  - `acceptance`: `spent + reserved + delegated <= granted`をDBで守り、親子二重計上をしない。
  - `evidence_expected`: 同時委譲、返還、上限超過Fixture。
  - `implementation_contract`:
    - `unit_model`: user-selected `resource-specific integer quanta`; account key includes `root_id, resource_kind, unit_code`; user-selected unit format=`NFC Unicode`; require valid UTF-8, already NFC-normalized, nonempty, no edge whitespace, no Unicode control characters; compare exact canonical UTF-8 bytes; BIGINT nonnegative counters; cross-resource/unit conversion=FORBIDDEN.
    - `allocation_identity`: user-selected `dedicated allocation_id`; each delegate creates one immutable allocation row `(allocation_id,parent_account_id,child_account_id,amount,state=OPEN)`; child references exactly one allocation; settlement names allocation_id, verifies both endpoints and amount, and transitions OPEN→SETTLED exactly once. No aggregate `delegated >= child.granted` substitute for allocation identity.
    - `root_grant_authority`: user-selected `operator/migrator only`; `paddock_app` MUST NOT create or increase Root grants. Application role may delegate/reserve/spend/settle only within the existing granted balance; root initialization uses a separate migrator-only SQL entry point.
    - `invariant`: per account/resource/unit, `spent + reserved + delegated <= granted`; `available = granted - spent - reserved - delegated`; overflow/underflow=DENY.
    - `delegate`: lock parent account; require same resource+unit and `available >= amount`; parent `delegated += amount`; create exactly one child account with `granted=amount`; append journal event in same transaction.
    - `reserve_and_spend`: reservation increases `reserved`; settlement requires `actual <= reserved`, then atomically `reserved -= reserved_amount` and `spent += actual`; unused amount becomes available; operation IDs are idempotent and conflicting replay=DENY.
    - `child_settle`: require child terminal, `reserved=0`, `delegated=0`, and no open descendants; atomically parent `delegated -= child.granted`, parent `spent += child.spent` exactly once, close allocation; `child.granted-child.spent` returns to parent available. Child counters are evidence, not separately added to root aggregate while escrowed.
    - `ledger`: append-only transaction journal for grant/delegate/reserve/spend/release/settle transitions; counters, allocation state, operation receipt, and journal update atomically; same operation ID + same request returns prior result, changed request=DENY. Persistence layer is the idempotency boundary; domain transitions remain pure values.
    - `journal_deltas`: user-selected explicit BIGINT delta columns `granted_delta, spent_delta, reserved_delta, delegated_delta`, plus allocation/account identity; every operation row MUST record all counter movements so before→after state is reconstructible from journal without relying on current mutable counters.
    - `execution_boundary`: Go/SQL source and static/unit tests only; no DB connection, credentials, migration application, destructive reset, production access, or CI attestation in this slice.
  - `approved_continuation`: User selected combined M08-S04/S05 + M09-S01 guarded migration/runtime verification limited to `paddock_test`, and separately authorized use of existing operator-injected connection variables for that database only. Down migrations, reset/drop, production/llm-memory, credentials display/storage, and external effects remain OUT_OF_SCOPE.
  - `fixture_retention`: User selected unique `m09_it_` prefix fixtures retained in paddock_test because the journal is append-only; tests must preflight collision, record created IDs/counts in receipt, and never attempt cleanup/delete of budget journal/accounts/allocations.
  - `receipt`: [M09-S01 local source-slice receipt](receipts/PDK-M09-S01/2026-10-16-source-slice.json)
  - `current_evidence`: Main Runner on dirty worktree revision `2f1dcfe143c3ef66e33d82c003e2432256b11518`; full Go tests/vet PASS; 29 SQL contracts PASS; full paddock_test PostgreSQL suite PASS (38.913s). Budget acceptance verifies migrator-only grant, concurrent one-winner delegation, exact allocation/replay, reserve/spend/release/refund, over-limit/cross-unit denial, child settlement and journal reconciliation. Postcheck: five retained m09_it_ scope/root pairs, eight accounts, forty journal rows, four settled allocations, zero open/invariant/journal mismatches.
  - `independent_review`: Separate Verifier reconciled M09 runtime receipt against Issue contract, SQL/test source and Runner postcheck; no actionable discrepancy. Retained fixtures and duplicate-migration failure are disclosed.
  - `runtime_update`: Guarded S04/M09 migrations COMMIT on paddock_test PG18.6. Duplicate M09 apply rolled back transactionally; two runtime SQL defects were corrected with guarded `CREATE OR REPLACE`; full tagged suite then PASSed. M09 fixtures remain append-only and reconciled.
  - `extension_runtime`: User-selected `STORAGE_BYTES/byte` distinct resource was added to Go domain and guarded additive constraint migration. Runner: full Go tests/vet PASS; tagged compile PASS; 10 storage/M09 static contract tests PASS; guarded migration COMMIT on paddock_test PG18.6; `TestBudgetLedgerAcceptance` PASS with migrator grant, app delegation/reserve/spend/settle, wrong-unit rejection and journal reconciliation. Read-only postcheck: 2 storage accounts, unit mismatches=0, invariant violations=0, open allocations=0; parent (1000/237/0/0), child (400/237/0/0).
  - `extension_receipt`: [M09-S01 STORAGE_BYTES extension receipt](receipts/PDK-M09-S01/2026-10-16-storage-bytes.json)
  - `extension_review`: Separate Verifier reconciled the updated STORAGE_BYTES receipt, target hashes, exact retained fixture IDs and postcheck counts; no actionable discrepancy. Main compared report with Runner read-only output and resolved the missing inventory/count finding.
  - `next_action`: M09-S01 is DONE under D-016 after the STORAGE_BYTES extension; preserve the append-only m09_it_ fixture inventory. M09-S02 and M09-S03 selected designs are fully recorded; proceed with disjoint bounded source workstreams, with S03 runtime still separately gated.
  - `remaining_gate`: `[x]` under D-016 local verification; Runner runtime acceptance, independent source/receipt review and Main reconciliation complete. CI attestation absent. Append-only fixtures listed in receipt; no down/reset.
  - `reopen_reason`: User selected M09-S03 Budget linkage using the new `STORAGE_BYTES` kind; previous domain enum and database CHECK only accepted CURRENCY/TOKENS/COMPUTE. Keep this Issue ID and extend the accepted implementation within the same resource-separated integer-quanta contract.
  - `selected_extension`: `STORAGE_BYTES`, unit `byte`, BIGINT integer quanta; reuse same escrow/invariant/explicit journal deltas; no conversion to other resource kinds.
- [x] `PDK-M09-S02` — Spawn/Retry/Deadline/反復Fingerprint上限。
  - `depends_on`: PDK-M09-S01
  - `acceptance`: 新IDを乱発した循環修復でも上限を突破できない。
  - `evidence_expected`: recursion/new-ID evasion, Root depth/descendant/live-child caps, operation replay/conflict, DB-clock deadline, and Lease attempt-cap integration fixtures (`paddock_test` opt-in).
  - `selected_design`:
    - `difficulty_assignment`: Main publishes `D_pub=HARD` because this work spans DB security, Root-serialized concurrency, persistent invariants, and Lease/Attempt enforcement; each Worker MUST self-report `D_worker` on the same `EASY<MEDIUM<HARD` scale before CODE and stop/escalate if incomparable or above scope.
     - `policy`: Root-wide immutable `SpawnPolicy`; trusted Coordinator SECURITY DEFINER function may configure once per Root; missing/unlimited policy=DENY.
     - `coordinator_identity`: trusted Coordinator is isolated `paddock_app` session (Coordinator-only per `docs/database-test-environment.md`); owner remains `paddock_migrator`; Agents/Workers never receive app credentials or direct table access.
    - `fingerprint_trust`: user-selected trusted-Coordinator boundary; Go Domain/Coordinator strictly parses and canonical-JCS fingerprints the full proposal before calling SQL. DB trusts fingerprint values only from isolated `session_user=paddock_app`, validates exact per-task map shape, and enforces Root repeat count/locks/atomic persistence. Workers never receive the app credential or function grant; SQL does not duplicate the semantic fingerprint algorithm.
     - `proposal_request`: `SpawnRequest{parent_work_order_id,tasks:[{key,title,goal,acceptance,depends_on:[temporary_task_key]}]}`; dependency refs are closed over this task array; all proposal tasks become direct ownership children of the selected parent while `depends_on` forms the sibling execution DAG. The DB-current Root `effective_bundle_digest` and parent WorkOrder `policy_digest` are bound to every semantic fingerprint; caller-supplied digest is ignored.
    - `caps`: required finite `max_spawn_depth`, `max_total_descendants`, `max_live_children`, `max_attempts_per_work_order`, DB-clock `root_deadline`, and finite `max_repeat_fingerprint`; configuration must supply all fields, no infinite/default-unlimited values.
    - `fingerprint`: recursive semantic DAG fingerprint: validate the dependency DAG first; fingerprint each node as RFC 8785 JCS over `(title,goal,acceptance,definition_digest,policy_digest,sorted dependency_fingerprints)`; exclude dependency temporary keys and Root/WorkOrder/Parent/Attempt IDs; duplicate dependency edges are rejected before hashing; Root-scoped repeat count is bounded by `max_repeat_fingerprint`.
    - `counting`: Root WorkOrder depth=0; each ownership descendant adds 1; `max_total_descendants` excludes Root but counts all descendants including DONE; `max_live_children` counts direct children of the selected parent with `pull_state IN (QUEUED,READY,RUNNING)`; `max_attempts_per_work_order` counts persisted Attempt rows and is enforced inside the Lease issue transaction before Attempt insert; all spawn cap checks serialize on Root.
    - `digest_source`: DefinitionDigest is DB-current `roots.effective_bundle_digest`; PolicyDigest is DB-current parent WorkOrder `policy_digest`, inherited by every task in the proposal; either missing=NULL=>spawn DENY; caller-provided digests are ignored/untrusted.
    - `unconfigured_root_attempts`: SpawnPolicy absence denies child spawning/retries; for compatibility with existing non-recursive WorkOrders, one initial Lease/Attempt is permitted only when no prior Attempt exists, then further attempts deny until a finite policy is configured.
    - `lease_cap`: extend the existing `raw.issue_work_order_lease` SECURITY DEFINER function via the additive S02 migration; check persisted Attempt count against Root SpawnPolicy inside the same DB transaction immediately before Attempt insert; retain existing PullStore API and app function-only privilege boundary.
     - `effect_boundary`: Agent/Worker cannot write Lease/Authority/DONE. On 2026-10-17, the user separately approved the original guarded S02 up migration and named opt-in fixture on `paddock_test`; any repair DDL or retry beyond that execution requires new explicit approval.
    - `operation_replay`: Root-scoped operation ID plus exact canonical request; same ID+same request returns prior spawn result/fingerprint count without duplicating descendants; same ID+different request=DENY. The canonical request and temporary-key→WorkOrder-ID result map are persisted in the immutable spawn operation ledger.
    - `code_scope`: existing spawn Domain/Application/Postgres/migration/static source plus new `internal/storage/postgres/spawn_integration_test.go`; existing core files remain individually owned; integration test source only, do not run DB without separate M09-S02 runtime approval.
    - `integration_fixture`: unique disposable `spawn_it_` Root/Scope/WorkOrder IDs; exact cleanup of spawn operation/fingerprint and test WorkOrder/Attempt/Lease rows; tests recursion/key renaming, limits, replay/conflict, dependency DAG, and first-vs-retry Lease cap.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`; full Go tests/vet, tagged compile-only, 33 M09 source-contract tests plus 8 repair static tests PASS; lint 89/148 PASS. Original guarded S02 migration and the single combined repair (applied SHA `9c1c358f53953f2910d3aa641b808266a89667f6070ace9265714fb14e8b915d`) committed. The expanded approved `TestSpawnAdmissionIntegration` PASS: reverse-order DAG/key-renaming/replay, depth/descendant caps, concurrent live-child cap one-winner, DB deadline, configured attempt cap, and no-SpawnPolicy initial Attempt/retry denial. Read-only postcheck confirmed exact `spawn_it_` cleanup (zero fixture rows). No further DB writes needed for S02 acceptance.
  - `independent_review`: A separate read-only Verifier reviewed the expanded S02 fixture, helper, SpawnStore call, Root-locked SQL, and final runtime receipt; no actionable finding remained. Main compared the report with Runner outputs and cleanup readback and reconciled all selected acceptance clauses under D-016.
  - `receipt`: [M09-S02 source-only receipt](receipts/PDK-M09-S02/2026-10-16-source-slice.json)
  - `source_fixture_receipt`: `receipts/PDK-M09-S02/2026-10-17-source-fixture-verification.json`
  - `runtime_attempt_receipt`: `receipts/PDK-M09-S02/2026-10-17-db-runtime-attempt.json`
  - `repair_runtime_receipt`: `receipts/PDK-M09-S02/2026-10-17-repair-runtime-attempt.json`
  - `repair_strategy`: User selected one combined guarded transaction in `sql/governance_m09_s02_s03_repair.sql`; it was later applied under renewed explicit approval (SHA `9c1c358f53953f2910d3aa641b808266a89667f6070ace9265714fb14e8b915d`). This does not authorize further DB retries.
  - `repair_source_receipt`: `receipts/PDK-M09-S02/2026-10-17-repair-source-verification.json`
  - `final_source_receipt`: `receipts/PDK-M09-S02/2026-10-17-final-source-verification.json`
  - `expanded_fixture_source_receipt`: `receipts/PDK-M09-S02/2026-10-17-expanded-fixture-source-verification.json`
  - `final_db_receipt`: `receipts/PDK-M09-S02/2026-10-17-final-db-verification.json`
  - `d016_reconciliation_receipt`: `receipts/PDK-M09-S02/2026-10-17-d016-reconciliation.json`
  - `remaining_gate`: `NONE` for selected S02 acceptance under D-016 local verification. Residuals: no CI attestation; dirty worktree/full dirty-diff hash unavailable; semantic fingerprinting remains the selected trusted-Coordinator boundary.
  - `next_action`: PDK-M02-S03 is DONE under D-016; next dependency-ready candidate is PDK-M02-S04 source/preflight review. Do not execute its up/down/reset/drop database steps without separate explicit scope.
- [x] `PDK-M09-S03` — L1 Local → L2 Durable Semantic Checkpoint。
  - `depends_on`: PDK-M08-S03, PDK-M09-S01
  - `acceptance`: Hash・Attempt権限・Definition/Policy版を検証し、失効Checkpointは候補として隔離。
  - `evidence_expected`: manifest/payload tamper, budget rollback on interrupted transaction, stale Attempt quarantine, and different-Runner restore/revalidation fixtures (`paddock_test` opt-in). For this Issue, user selected the different-Runner boundary as a separate `pgxpool.Pool` and distinct `CheckpointStore` in the same test process; a subprocess is not required.
  - `selected_design`:
    - `difficulty_assignment`: Main publishes `D_pub=HARD` because this work spans database persistence, authority/Lease validation, budget accounting, bytea artifact integrity, and transaction atomicity; each Worker MUST self-report `D_worker` on the same `EASY<MEDIUM<HARD` scale before CODE and stop/escalate if incomparable or above scope.
    - `store`: one-row PostgreSQL `bytea` payload plus RFC 8785 canonical JCS manifest in one transaction; rollback on interrupted upload leaves neither checkpoint nor spend.
     - `quota`: immutable per-Root `CheckpointPolicy`, configured once by trusted Coordinator; finite `max_bytes_per_checkpoint` and `max_total_checkpoint_bytes`, missing limit=DENY.
     - `policy_authority`: trusted Coordinator identity is isolated `paddock_app`; do not require an undeclared `paddock_coordinator` DB role. SECURITY DEFINER owner is `paddock_migrator`; app has function-only access.
    - `budget`: use M09-S01 `STORAGE_BYTES`/`byte`; reserve and charge exact stored manifest+payload bytes atomically. Valid L2 and QUARANTINED retained candidates both consume bytes once; rollback spends nothing; no auto-refund/delete.
    - `store_precondition`: checkpoint insert function verifies the matching `budget_operations` RESERVE receipt for `<checkpoint_id>:reserve`, the configured storage account, and the exact stored-byte amount; direct insert-function invocation without a matching reservation=DENY.
    - `atomicity`: user-selected `pgx single transaction`: call existing `budget_apply` RESERVE, then narrow checkpoint insert function, then `budget_apply` SETTLE_RESERVATION in one pgx.Tx; any error rolls back all three. Operation IDs and checkpoint ID are stable/idempotent; commit-unknown is resolved by replaying the same IDs/request, never a new request ID.
     - `manifest`: `schema_version,root_id,work_order_id,attempt_id,lease_epoch,definition_digest,policy_digest,payload_sha256,payload_size`; DefinitionDigest=current DB `roots.effective_bundle_digest`; PolicyDigest=current WorkOrder policy digest.
     - `server_integrity`: DB recomputes SHA-256 over exact payload bytes and reconstructs fixed-key RFC 8785 JCS manifest bytes, rejecting duplicate-key/noncanonical input; verify Attempt belongs to supplied WorkOrder and WorkOrder belongs to supplied Root even when Lease is stale. Provenance-identity mismatch=DENY, never a cross-root quarantine write.
    - `identity_replay`: user-selected `checkpoint_id = operation_id`; same ID+same canonical manifest/payload returns the existing result; same ID+different request=DENY; a new checkpoint requires a new operation ID.
     - `promotion`: current valid Attempt/Lease/epoch/Definition/Policy may persist as L2; stale/revoked upload persists only as `QUARANTINED` candidate and is never auto-promoted on reconnect; restore revalidates current authority. No signature/key custody added.
      - `restore_api`: every read/restore re-queries current Root bundle digest, WorkOrder policy digest, Attempt↔WorkOrder↔Root relation, active Lease/Epoch and checkpoint state; only currently valid L2 returns payload; mismatch/expiry/revocation returns QUARANTINED candidate metadata only, never payload as resumable L2.
      - `restore_boundary`: User selected a second independent `pgxpool.Pool` and distinct `CheckpointStore` in the same test process as the `different-Runner` boundary; a separate subprocess is not required by this selected scope.
     - `fixture_retention`: tagged S03 tests use collision-checked `checkpoint_it_`/`m09_it_` IDs and retain checkpoint/budget rows; no cleanup/delete because artifacts and journal are append-only.
     - `runtime_boundary`: On 2026-10-17, the user separately approved the original guarded S03 up migration and named opt-in fixture on `paddock_test`, including retention of append-only fixture/budget rows. Any repair DDL or retry beyond that execution requires new explicit approval; no down/reset/delete is authorized.
     - `code_scope`: checkpoint Domain/Application/Postgres files plus new `internal/storage/postgres/checkpoint_integration_test.go`, `sql/governance_checkpoints.sql`, and focused tests; use trusted Coordinator `raw.configure_checkpoint_policy` function for setup. Reuse existing Budget APIs without editing shared M09-S01 files. Integration test source only; no S03 DB runtime/migration apply without separate scoped approval.
    - `integration_fixture`: unique `checkpoint_it_` Root/WorkOrder/Attempt/checkpoint operation IDs; append-only checkpoint and budget rows are logged and retained; verify valid L2 + restore through a second identity-checked app `pgxpool.Pool`/`CheckpointStore`, stale Lease=>QUARANTINED/no payload, interrupted transaction rollback/no spend, over-cap rejection, and tamper cases.
  - `current_evidence`: Main Runner at dirty overlay HEAD `2f1dcfe143c3ef66e33d82c003e2432256b11518`; Go tests/vet, tagged compile-only, 33 M09 source-contract tests, and 8 repair static-contract tests PASS; lint 89/148 PASS. Original S03 migration and combined repair (applied SHA `9c1c358f53953f2910d3aa641b808266a89667f6070ace9265714fb14e8b915d`) committed. The revised `TestCheckpointDurabilityIntegration` PASS using a distinct identity-checked app pgxpool for restore. Readback verified L2=523 bytes + QUARANTINED=501 bytes, stored sum/spent=1024, reserved=0, and one exact reserve/settle journal pair per successful checkpoint. Five `m09_it_` setup/grant fixture sets remain retained; earlier failed setups have no checkpoint/spend, and three successful fixture sets retain two checkpoints and 1024 bytes each. After Lease expiry, restore returns QUARANTINED/NULL payload as required.
  - `independent_review`: A separate read-only Verifier reviewed the S03 source, final DB receipt, append-only/budget readbacks, and the user-selected separate-pool different-Runner boundary; no actionable finding remained. Main reconciled the report with the Runner observations under D-016.
  - `receipt`: [M09-S03 source-only receipt](receipts/PDK-M09-S03/2026-10-16-source-slice.json)
  - `source_fixture_receipt`: `receipts/PDK-M09-S03/2026-10-17-source-fixture-verification.json`
  - `runtime_attempt_receipt`: `receipts/PDK-M09-S03/2026-10-17-db-runtime-attempt.json`
  - `repair_strategy`: User selected one combined guarded transaction in `sql/governance_m09_s02_s03_repair.sql`; it was later applied under renewed explicit approval (SHA `9c1c358f53953f2910d3aa641b808266a89667f6070ace9265714fb14e8b915d`). No further DB application is authorized.
  - `repair_source_receipt`: `receipts/PDK-M09-S03/2026-10-17-repair-source-verification.json`
  - `repair_runtime_receipt`: `receipts/PDK-M09-S03/2026-10-17-repair-runtime-attempt.json`
  - `final_source_receipt`: `receipts/PDK-M09-S03/2026-10-17-final-source-verification.json`
  - `final_db_receipt`: `receipts/PDK-M09-S03/2026-10-17-final-db-verification.json`
  - `d016_reconciliation_receipt`: `receipts/PDK-M09-S03/2026-10-17-d016-reconciliation.json`
  - `remaining_gate`: `NONE` for selected S03 acceptance under D-016 local verification. Residuals: the selected different-Runner boundary is a separate app pool in the same test process; no CI attestation; dirty worktree/full dirty-diff hash unavailable.
  - `next_action`: PDK-M02-S03 is DONE under D-016. Preserve all retained S03 checkpoint and budget fixtures. Next dependency-ready candidate is PDK-M02-S04 source/preflight review; no down/reset/drop execution without separate explicit scope.
- [ ] `PDK-M09-S04` — Offline GrantのBudget精算。
  - `depends_on`: PDK-M09-S01, PDK-M08-S04
  - `acceptance`: 事前予約、報告照合、未使用返還。信頼不能Workerへの物理制限保証を主張しない。
  - `evidence_expected`: 精算・不正申告テスト。

### M10 / P1 / Open Enrollment・Identity・Credential・Capability

**中目標:** 未知Workerを隔離から受け入れてもAuthorityを混同しない。

- [ ] `PDK-M10-S01` — 公開鍵Challenge、Enrollment、Quarantine登録。
  - `depends_on`: PDK-M06-S01
  - `acceptance`: 未知Workerは申請可能、Replayや再利用Ticketは拒否、通常Scopeには参加不可。
  - `evidence_expected`: 認証・異常系Fixture。
- [ ] `PDK-M10-S02` — Session/Attempt CredentialとIssuer Ceiling。
  - `depends_on`: PDK-M10-S01, PDK-M08-S03
  - `acceptance`: Credentialは鍵・Worker・Attempt・Epoch・Audienceに束縛され、失効後拒否。
  - `evidence_expected`: 期限切れ・盗用・失効試験。
- [ ] `PDK-M10-S03` — Capability Claim/Evidence/Probe。
  - `depends_on`: PDK-M10-S01
  - `acceptance`: 自己申告・観測・ハードウェア証明を区別し、Dynamic Evidence期限切れを配車に反映。
  - `evidence_expected`: Manifest, Probe結果, 期限検証。
- [ ] `PDK-M10-S04` — Worker信頼段階を能力別に管理。
  - `depends_on`: PDK-M10-S03, PDK-M11-S02
  - `acceptance`: Q0〜Q3が能力別。通信断をIntegrity違反扱いしない。
  - `evidence_expected`: Trust Profile遷移テスト。

- [ ] `PDK-M10-S05` — Open Enrollment EndpointのDoS/登録枯渇対策。
  - `depends_on`: PDK-M10-S01, PDK-M00-S05
  - `acceptance`: 匿名全体Quota、IP単独非依存の適応制限、Challenge TTLとコスト上限、登録数急増の隔離と監査が機能。PoC未実装時は公開エンドポイントを無効化。
  - `evidence_expected`: Burst/Replay/費用枯渇の負荷Fixtureと拒否ログ。


### M11 / P1 / Evidence Graph・Risk-Adaptive Trust

**中目標:** 多数決の自作自演とPolicyの自己認可を防ぐ。

- [ ] `PDK-M11-S01` — Evidence Node/Relation/署名/Domain識別。
  - `depends_on`: PDK-M06-S01, PDK-M10-S03
  - `acceptance`: DERIVED_FROM、OBSERVED_BY、CONTROLLED_BY等の出所を追跡し、循環Evidenceを拒否。
  - `evidence_expected`: Graph Fixture、署名証拠。
- [ ] `PDK-M11-S02` — 独立性とQuorum判定。
  - `depends_on`: PDK-M11-S01
  - `acceptance`: 同じ測定を10体で評価しても独立10票にならず、独立不明はカウントしない。
  - `evidence_expected`: Sybil/結託Fixture。
- [ ] `PDK-M11-S03` — Risk別型付きPolicy DSLとTrust Engine。
  - `depends_on`: PDK-M11-S02, PDK-M06-S02
  - `acceptance`: 同じSnapshot+Policy+評価時刻で決定論的結果。未知型/フィールドを拒否。
  - `evidence_expected`: Replay Test、理由コード。
- [ ] `PDK-M11-S04` — Bounded Evolutionの独立Approval Graph。
  - `depends_on`: PDK-M11-S03
  - `acceptance`: Builder自己承認不可。Kernel外変更拒否。Risk Adaptive独立検証を適用。
  - `evidence_expected`: Policy攻撃/変更回帰Fixture。

### M12 / P2 / Sandbox・SKILL Supply Chain

**中目標:** NAYA生成物を、隔離・検証・Digest固定で各Rootに再利用。

- [ ] `PDK-M12-S01` — Sandbox Profileと実環境強制能力の照合。
  - `depends_on`: PDK-M10-S03
  - `acceptance`: PRootをセキュリティ境界と誤認せず、未信頼コードを隔離不能Workerに配車しない。
  - `evidence_expected`: Sandbox Probe / adversarial test。
- [ ] `PDK-M12-S02` — Skill Manifest・署名・Provenance・Digest Pin。
  - `depends_on`: PDK-M12-S01, PDK-M11-S02
  - `acceptance`: instruction/wasm/native/script/container等を宣言し、Manifest要求権限は認可と区別。
  - `evidence_expected`: 悪性/改竄/互換性Fixture。
- [ ] `PDK-M12-S03` — NAYA → Stage → Independent Verify → Publish → Canary → Revoke。
  - `depends_on`: PDK-M12-S02
  - `acceptance`: 自作SKILLをBuilder本人が署名公開しない。Revocation後に新規配車されない。
  - `evidence_expected`: Lifecycle統合試験。
- [ ] `PDK-M12-S04` — RootをまたぐArtifact/Skill共有とアクセス制御。
  - `depends_on`: PDK-M12-S03, PDK-M01-S03
  - `acceptance`: Root間に実行依存を追加せず、許可済みDigestの共有だけが成立。
  - `evidence_expected`: cross-root参照・失効試験。

- [ ] `PDK-M12-S05` — Worker成果物のPrompt InjectionとSKILL/Go依存Supply Chain Gate。
  - `depends_on`: PDK-M00-S05, PDK-M12-S02
  - `acceptance`: 未信頼ArtifactをLLMの命令として昇格しない。Worker/Verifier経由のPrompt Injectionと依存パッケージ改竄に対し、出所・隔離・権限分離・依存Pin・再現可能検査を定義。
  - `evidence_expected`: 攻撃Payload Fixture、Dependency tampering、SBOM/署名/失効試験。


### M13 / P2 / NAYA・Steward・GUI/CUI

**中目標:** 制御系が成立した後に自律生成と人間用観測を接続する。

- [ ] `PDK-M13-S01` — StewardのWorkOrder提案/分解Adapter。
  - `depends_on`: PDK-M08-S02
  - `acceptance`: Agentは依頼を提案できるがLease/Authority/DONEを直書きできない。
  - `evidence_expected`: Mockと実LLMの境界試験。
- [ ] `PDK-M13-S02` — NAYAのSKILL不足検出・子WorkOrder発行。
  - `depends_on`: PDK-M12-S03, PDK-M08-S01
  - `acceptance`: 不足SKILLの生成・Verifier合格・元依頼再開がBudget内で成立。
  - `evidence_expected`: DAG End-to-End Fixture。
- [ ] `PDK-M13-S03` — GUI/CUI/APIの共通State Read Model。
  - `depends_on`: PDK-M13-S01, PDK-M14-S01
  - `acceptance`: 見た目の差で権限判定と状態遷移が変わらない。
  - `evidence_expected`: 同一APIのCLI/GUI整合試験。

### M14 / P1 / Observability・Audit

**中目標:** 故障後でも何が確定・未確定か判定可能にする。

- [ ] `PDK-M14-S01` — 構造化Event・Trace ID・Correlation ID・Receipt。
  - `depends_on`: PDK-M05-S01
  - `acceptance`: WorkOrder/Attempt/Policy Release/Rootを辿れ、資格情報はログへ出ない。
  - `evidence_expected`: サンプルTrace・機密値漏出検査。
- [ ] `PDK-M14-S02` — Rollout/Lease/Outboxのメトリクスとアラート。
  - `depends_on`: PDK-M14-S01
  - `acceptance`: Canary異常/配送停滞/Lease失効を計測可能。
  - `evidence_expected`: Metrics Fixture、障害注入値。
- [ ] `PDK-M14-S03` — Decisionと検証Receiptの長期追跡。
  - `depends_on`: PDK-M14-S01
  - `acceptance`: Git Revision / Schema / Evidence / Policy Digestを再照合可能。
  - `evidence_expected`: サンプル監査レポート。

- [ ] `PDK-M14-S04` — Trusted Verification Runner / CI Receipt（Verifier of Record）。
  - `depends_on`: PDK-M00-S07, PDK-M14-S01
  - `acceptance`: Worker自身が`PASS`を記入できない。Runnerがexit_code/go version/git HEAD/tree/dirty diff hash/対象Hash/fixtureを観測して署名またはCI attestし、テスト成功とレビューを区別。
  - `evidence_expected`: 生成ReceiptとCI Run ID、改竄Fixture、`[*]→[x]`の権限検証。


### M15 / P0 / 最小PoC統合・故障注入

**中目標:** 2 Coordinator + 2 Worker Sim + 1 PostgreSQLでAutonomous Policy Recoveryを再現する。

- [ ] `PDK-M15-S01` — Seed・Migration・Baseline起動。
  - `depends_on`: PDK-M02-S04, PDK-M04-S01, PDK-M15-S06
  - `acceptance`: Root A/BのPolicy v1・Epoch40が作成される。
  - `evidence_expected`: 再現コマンド、DB Readback。
- [ ] `PDK-M15-S02` — Root B Canary競合、Scope隔離。
  - `depends_on`: PDK-M15-S01, PDK-M07-S01
  - `acceptance`: 同時StartCanaryでも成功1件。Root A=v1, B=v2, Epoch41。
  - `evidence_expected`: Coordinator並列Test結果、Event/Outbox件数。
- [ ] `PDK-M15-S03` — Promote + Rollbackの原子性。
  - `depends_on`: PDK-M15-S02, PDK-M07-S04
  - `acceptance`: Promoteで両Root=v2, Epoch42。Fault Injection後v1, Epoch43。古いEpoch操作拒否。
  - `evidence_expected`: Integration Fixture、DB Snapshot。
- [ ] `PDK-M15-S04` — Command再送、DB障害、Outbox再配送。
  - `depends_on`: PDK-M15-S03, PDK-M04-S06, PDK-M05-S04, PDK-M15-S07
  - `acceptance`: Commit結果不明・Coordinator Kill・Event重複でも状態/効果一意。
  - `evidence_expected`: 故障試験Receipt・RowCount・Exit Code。
- [ ] `PDK-M15-S05` — PoC判定と独立レビュー。
  - `depends_on`: PDK-M15-S04, PDK-M14-S04, PDK-M01-S05
  - `acceptance`: 不変条件INV-01〜15、PoC期待値、未実装境界、残リスクを再現可能な証拠で記録。
  - `evidence_expected`: Test Report、Git Revision、Verifier Verdict、Fail箇所。

- [x] `PDK-M15-S06` — `cmd/coordinator`・`cmd/worker-sim`×2・Test DB Provisioning/起動Harness。
  - `depends_on`: PDK-M02-S05, PDK-M03-S01, PDK-M00-S08
  - `acceptance`: 選択されたlocal process-harness境界として、2 Coordinator/2 idle Worker processをloopback上で再現可能に起動し、専用Test DB identityをread-onlyで検証し、Workerを両Coordinatorへ1台ずつ接続、health/pull応答を確認して全process/temp artifactを安全に終了する。DB名がpaddock_test以外なら起動拒否。これはScheduler/Lease/競合Gateの実装・検証ではなく、受け入れ範囲外（M08-S02/M15-S02以降）。Test DB作成・再初期化・DDL適用はこのHarnessで行わない。
  - `evidence_expected`: 起動コマンド、プロセス/DB確認、Harness Receipt、誤本番接続拒否。
  - `current_evidence`: Added `cmd/coordinator`, `cmd/worker-sim`, a strict loopback-only local health/empty-pull HTTP seam, and `scripts/run_poc_harness.sh`. The runner read-only checked `paddock_test` PostgreSQL 18.6/raw_relations=26, built binaries into a private temp directory, launched 2 loopback coordinators and 2 idle workers (one worker per coordinator), observed health and pull responses, confirmed zero jobs executed, and terminated/reaped processes and removed temp files. Non-paddock_test DB refused at coordinator startup; URL parser-confusion, non-loopback, malformed port and path negative unit cases reject. Runner commands: `go test ./internal/harness ./cmd/coordinator ./cmd/worker-sim -count=1` PASS; matching `go vet` PASS; `bash -n scripts/run_poc_harness.sh` PASS; `scripts/run_poc_harness.sh` PASS (`coordinators=2 workers=2 database=paddock_test scheduler=stub jobs_executed=0`); design lint PASS 89/148; `git diff --check` PASS. Separate verifier reviewed the signal cleanup fix and narrowed acceptance and found no blocking issue. Source SHA-256: poc.go `df6383e30c6e163ee2bc9c764467635af7ea30325d428b974c5d5c9835412cbd`; poc_test.go `8c69e1b288d6ffde2ebede263e24ff33d775197e36baa815b1e2327200d8afd3`; coordinator `cd7beb8ddb1784386a0ec65022b52a3c49a0675ea5bc8e4b469af576ade900b6`; worker `4ccbdf59b97f9e9ee1fc66ab20b35eb2874aa33994f7b6235073a58477211c57`; runner script `0b9669a23fe638792f5279cee68044ba0b2bc6ad57ef0e553e803b04fa332a9d`. This is a process smoke harness only: scheduler/lease/contention gate is not implemented or validated; SIGKILL/host failure cleanup is not guaranteed; no DB creation/init/DDL or CI attestation claimed.
- [ ] `PDK-M15-S07` — DB Commit-unknown/Network分断/Fuzz Fault Harness。
  - `depends_on`: PDK-M15-S03, PDK-M15-S06
  - `acceptance`: Connection強制切断（Toxiproxy等）、DB Crash相当隔離、Policy DSL Go Fuzzを実行し、誤った二重実行・認可を拒否。`pg_ctl -m immediate`は専用隔離DBのみ。
  - `evidence_expected`: Fault Matrix、実Command Receipt、State/Epoch/RowCount照合。


## 4. 不変条件と検証マップ

| Invariant | 主要Issue | 失敗を検出する試験 |
|---|---|---|
| INV-01 Active Rollout ≤1 / Scope | M02-S02, M04-S03 | 2 Coordinator同時起動 |
| INV-02 Activation EpochはRollbackを含め増加のみ | M01-S02, M07-S04 | v1→v2→v1 / 40→41→42→43 |
| INV-03 Canary Root隔離 | M07-S01, M15-S02 | Root Aはv1のまま |
| INV-04 Policy Digest/Approval固定 | M06-S01, M06-S04 | 改竄/古い承認拒否 |
| INV-05 State+Event+Outbox+Receipt原子 | M03-S04, M05-S01 | Event挿入失敗で全Rollback |
| INV-06 古いLeaseの結果確定拒否 | M08-S03 | stale `lease_epoch` |
| INV-07 子BudgetとRoot Budget上限 | M09-S01 | 並行委譲と二重計上検査 |
| INV-08 TrustとAuthority分離 | M10-S02, M11-S03 | 高Trustでも権限外操作拒否 |
| INV-09 Root間WorkOrder依存なし | M01-S03, M12-S04 | cross-root edge DB拒否 |

| INV-10 人間の緊急停止はAgentで解除不能 | M06-S05, M00-S06 | Break-glassの停止・不正解除拒否 |
| INV-11 LKG失効でも組込みSafe Baselineへ退避可能 | M06-S06, M07-S04 | LKG失効/不在・SAFE_STOPPED |
| INV-12 HOLD/MONITORINGの終端 | M07-S06 | Deadline/公平性を明示したLiveness検査 |
| INV-13 Root別認可Epochで非Canary隔離 | M01-S06, M07-S07 | Root A Grant非失効、Root Bのみ変更 |
| INV-14 ReceiptはRunner/CIの観測証拠 | M14-S04 | Worker捏造Receipt拒否 |
| INV-15 署名対象用途分離・Canonical Digest | M06-S07, M03-S05 | Cross-protocol Replay/JSON同値Fixture |


## 5. 再開・終了ルール

- 初回の次Issueは **PDK-M00-S01の検証**（新規のThreat Model/M00-S08は追加設計案で、承認済み実装とは扱わない）。既にファイルが存在しても検査までは`[~]`のまま。
- Work開始前: `method.md`のCONTINUE/1を実行し、Cursor・Gitの作業状態・最後のReceiptを照合する。
- 同一Issueを二人が書き換えない。中断中のWIPを奪取する場合はGit差分と担当権限を確認する。
- 完了条件未達でも結果が残った場合は`[-]`または`[~]`として残し、未実行検査を明記する。
- **`[x]`変更は検証証拠がある場合のみ**。Task内容が書いてあるだけで完了にしない。
- 一度の`continue`で中目標を丸ごと進める必要はない。依存が解決した**小目標1件**を選び、検証・記録して次のCursorを示す。
