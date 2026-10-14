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
active_goal: M02
active_issue: PDK-M02-S05
issue_state: TODO
execution_state: NOT_STARTED
current_branch: main
verified_commit: NONE
last_receipt: NONE
last_verified_test: "M15-S06 worktree: go test ./internal/harness ./cmd/coordinator ./cmd/worker-sim PASS; matching vet PASS; bash -n and scripts/run_poc_harness.sh PASS (2 coordinators, 2 workers, paddock_test PG18.6, scheduler stub, no jobs); design lint 89/148 PASS; diff-check PASS."
next_action: "PDK-M02-S05: confirm dedicated Test DB and migration runner evidence from actual receipts; preserve other worktree changes."
confidence: "PDK-M01-S05, PDK-M06-S05, and PDK-M15-S06 have local Runner evidence and independent review; issue-specific push for M15-S06 is pending isolation. PDK-M08-S01 implementation and local tests pass, but SQL runtime is blocked because current DB role lacks raw USAGE/CREATE. User said they will handle role via Admin psql; no DB role/grant changes made by agent. No other READY issue presently selected by dependency planner. Preserve remaining dirty work; no CI attestation."
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
- [x] `PDK-M00-S04` — `CONTINUE/1`を模擬通信断で演習する。
  - `depends_on`: PDK-M00-S03
  - `acceptance`: `tests/test_s04_continue_resume.py` must simulate interruption in a disposable fixture, then launch a fresh subprocess with no session memory; it selects the same active WIP Issue, and rejects changing unverified WIP to DONE. No claim of actual network/process crash is required.
  - `evidence_expected`: Test-captured before/after Cursor snapshots, controlled unverified-work diff, and subprocess command/stdout/exit-code log in disposable fixture; test report and local verifier review.
  - `current_evidence`: `tests/test_s04_continue_resume.py` uses a disposable temp repository, captures identical before/after Cursor text, creates a controlled unverified WIP artifact and unified diff, then executes `continue_plan.py` in a fresh subprocess and records command/stdout/exit status in temporary JSON; it asserts S04 remains WIP and is selected. Independent verifier confirmed this meets the revised simulated-interruption acceptance and independently ran focused tests 5/5, full suite 35/35, design lint PASS (89 issues/148 edges), planner CLI exit 0 (active S04), and `git diff --check` PASS at HEAD `9d6296b17c9b569e7f010fe7c30755a94ff0042f`. Local simulation only; not a real crash or CI attestation.

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

- [ ] `PDK-M02-S01` — 初期Governance Migration (up/down)を設計・適用。
  - `depends_on`: PDK-M01-S05, PDK-M02-S05
  - `acceptance`: `policy_bundles`, `policy_scopes`, `roots`, `policy_rollouts`, `rollout_targets`, `governance_approvals`, `command_receipts`, `domain_events`, `event_outbox`, `event_inbox`, `security_generation`を整合した順序で作成/撤去。
  - `evidence_expected`: 専用DB `psql -v ON_ERROR_STOP=1` / migration runner Exit Code、Schema dump。
- [ ] `PDK-M02-S02` — Scope複合FK・Partial Unique Index・State制約。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: 違うScopeへのTarget、ScopeあたりActive Rollout二件をDB側が拒否。
  - `evidence_expected`: SQL負例/陽例テスト結果。
- [ ] `PDK-M02-S03` — 不変Bundle/Eventと最小権限DBロール。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: 通常App RoleのUPDATE/DELETEを拒否。Migration Roleを分離。
  - `evidence_expected`: 権限テスト、トリガー/GRANT一覧。
- [ ] `PDK-M02-S04` — 全Schemaの再構築・巻戻しを検証。
  - `depends_on`: PDK-M02-S02, PDK-M02-S03, PDK-M02-S06
  - `acceptance`: 空DBにup→down→upし、整合性エラーなし。テストDB以外は変更しない。
  - `evidence_expected`: Migrationログ、SQLSTATE、Exit Code。

- [ ] `PDK-M02-S05` — PoC Test DB・PostgreSQL版・Migration Runnerを確定（O-003解決）。
  - `depends_on`: PDK-M00-S02, PDK-M00-S06
  - `acceptance`: PG版、DSN secretの注入経路、テスト用Isolation、Migration実行コマンド、再作成/破棄ガードを決める。本番接続でテストを走らせない。
  - `evidence_expected`: テストDB起動/接続の実測、版表示、Migration Runner設定、環境変数名（秘密値なし）。
- [ ] `PDK-M02-S06` — Root別認可Epoch・Scope Freeze・Safe Baseline対応のDDL。
  - `depends_on`: PDK-M02-S01, PDK-M01-S06
  - `acceptance`: Root別Epoch/実効Policy、Scope Freeze、Security Epochの整合制約と状態変更のCASを追加。RolloutとRootのScope複合FKを保持。
  - `evidence_expected`: Migrationおよび正/負のSQL Test。


### M03 / P0 / pgx Native Repository Adapter

**中目標:** `GovernanceTx` Interfaceを実DBの1 Transactionへマップする。

- [ ] `PDK-M03-S01` — `Transactor`、`GovernanceTx`、Port境界を定義。
  - `depends_on`: PDK-M01-S02, PDK-M02-S06
  - `acceptance`: Domainにpgxが漏れず、1つのUse Caseが1 Transactionを共有。
  - `evidence_expected`: Goコンパイル、Interface検証。
- [ ] `PDK-M03-S02` — `LockScope/LockRollout/ValidateTargets`と保存CAS。
  - `depends_on`: PDK-M03-S01, PDK-M02-S02
  - `acceptance`: `FOR UPDATE`、Scope所属照合、Epoch/State CASと一貫したロック順序。
  - `evidence_expected`: pgx Integration Tests、競合ログ。
- [ ] `PDK-M03-S03` — `SERIALIZABLE`再試行(40001/40P01)と取消。
  - `depends_on`: PDK-M03-S01
  - `acceptance`: 業務CallbackはDB内だけ。Retry時に外部副作用なし。Context Cancelで停止。
  - `evidence_expected`: リトライ注入テストと競合試験。
- [ ] `PDK-M03-S04` — Transaction内Receipt/Event/Outbox保存。
  - `depends_on`: PDK-M03-S02, PDK-M05-S01
  - `acceptance`: 一つ失敗すればScope/Receipt/Event/Outboxが全Rollback。
  - `evidence_expected`: 故障注入SQLと最終RowCount。

- [ ] `PDK-M03-S05` — Canonical Request/Bundle DigestのRepository受け渡し。
  - `depends_on`: PDK-M03-S01, PDK-M06-S07
  - `acceptance`: 署名用途別バイト列とRequest DigestをGo Domain入力に固定し、JSON Key順/空白/数表現の相違でIdempotencyが破綻しない。
  - `evidence_expected`: 同値/非同値Payload FixtureとDigest Test。
- [ ] `PDK-M03-S06` — DB時刻の正本・Timeout照合契約。
  - `depends_on`: PDK-M03-S01
  - `acceptance`: Lease/Monitoring/HOLD期限はDB時刻基準。`now()`と`clock_timestamp()`の違いをテストし、Worker時計による延命不可。
  - `evidence_expected`: DB時間スキュー・Transaction遅延Fixture。


### M04 / P0 / Application Use Cases・Command冪等性

**中目標:** `StartCanary`などの業務操作を一意に確定させる。

- [ ] `PDK-M04-S01` — `Propose`, `StartCanary`, `Promote`, `Rollback` Application Services。
  - `depends_on`: PDK-M03-S02, PDK-M06-S02
  - `acceptance`: 承認検証後だけ遷移し、Commitまで状態が外部に見えない。
  - `evidence_expected`: Service Test、DB Integration Test。
- [ ] `PDK-M04-S02` — `command_id` + 正規化`request_digest`のReceipt契約。
  - `depends_on`: PDK-M03-S05, PDK-M03-S02
  - `acceptance`: 同ID同引数は同結果、同ID異引数は拒否、Commit応答喪失後に再送してもEpoch不変。
  - `evidence_expected`: 重複・競合Fixture、行数/結果ログ。
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

- [ ] `PDK-M05-S01` — Event EnvelopeとAppend Event+Outbox。
  - `depends_on`: PDK-M02-S01
  - `acceptance`: Aggregate Version一意。状態遷移とEvent/Outboxが同一Transaction。
  - `evidence_expected`: SQL Integration Test、Eventサンプル。
- [ ] `PDK-M05-S02` — Dispatcher方式O-001の正式選択。
  - `depends_on`: PDK-M05-S01
  - `acceptance`: Polling/NOTIFY/Brokerの選択理由、契約、障害時方針をdecision追記。
  - `evidence_expected`: 更新済みDecision IDと設計レビュー。
- [ ] `PDK-M05-S03` — Outbox Claim/Ack/Retry/Dead Letter。
  - `depends_on`: PDK-M05-S02, PDK-M03-S01
  - `acceptance`: Coordinator2体のClaim競合で重複配信しても無害、配送途中落ちても再回収。
  - `evidence_expected`: 失敗注入Integration Test、再配信ログ。
- [ ] `PDK-M05-S04` — Consumer Inboxによる冪等効果。
  - `depends_on`: PDK-M05-S03
  - `acceptance`: 同Event3回配送でもDB側の業務効果は1回。外部APIのExactly-onceと混同しない。
  - `evidence_expected`: Retry Fixture、Consumer RowCount。

- [ ] `PDK-M05-S05` — Event/Policy DSL/ReceiptのSchema VersionとEvent保存・Partition方針（O-009）。
  - `depends_on`: PDK-M05-S01, PDK-M00-S08
  - `acceptance`: 未知Major Versionの扱い、Event・Outbox・Inbox retention、DLQ後の監査保存とReplay窓、Partition/Archive方針を記録。
  - `evidence_expected`: Version互換Fixture、expiry/replay境界テスト、更新Decision。


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
- [-] `PDK-M06-S07` — Canonicalizationと署名用途分離（O-008）。
  - `depends_on`: PDK-M00-S06
  - `acceptance`: JCS等の確定Byte Codec/型制限、Bundle・Approval・Commandの用途タグ、署名対象schema_versionとanti-replay文脈を仕様化し検証。
  - `evidence_expected`: Golden Vector、Key順/Unicode/数値Fixture、cross-protocol署名拒否。
  - `blocker`: D-015 selects RFC 8785 JCS, but no compliant JCS codec or verified vectors are available. Keep fail-closed; select no external dependency without authorization and do not claim completion.
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

- [ ] `PDK-M08-S01` — WorkOrder/Dependency/Attempt永続化。
  - `depends_on`: PDK-M01-S03, PDK-M03-S02
  - `acceptance`: 親子Tree・Root内DAG・Attempt試行履歴が追跡可能。
  - `evidence_expected`: DDL・DAG循環・cross-root拒否テスト。
- [ ] `PDK-M08-S02` — Worker Pull/Capability Filter/Slot予約。
  - `depends_on`: PDK-M08-S01
  - `acceptance`: Hard条件適合後にAuthority/Trust/Budget検査し、一つのSlotを原子的確保。
  - `evidence_expected`: Concurrent Pull Integration Test。
- [ ] `PDK-M08-S03` — Lease TTL/Heartbeat/Reaper/Fencing。
  - `depends_on`: PDK-M08-S02
  - `acceptance`: 古いEpochのAttempt結果を拒否し、新Attemptへ安全に移行。
  - `evidence_expected`: Worker停止・再起動・遅延応答Fixture。
- [ ] `PDK-M08-S04` — WorkOrder Policy別Offline運用。
  - `depends_on`: PDK-M08-S03
  - `acceptance`: 投機ローカル計算と外部副作用を区別。オフライン中のGateway操作は不可。
  - `evidence_expected`: Offline Grant/Fencing Test。

- [ ] `PDK-M08-S05` — Lease期限のDB Clock・Gateway staleness境界（O-006）。
  - `depends_on`: PDK-M08-S03, PDK-M03-S06
  - `acceptance`: 失効時間はDB Clockで評価し、Worker側の時刻変更でLease延長不能。Gatewayの最大stalenessを測定して高リスクは不明時deny。
  - `evidence_expected`: Clock skew・TTL・DB停止・Gateway再接続Fixture。


### M09 / P1 / 階層Budget・Checkpoint

**中目標:** 再帰的な自律作業で資源上限を守り、途中から復旧できる。

- [ ] `PDK-M09-S01` — Budget Account / Escrow Ledger。
  - `depends_on`: PDK-M08-S01
  - `acceptance`: `spent + reserved + delegated <= granted`をDBで守り、親子二重計上をしない。
  - `evidence_expected`: 同時委譲、返還、上限超過Fixture。
- [ ] `PDK-M09-S02` — Spawn/Retry/Deadline/反復Fingerprint上限。
  - `depends_on`: PDK-M09-S01
  - `acceptance`: 新IDを乱発した循環修復でも上限を突破できない。
  - `evidence_expected`: 再帰攻撃Fixture。
- [ ] `PDK-M09-S03` — L1 Local → L2 Durable Semantic Checkpoint。
  - `depends_on`: PDK-M08-S03, PDK-M09-S01
  - `acceptance`: Hash・Attempt権限・Definition/Policy版を検証し、失効Checkpointは候補として隔離。
  - `evidence_expected`: Upload中切断・異Runner復元Fixture。
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
