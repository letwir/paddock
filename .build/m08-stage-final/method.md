# PADDOCK — method.md

> SIGMA/1: PIDGEN/text · Execution / Verification / CONTINUE Protocol
> Snapshot: 2026-10-12 · Revision: design-review/2 · Applies to: this PADDOCK repository only
> **目的:** 会話履歴・LLM内部状態・ネットワークセッションに依存せず、Git・Issue・Receiptを読み直して安全に作業を再開する。

## 0. 文書の役割と優先順位

- `decisions.md`: **明示採用された設計判断の転記正本**。Proposalや今回のDESIGN_BASELINE追補を採用済みとして扱わない。Git移植後、承認者・署名・Commitを照合し移植記録を固定する。
- `Issues.md`: **目標・依存・状態・Cursorの正本**。ただし状態の真偽はGit Tree/テストReceiptで照合する。
- `method.md`: **開発作業の手順・再開契約の正本**。
- `README.md`: 入口と操作案内。上の3文書に優先しない。
- `THREAT_MODEL.md`: 脅威・境界・緩和の**設計案**。現時点では未検証の安全性を保証しない。
- `docs/issue-dependencies.generated.md`: `Issues.md`の小目標依存から生成する派生文書。再開順序の根拠は元の`depends_on`に限定する。
- `.HARNESS` (`letwir/config/.HARNESS`) は **参照**。PADDOCKと別のリポジトリ・認可・端末環境である。既存HARNESSのLRFを無条件で実行規則に追加しない。
- 現在の作業依頼と適用される上位指示が最優先。文書に書いてあるだけで外部Push・本番DB変更・秘密情報取扱い・課金は認可されない。

## 1. PIDGEN/text と SIGMA/1 の使用契約

### 1.1 元仕様との接続

参照: `https://github.com/letwir/config/blob/main/.HARNESS/rules/MANUAL.lrf` と `https://github.com/letwir/config/blob/main/.HARNESS/rules/state.lrf`。

`.HARNESS` の委譲メッセージで使われる**表記**は、次の固定エンベロープである。PADDOCKでは、小目標を単位とする短い作業指示の交換形式として必要部分のみ採用する。

```text
<Γ>
SIGMA/1: PIDGEN/text
Role: <worker role>
Target: <one stable issue ID and exact deliverable>
Acceptance: <machine-checkable completion criteria>
Scope: <allowed repository paths; forbidden side effects>
Known facts: <verified facts and source refs only>
SIGMA/1
</Γ>
```

**守る形式:** `Role`, `Target`, `Acceptance`, `Scope`, `Known facts` の順序を変更しない。先頭は`<Γ>`、プロトコル行は`SIGMA/1: PIDGEN/text`、最後のPayload行は正確に`SIGMA/1`、終端は`</Γ>`。ここで`SIGMA/1`はフォーマットの識別子であって、認可やPolicyの置換ではない。

このエンベロープは単に**メッセージ形式**を定める。LLMが作業対象を知るためのものであり、Credential発行や生産環境の変更権限を付与しない。未確認事実を`Known facts`に混入させない。曖昧な部分は`Unknown`としてTarget/Acceptanceの外へ明示するか、Issueへ戻す。

### 1.2 確定した小目標のHandoff例

```text
<Γ>
SIGMA/1: PIDGEN/text
Role: Worker / implementation
Target: PDK-M01-S02; implement pure transitions according to PDK-M01-S06 and PDK-M07-S07
Acceptance: Table-driven tests prove Scope Epoch 40→41→42→43, Root A unaffected in Root B Canary, two-phase rollback and fail-closed authorization; no network calls in Domain
Scope: internal/governance/domain* only (repository-relative); no .HARNESS edits; no remote push, live DB, or credential access
Known facts: D-010 Hybrid Epoch+Scoped Canary; D-011 Single Active Rollout; D-012 Contract First; 3-layer Epoch is DESIGN_BASELINE (not new ACCEPTED); source=decisions.md
SIGMA/1
</Γ>
```

この例に書かれたPathは予定ディレクトリであって、現時点で存在することを保証しない。実行前に確認する。

### 1.3 PIDGEN意味圧縮で保持する属性

`Role`, `Target`, `Acceptance`, `Scope`, `Known facts`を省略しない。文を圧縮しても**目的・否定・権限境界・例外・停止条件・受入条件・確認済み事実**を不可逆に削らない。記号/絵文字だけを安全条件の唯一の媒体にしない。作業者は圧縮表現の未定義語を勝手に補完しない。

## 2. 作業状態機械（Issues.md）

```text
[ ] TODO ──着手・Cursor更新──> [-] WIP
  ^                               │
  │                               v
  └──範囲変更/撤回             [~] IMPLEMENTED
                                  │
                                  v
                               [*] TESTED
                                  │
                                  v
                                [x] DONE
```

`[x]`は検査コマンド・Exit Code・対象Revision・信頼済みVerifier/CIの検証証拠が揃った場合のみ。**Workerが自身で作成したReceiptの`PASS`では完了しない**。実行結果を確認できない場合は「成功したはず」で先へ進めず、`[-]` / `[~]`を維持する。

### 2.1 小目標を選ぶ規則

1. `Issues.md`のCursorを読む。
2. Cursor候補が依存を満たすか検査。満たさなければ同じ中目標から依存完了済みの小目標を探す。
3. 優先順: P0 → P1 → P2。同順位は小目標の依存DAGとブロッカーで決める。中目標の表はDAGではない。`python3 scripts/lint_design.py`で小目標の参照・Cycleを先に検査する。
4. 一度に責任を持つ小目標は原則**1件**。別件を並列化する場合はファイルの単独Write Ownerと独立した検証境界が必要。
5. 「何が変わるか」「どの検査で終わるか」が未定ならIssueを分解してから実装する。

### 2.2 Cursor更新のタイミング

- **開始前:** active_issue, phase, preflight commit/tree, next_action, worktree statusを保存。Issueは`[-]`。
- **安全な実装境界後:** 出力、実行検査、未完了の箇所を追記。Issueは`[~]`まで。
- **検証後:** 実際のTest ReceiptがPASSなら`[*]`。レビューと残余確認後に`[x]`。
- **通信断時:** 書きかけを完了とみなさない。Cursorが残せなければGit+Receiptから再構築。
- **完了後:** 次のREADYなIssueをCursorに設定。実行しない場合はnext_actionだけ記録して終了。
- **`verified_commit`の自己参照禁止:** Cursor自身の保存を含むCommit SHAを、同じファイル内で事前に確定値として記載しない。最後に検証済みだった**過去**のCommitを記録する。未作成・未検証なら`NONE`。現在のGit HEADと混同しない。

## 3. CONTINUE/1 — 通信断・プロセス再起動・会話断絶からの復帰

**Trigger:** `continue`, `続き`, `再開`, 新WorkerによるHandoff。過去会話が閲覧できなくても実行可能にする。

### 3.1 Preflight：最初は読み取り専用

```text
1. Project Root確定 (git rev-parse --show-toplevel、存在しないなら明示して停止)
2. git status --short / git diff --stat / git diff / git log -1を確認
3. decisions.md → method.md → Issues.mdのCursor → active Issue本文を読む
4. last Receipt/last verified commit が存在すれば参照とHashを照合。Receiptの作成者/CI Run/署名・観測Revisionを検証し、Worker自己申告は検証証拠に数えない
5. `scripts/lint_design.py`があるならDAG/参照を検査し、先行する小目標の依存と、作業対象の未保存差分を確認
6. 実ファイルとCursorが矛盾したら「実ファイル・Git・検証ログ」を観測して修正計画を作る
7. 最初の安全な1小目標を選ぶ。Safety/OPENブロッカーがあれば設計Issueを優先。未知の副作用はSTOP
```

使用例（リポジトリ初期化後。Shell依存性の低いGitコマンド）:

```sh
git rev-parse --show-toplevel
git status --short
git diff --stat
git diff
git log -1 --format='%H %s'
```

新規ディレクトリでGit未初期化なら`REPO_NOT_INITIALIZED`として報告する。**誤った親Repoや既存`.HARNESS`に対してgit操作しない。** Git作成は対象パスを確認してから行う。

### 3.2 Conflict Matrix

| 観測 | 取扱い | 禁止事項 |
|---|---|---|
| Cursor=TODO、実ファイルが既に存在 | Diffと受け入れ条件を比較。作業済みと決めつけない | 全上書き |
| Cursor=WIP、通信断で中断 | `git status`→差分→部分テスト→不明点記録 | 再初期化・無断reset |
| Cursor=DONE、Receipt欠落 | `UNVERIFIED`に戻して再検証または証拠不足を明記 | DONEを無条件信用 |
| 直前のDB Commit結果不明 | `command_id` / Receiptで照会。重複Request発行前に調停 | 新Command IDで即再実行 |
| 新しいCommitが存在 | 差分を確認し、既存の変更を保存 | 強制Checkout |
| 変更対象に別WorkerのWIP | One-writer-per-fileを検査し、必要なら非競合Issueへ | 同時上書き |
| Policy/署名/Epochが更新 | Scope/Root/Securityの各EpochとEffective Digestを再評価、旧Approvalを使用しない | Scope Epochだけで無関係RootのGrantを一律拒否 |
| Emergency Stopが観測/不明 | 新規実行・外部操作を停止し、Safety Plane状態の認証済み確認 | Agentによる自己解除 |
| LKG失効・破損 | 組込みSafe Baseline/SAFE_STOPPEDの設計経路へ、未実装なら実操作STOP | 期限切れLKGの強制反映 |
| HOLD/MONITORING長期化 | DB ClockとDeadline、再試行/ABORT規則を評価 | 無期限Active Slot保持 |
| `decisions.md`承認不明 | 転記の由来を明示し、人間の承認記録を待つ | Worker単独でACCEPTED改竄 |
| DB/ネットワーク未接続 | 依存しない作業を実施、DB関連をBLOCKED | 接続成功・検証成功の捏造 |

### 3.3 Recover → Reconcile → Execute

```text
READ_ONLY_PREFLIGHT
  ↓
OBSERVED_STATE != CURSOR ?
  ├─ Yes: reconcile cursor / document discrepancy (not silent overwrite)
  └─ No:  current issue selected
  ↓
DEPENDENCIES_READY ?
  ├─ No: mark blocker and choose another READY issue
  └─ Yes: write durable intent ([-] WIP)
  ↓
ONE_BOUNDED_CHANGE
  ↓
VERIFY (commands + hashes + scope/diff checks)
  ↓
RECEIPT + STATE UPDATE
  ↓
NEXT CURSOR / STOP
```

もし大きい仕事が途中で切れる可能性があるなら、Issueを一層細かく分ける。**短い小目標と短い永続化境界**を優先し、長時間のLLMコンテキスト保持を再開契約にしない。

### 3.4 通信断後に必要な再開出力

```yaml
resume_report_schema: paddock.resume/1
project_root: <verified-path>
issue_id: <stable-ID>
observed_revision: <git-commit-or-NONE>
worktree: <clean|dirty|unknown>
state_from_issue: <TODO|WIP|IMPLEMENTED|TESTED|DONE>
state_from_evidence: <verified|partial|unverified>
last_receipt: <path-or-NONE>
action_taken: <read-only reconciliation | bounded-change | stop>
next_action: <one concrete action>
blocker: <NONE|reason>
```

この報告は毎回の出力末尾に短く載せてもよい。Receipt未確認の状態で`verified`を名乗らない。

## 4. 開発工程と検証Gate

既存`.HARNESS`のETLに似た工程を参考にするが、PADDOCKの開発規則として独立に定義する。

```text
PRECEDENT → RESEARCH → PLAN → PRE_VERIFY → CODE → POST_VERIFY → FINISH
```

- **PRECEDENT:** 既存Decisions/Issuesと差分、権限・Scope・依存の確定。
- **RESEARCH:** 既存実装、一次資料、コンパイル/API仕様の確認。推測を事実と区別。
- **PLAN:** Small issue 1件、対象ファイル、テスト、Rollback、失敗条件。
- **PRE_VERIFY:** State Machine、DDL制約、公開鍵、Lock順序、書込み先などを事前監査。
- **CODE:** 許可されたScopeのファイルだけを編集。複数Workerでも1ファイル1Writer。
- **POST_VERIFY:** `gofmt`, `go test`, `go test -race`, SQL Integration、Model Checking、Fuzz、差分/Scopeチェック（該当するものだけ）。**Runnerが実際にプロセスを起動し終了コードとHashを採録**する。
- **FINISH:** Issue更新・Receipt/残余リスク・次Cursor。人間に未確認を成功として報告しない。

**Verifierの独立性:** 同じモデルを別スレッドで起動しただけで独立ドメインとは扱わない。検査により確認した項目と意見評価を分ける。**Verifier of Recordは信頼済みCI Runner**とする計画（O-007未解決時は独立検証未達）。CI設定・鍵・Workflowも検証対象であり、Worker自己報告をCI署名済みとして扱わない。

## 5. Receipt / Evidence Contract（信頼された観測のみ）

将来の保存先: `receipts/<issue_id>/<utc>-<uuid>.json`。非機密ReceiptとCI Run URL/署名をGitで参照し、外部Raw Log・秘密・DSN値を入れない。

**Actor split:** `Worker Report`（作業者の自己申告）≠ `Verification Receipt`（Runnerによる実観測）≠ `Verifier of Record`（CIで認証された最終判定）。Workerは自分の作業について`exit_code: 0`というJSONを自由に書けるので、それだけでは[*]/[x]にしない。

```json
{
  "schema_version": "paddock.receipt/1",
  "issue_id": "PDK-M01-S02",
  "runner": {"kind": "CI", "identity": "UNSET", "run_id": "NONE", "attestation": "NONE"},
  "time_start_utc": "UNSET",
  "time_finish_utc": "UNSET",
  "source": {"git_commit": "NONE", "git_tree": "NONE", "dirty": true, "dirty_diff_sha256": "UNSET"},
  "environment": {"go_version": "NOT_RUN", "db_version": "NOT_RUN"},
  "targets": [{"path": "internal/governance/domain.go", "sha256": "UNSET"}],
  "checks": [{"command": "go test ./internal/governance -count=1", "exit_code": null, "stdout_sha256": "UNSET", "stderr_sha256": "UNSET", "result": "NOT_RUN"}],
  "verdict": "NOT_VERIFIED",
  "remaining_risks": []
}
```

このJSONは**例示であって実行Receiptではない**。`verdict: PASS`は、信頼されたWrapper/CIが実行・採録し、Workflowの定義・Runner Identity・対象Git Revision・署名/Attestationを照合した後のみ。実行終了コードが0でも受入条件が未達ならPASSにしない。テスト前の`make verify`・`go test`の想定結果は`NOT_RUN`。ローカルWrapperによるReceiptはCIの代用ではなく暫定証拠。

**決定の保護:** `decisions.md`のACCEPTEDを書き換えるには、保護Branch・CODEOWNERS・人間承認者・署名Commitの照合が必要というDESIGN_BASELINE。GitHub接続・保護設定がない段階で『保護済み』と言わない。

## 6. PostgreSQL Transaction・Fault Safety

- DB正本: Scope/Rollout/CommandReceipt/Event/Outboxを一つのTransaction境界で変更。
- 同じScopeを更新する場合、Command Receipt → Scope Row Lock → Rollout Row Lockの順序を守る。別トランザクションも同順序。
- `SERIALIZABLE`を使う場合、SQLSTATE `40001` / `40P01`で**Transaction全体**を再試行。Callbackは再実行可能かつ外部副作用なし。
- Command IDは用途タグ・スキーマVersionを含むCanonical Request Digest（方式O-008）と結び付け、再送時に確定Receiptを読み直す。同ID別内容は衝突拒否。
- `FORBIDDEN/INVALID`のような**確定拒否**はNegative Receiptとして監査/同ID再送へ保存する。`RETRYABLE`や`UNKNOWN_COMMIT`は確定結果と誤記しない。Retention期間の変更はID再利用窓と一緒に検討（PDK-M04-S05）。
- Commit成功か不明なら同じCommand IDで照会・再送して調停。別IDによる二重実行をしない。
- `FOR UPDATE SKIP LOCKED`はQueue Claim用。Row Lockを保持したままLLM処理を待たない。
- OutboxはAt-least-once。外部副作用は操作単位の冪等性とGateway/結果照合が必要。
- `policy_bundles`やDomain Eventの署名/HashをDB保存するだけで真偽を証明したことにしない。
- Lease/HOLD/Monitoringの期限はDB Clockを正本とし、Worker時計に従わない。DBの`now()`はTransaction開始時刻であり長いTransactionには不適切なことがある。Gateway高リスク操作は認可Epochが新鮮だと証明できない場合拒否。
- Policy確定・外部操作の認可は`(scope_activation_epoch,root_authz_epoch,security_epoch,effective_policy_digest,lease_epoch)`を区別する。Canary対象外Rootの認可Epochを無関係に増やさない。
- 本番DBとテストDBを混ぜない。DBに接続できないなら、統合テストはNOT_RUNと報告する。

## 7. Safety / Liveness / Bootstrapの追加ゲート

**実装開始前の順序:** `PDK-M00-S05` Threat Model → `M00-S06` 起点/停止境界 → `M01-S06` Epoch/Freeze契約 → `M01-S05` Model Checking → DB実装。O-002はM06-S08、O-003はM02-S05、O-007はM00-S07/M14-S04にそれぞれ解決Issueが必要。

- **Safety Plane:** 人間のBreak-glassで停止。通常Agentが停止/解除を決めない。DB切断時にはGatewayをdeny-all側へ倒す。ハードウェアを完全停止できるとは主張しない。
- **Safe Baseline:** LKG無効時でも安全停止へ到達。Rollbackの新規Approval待ち禁止。診断/復旧のみ人間認証の固定手続きに限定。
- **Rollout Liveness:** `MONITORING→COMPLETED`の成功Gate、HOLD最大Deadline、超過でABORT→ROLLBACKを定義。通常監視Scheduler/DBが無期限停止する場合まで進行保証しない。
- **Rollback Epoch:** `ROLLING_BACK`の開始で`FROZEN`になり新規権限を拒否。実効Policy切替を原子的に確定した時点だけ、Scope Activation Epochおよび対象Root Authorization Epochを進める。障害時にはFreeze/Safe Baselineを維持。
- **Threat Model:** [THREAT_MODEL.md](THREAT_MODEL.md)を検査。未知Worker・Prompt Injection・Supply Chain・DoSのいずれか未検討なら公開Registrationを有効にしない。
- **モデル検査:** Rollout×Epoch×Leaseの有限状態でSafety+Livenessの仮定を明示。TLA+/Alloy PASSはGo/DB実装の独立検証を省略する理由にはならない。

## 8. 開発者用の再開チェック（手動でも実行可能）

```text
[ ] PADDOCKのGit Rootを識別したか？
[ ] .HARNESSを編集対象に含めていないか？
[ ] decisions.mdのACCEPTEDとDESIGN_BASELINEを区別したか？
[ ] Issues.mdのCursorとGit/Receiptを照合したか？
[ ] 小目標のdepends_onはDONEか？
[ ] 書込み対象の差分・既存変更を確認したか？
[ ] 独立Verifierを呼べない場合、その事実を明示したか？
[ ] 行ったコマンドだけを証拠として記録したか？
[ ] 失敗・未実行検査を隠していないか？
[ ] 次のcontinueで行う具体的な1手を残したか？
[ ] Human Emergency Stop・Safe Baseline・Root Epoch・HOLD期限に違反していないか？
[ ] Receiptの作成者はWorkerではなくRunner/CIの実観測か？
[ ] リポジトリ内参照と小目標DAGをLintしたか？
```

## 9. 未確定・曖昧な状態での停止ルール

- 明示されない外部効果の実行、秘密情報の表示/転記、誤ったGit Rootへの書込みは禁止。
- `decisions.md`がACCEPTEDとする方針を変える必要が生じたら、Issueに理由と代替案を提示し、新しいDecision IDによる承認記録を待つ。実装都合でサイレント修正しない。
- 実装上の未確定項目（例: Event Dispatcher方式）は、現状の推薦だけでは確定扱いしない。安全で局所的なPoC仮定が必要なら`DESIGN_BASELINE`とFixtureに明示。
- 既存ファイルの中身が会話要約と矛盾する場合、**ファイルの現物・実試験結果を優先して状況報告**する。ただし不変の設計判断を無断変更しない。
- サービスが切れた・Toolが失敗した場合、最新コミットとReceiptが確認できない処理を成功と主張しない。

## 10. 運用メモ

- READMEは入口、`decisions.md`は採用判断、`Issues.md`は仕事、`method.md`は実行法。作業中の単なるメモを正本に昇格させない。
- 初期の次の小目標は`PDK-M00-S01`の確認。レビュー修正版はまだGit未コミット・CI未検証。`PDK-M00-S02`以降は実際の新規Gitリポジトリが確認できるまで開始しない。
- **必要最小の参照**: `.HARNESS/rules/MANUAL.lrf`（SIGMA/1の表記）、`.HARNESS/rules/state.lrf`（状態ファイルの役割）、`.HARNESS/agents/SUBAGENTS.lrf`（必要時のHandoff）、`.HARNESS/rules/BOOTSTRAP.lrf`（思想的参照）。これらをPADDOCKの権限の出所にしない。
