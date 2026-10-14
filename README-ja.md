# PADDOCK — 日本語版

> SIGMA/1: PIDGEN/text · Snapshot: 2026-10-12 · Revision: design-review/2

PADDOCKは、完全自律型WorkOrder・分散Trust・自己改善型Governanceのための独立プロジェクトです。

本書は[LLM向け構造版](README-forLLM.md)および[英語版](README-en.md)と並列の、人間向けプレゼンテーションです。3版は同じPADDOCKスナップショットを示し、いずれも正本・権威ソースではありません。歴史的識別子は `snapshot_2026-10-12`、revision `design-review/2` です。現在のリポジトリ状態を示すものではありません。`decisions.md`、`Issues.md`、`method.md`、`rules/` が正本であり、本概要に優先します。

## 歴史的スナップショットと境界

当時のPADDOCKは `MAIN_DESIGN / DESIGN_ONLY` と記載され、Go実装、DB migration、実機検証、新規GitHubリポジトリ作成は行われていませんでした。D-001〜D-014（14件）という数はそのスナップショット時点のみを指します。後続のD-015〜D-017は別の後発記録であり、過去の件数や記述を書き換えません。本書は後続実装の有無について主張しません。現在の状態は、正本であるGit状態、`Issues.md`、検証Receiptを確認してください。

Emergency Stop、組込みSafe Baseline、Root別Epoch、Canary期限、CI ReceiptはDESIGN_BASELINEとして記載され、当時の14件のACCEPTED決定を変更したものでも、Issuesの完了を証明するものでもありません。当時の初期Cursorは `PDK-M00-S01` 文書検証、次の安全設計ゲートは `PDK-M00-S05`（Threat Model）と `PDK-M00-S06`（Bootstrap/非常停止境界）でした。これらは日付付きの歴史的記述です。当該文書は、既存HARNESSの変更、GitHubリポジトリ作成・push、DBアクセス、Credential操作を許可していません。

既存の[`.HARNESS`](https://github.com/letwir/config/tree/main/.HARNESS)は参考資料のみです。PADDOCKはその実行規則、資格情報、権限を黙示に継承しません。

PADDOCKは独立リポジトリとして維持し、`.HARNESS`の配下に置いてはいけません。有用なHandoff表記とIssue状態管理の実践のみを参照し、`.HARNESS`の規則・資格情報・権限は継承していません。

## 正本と派生文書

| ファイル | 役割／当時の説明 |
|---|---|
| [AGENTS.md](AGENTS.md) | このスナップショットで新規追加。エージェント起動入口。`rules/BOOTSTRAP.lrf`からSIGMAを読み込む。.HARNESSの方式を参考にしたPADDOCK独立規則。 |
| [rules/](rules/)・[rules/BOOTSTRAP.lrf](rules/BOOTSTRAP.lrf) | このスナップショットで新規追加。LRF/1形式の設計・実行規則。.HARNESSのLRFは読み込まない。 |
| [decisions.md](decisions.md) | 当時のACCEPTED D-001〜D-014（当時のみ14件）、Design Baseline、OPEN O-001〜O-010。会話転記で、人間署名付きGit承認は未完と記載。 |
| [Issues.md](Issues.md) | 当時の中目標16領域・小目標89件、安定ID、依存、証拠、Cursor。現在の状態は各Issueを参照。当時のREADMEはローカル検証中と記載。 |
| [method.md](method.md) | `SIGMA/1: PIDGEN/text`、`CONTINUE/1`、検証Receipt・再開契約。当時は設計案と記載。 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Safety Plane、Sybil、Prompt Injection、Supply Chain、DoS等。当時は未レビュー・未検証と記載。 |
| [docs/bootstrap-safety.md](docs/bootstrap-safety.md) | PoC trust root、DB境界、Emergency Stop/Safe BaselineのDESIGN_BASELINE。S06設計案、運用値はOPEN。 |
| [docs/issue-dependencies.generated.md](docs/issue-dependencies.generated.md) | 機械生成の依存表。派生文書で手編集禁止。 |
| [scripts/lint_design.py](scripts/lint_design.py) | ID/DAG/OPEN解決先/Markdown参照/Cursorの静的検査。ローカル文書検査。 |

生成依存インデックスは小目標の `depends_on` から生成され、中目標間の依存DAGではありません。`decisions.md`、`Issues.md`、`method.md`、`rules/` は本概要に優先します。

## Workerの起動・再開

1. Repo Rootを確認し、`.HARNESS`や親Repoへ誤って書き込まない。
2. `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`の順に読む。
3. `python3 scripts/lint_design.py`を実行し、ID、小目標DAG、OPEN解決先を確認する。
4. `Issues.md`のDurable Cursorを実際のGit差分およびCI/検証Receiptと照合する。Cursorはヒントであり、実状態に優先しない。
5. 依存と許可が満たされる小目標を1件選ぶ。状態は作業前 `[-] WIP`、実装後 `[~]`、ローカル検査の実観測後 `[*]`、独立したローカル検証と受入条件の充足後に限り `[x]`。この原文READMEの当時、当時のユーザー指示ではCI/remote attestationは完了条件として要求されていませんでした。これは原文READMEに関する歴史的記述であり、現在・一般の方針でも、現在の認可でもありません。
6. 通信断時は `continue` と指示する。未確定のDB commitは同じCommand IDで照合し、異なるIDで再実行しない。

### 推奨チェック（コマンド原文）

```sh
python3 scripts/lint_design.py
python3 scripts/lint_design.py --emit-summary
```

Python標準ライブラリのみを使用します。これらは文書構造を検査するもので、Go/DBの動作や安全性を実証しません。生成される `docs/issue-dependencies.generated.md` は `Issues.md` の派生物であり、中目標同士の依存関係DAGではありません。

## SIGMA/1 handoff例（原文）

```text
<Γ>
SIGMA/1: PIDGEN/text
Role: Worker / design-review
Target: PDK-M00-S05; review THREAT_MODEL.md and map risks to stable Issues
Acceptance: Every threat has an Issue, acceptance and remaining risk; do not claim tests ran
Scope: THREAT_MODEL.md and Issues.md (repository-relative); no .HARNESS edits, no VCS push, no live DB/credential access
Known facts: D-001..D-014 imported conversation decisions; Emergency Stop and Safe Baseline are DESIGN_BASELINE; source=decisions.md
SIGMA/1
</Γ>
```

この例ではフィールド順と事実を保持します。Envelopeは指示フォーマットであり、認可権限ではありません。未確認の事実を `Known facts` に含めてはいけません。

## PoC概要（当時は未実装）

Go Contract First + pgx Native + PostgreSQL 1インスタンス + Coordinator 2プロセス + Worker Simulator 2体 + Root A/B。Policy v1 → Root BのみCanary v2 → 全体Promote → 故障注入 → 検証済みLKGへRollback（無効なら組込みSafe Baseline）。

- Epochの設計基準案はScope Activation、Root Authorization、Securityを区別し、Root BのCanary中にRoot Aの旧Credentialを不当に失効させない。
- Safety上の優先事項は、人間のBreak-glass、Gateway fail-closed、事前認可済みRollback、期限によるHOLD/MONITORING終端。
- 検証案は有限モデル検査、DDL/DB競合、Commit-unknown、ReceiptのCI実観測。LLMの説明やダミー署名は合格証拠ではありません。

この概要は、コンポーネントの存在やテスト実行を証明しません。現状は正本と実証拠から判断してください。

## 正本へのリンク

[decisions.md](decisions.md) · [Issues.md](Issues.md) · [method.md](method.md) · [rules/](rules/) · [THREAT_MODEL.md](THREAT_MODEL.md)
