# PADDOCK

**完全自律WorkOrder / 分散Trust / 自己改善Governanceの独立プロジェクト**

> `SIGMA/1: PIDGEN/text` · Snapshot: 2026-10-12 · Revision: **design-review/2**
> **MAIN_DESIGN / DESIGN_ONLY**: 設計文書の改訂段階。Go実装・DB Migration・実機検証・新規GitHub Repo作成は行われていない。

既存の [`.HARNESS`](https://github.com/letwir/config/tree/main/.HARNESS) は**参考資料**。PADDOCKを`.HARNESS`配下に置かず、そこから実行規則・資格情報・権限を黙示継承しない。Handoffの表記やIssue状態管理の有用部分だけを参照する。

## 正本・派生物

| ファイル | 役割 | 状態 |
|---|---|---|
| [AGENTS.md](AGENTS.md) | エージェント向けの起動入口。`rules/BOOTSTRAP.lrf` の SIGMA を読み込む | 新規追加。`.HARNESS` の方式を参考にした PADDOCK 独立の規則 |
| [rules/](rules/) | LRF/1 形式の設計・実行規則。入口は [rules/BOOTSTRAP.lrf](rules/BOOTSTRAP.lrf) | 新規追加。`.HARNESS` の LRF は読み込まない |
| [decisions.md](decisions.md) | **ACCEPTED D-001〜D-014（14件）**、Design Baseline、OPEN O-001〜O-010 | 会話転記。人間署名付きGit承認は未完 |
| [Issues.md](Issues.md) | 中目標16領域・小目標89件、安定ID・依存・証拠・Cursor | Issue別の現在状態を参照。各Issueはローカル検証で進行中 |
| [method.md](method.md) | `SIGMA/1: PIDGEN/text`、`CONTINUE/1`、検証Receipt・再開契約 | 設計案 |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Safety Plane、Sybil、Prompt Injection、Supply Chain、DoS等 | 未レビュー・未検証 |
| [docs/bootstrap-safety.md](docs/bootstrap-safety.md) | PoC trust root・DB境界・Emergency Stop/Safe BaselineのDESIGN_BASELINE | S06設計案。運用値はOPEN |
| [docs/issue-dependencies.generated.md](docs/issue-dependencies.generated.md) | 小目標`depends_on`から**機械生成した依存表** | 派生文書・手編集禁止 |
| [scripts/lint_design.py](scripts/lint_design.py) | ID/DAG/OPEN/Markdown参照/Cursorを静的チェック | ローカルの設計文書検査 |

**重要:** 今回のレビューで提示されたEmergency Stop、組込みSafe Baseline、Root別Epoch、Canary期限、CI Receipt等は**DESIGN_BASELINE**。既存の14件のACCEPTEDを無断変更したものではない。Issueにある小目標の完了も意味しない。

## 新しいWorkerの起動・再開

1. Repo Rootを確認する。`.HARNESS`や親Repoに誤って書き込まない。
2. `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`の順に読む。
3. `python3 scripts/lint_design.py` でID・小目標DAG・OPEN解決先を確認する。
4. `Issues.md`のDurable Cursor、実Git差分、CI/検証Receiptを照合する。**Cursorはヒントであり実際の状態より優先しない**。
5. 依存と許可が満たされる**小目標1件**を選ぶ。実行前に`[-] WIP`、実装後に`[~]`、ローカル検査の実観測後`[*]`、ローカル独立検証と受入条件を満たした後`[x]`。現在のユーザー指示ではCI/remote attestationを完了条件にしない。
6. 通信断なら `continue` と指示する。未確定のDB Commitは**同じCommand ID**で照合し、別IDで再実行しない。

### 推奨する設計文書の確認コマンド

```sh
python3 scripts/lint_design.py
python3 scripts/lint_design.py --emit-summary
```

Python標準ライブラリのみ使用。上記は**文書構造**を検査するもので、Go/DB/安全性を実証するものではない。生成した`docs/issue-dependencies.generated.md`は`Issues.md`の派生物であり、中目標同士の依存DAGを表すものではない。

### `SIGMA/1: PIDGEN/text` Handoff（表記例）

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

このEnvelopeは**指示のフォーマットであり、認可権限ではない**。未確認の事実をKnown factsへ入れない。

## PoC想定（未実装）

Go Contract First + pgx Native + PostgreSQL 1インスタンス + Coordinator 2プロセス + Worker Simulator 2体 + Root A/B。Policy v1 → Root BだけCanary v2 → 全体Promote → 故障注入 → 検証済みLKGへRollback（無効なら組込みSafe Baseline）。

- **Epoch** はScope Activation、Root Authorization、Securityの3種類を区別する**設計基準案**。CanaryでRoot Aの旧Credentialを不当に失効しない。
- **Safety** は人間Break-glass、Gateway fail-closed、Rollback事前認可、DeadlineによるHOLD/MONITORING終端を優先設計。
- **検証** は有限モデル検査、DDL/DB競合、Commit-unknown、ReceiptのCI実観測。LLMの説明やダミー署名を合格証拠にしない。

初期Cursorは`PDK-M00-S01`の文書検証。次の安全設計ゲートは`PDK-M00-S05`（Threat Model）と`PDK-M00-S06`（Bootstrap/非常停止境界）。既存HARNESSへの変更、GitHubのRepo作成・Push、DBアクセス、Credential操作は本ドキュメントだけで許可されない。
