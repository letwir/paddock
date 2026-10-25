# PADDOCK / LRF-1 bootstrap

READ+COMPILE [SIGMA](rules/BOOTSTRAP.lrf) before action; then load matching records from [MANUAL](rules/MANUAL.lrf) and [LOAD](rules/LOAD.lrf) after task classification.

権限の出所は `decisions.md` の **ACCEPTED レジスタ（D-001〜D-014）** と、そこからルーティングされた LRF 記録のみです。`DESIGN_BASELINE` は ACCEPTED ではなく、OPEN の推薦も決定として扱いません。既存 `.HARNESS`（letwir/config）は**参照のみ**で、その実行規則・資格情報・権限・ホスト環境・エージェント配車方針を PADDOCK は黙示に継承しません。

- 読み順: `decisions.md` → `method.md` → `THREAT_MODEL.md` → `Issues.md`。作業選択の前に `python3 scripts/lint_design.py` を実行し、ID・小目標DAG・OPEN解決先・Cursor照合を機械検査する。
- `Issues.md` の Cursor はヒントであり、実際の Git 状態・検証 Receipt より優先しない。矛盾時は実ファイル・Git・検証ログを観測して報告する。
- 効果分類: `RO_LOCAL`=ローカル読み取り/検査、`RO_PUBLIC`=公開読み取り専用、`LW_SCOPE`=依頼された可逆的なワークスペース編集と比例する検査。`EXT_WRITE` / `RELEASE` / `LIVE_WRITE` / `VCS_WRITE` / `DESTRUCT` / `CRED` / `CHARGE` / `PROD_DEP` はその都度タスクの明示承認が必要。分類不能の効果: STOPして質問。
- Worker の自己申告は検証証拠ではない。証拠は Runner による実際の実観測（Exit Code・Hash・対象Revision）のみ。未検証・未実行の検査を成功として報告しない。
- 書込み対象は PADDOCK リポジトリ内。`.HARNESS` や親 Repo に書き込まない。1ファイル1Writer。
- SIGMA/link が欠落・読めない・不正・構造不明・同順位衝突: 該当アクションを STOP して質問する。

## 状態語彙と再開

Issue 状態は `[ ] TODO` → `[-] WIP` → `[~] IMPLEMENTED` → `[*] TESTED` → `[x] DONE`。`[x]` は独立検証（信頼済み CI/Verifier）と受入条件充足の後にのみ付与する。通信断・会話断絶からの再開は `method.md` の `CONTINUE/1`（Preflight→Reconcile→Execute）に従い、`continue` 指示で読める状態を Cursor と Git に残す。

## この文書の位置づけ

本ファイルは**エージェント向け起動入口（ブートストラップ手順）**であり、設計判断の正本ではない。設計判断は `decisions.md`、手順・再開契約は `method.md`、仕事と状態は `Issues.md` を正本とする。人間・汎用閲覧の入口は `README.md`。
