# PADDOCK — decisions.md

> SIGMA/1: PIDGEN/text · Project state / Decision SSOT
> Snapshot: 2026-10-13 · Revision: design-review/2 · Status: DESIGN_ONLY · Repo: **PADDOCK (independent)**
> Provenance: 2026-10-12の設計対話から転記。**未署名の転記記録であり、Gitコミットや人間承認署名の代用品ではない**。Git導入後、保護された承認コミットにより固定する（PDK-M00-S07）。既存 `.HARNESS` は表記・運用上の参照のみ。

## 0. 読み方・正本性

- **ACCEPTED**: 2026-10-12の対話でユーザーが選択肢・方針を明示的に採用した内容の転記。勝手に変更しない。移植後は承認者・承認日・保護されたGit commit/レビュー記録を別途照合し、転記そのものを署名済み承認と扱わない。
- **DESIGN_BASELINE**: 会話中に提案された実装の叩き台。実装前に検証・調整可能で、ACCEPTED と区別する。
- **OPEN**: 未決。選択肢の推薦は決定と扱わない。
- **IMPLEMENTED / TESTED**: 実在する変更とコマンド結果が裏付ける場合のみ記載。現在この文書に検証済み実装はない。
- 本文での MUST / MUST_NOT は **PADDOCKに将来実装するプロダクト上の契約**を意味する。外部のAIやGitHubに対する現在の操作許可ではない。
- 方針変更時は同じIDを上書きせず、変更理由・差分・影響IDを追記して明示的に supersede する。
- `decisions.md`は通常Workerの直接更新対象外。人間承認者に限定したCODEOWNERS/保護ブランチ/署名とCI検証の導入は **DESIGN_BASELINE**（O-007、PDK-M00-S07）。署名は本人承認の代替ではない。

## 1. ACCEPTED Decision Register

| ID | 主題 | 決定 | 対応 |
|---|---|---|---|
| D-001 | 自治権 | **C: 完全自律型**。事前に定義された上限の範囲で作業発見・分解・実装・検証・反映を自動化。人間は原則事後監査 | M01, M08, M11 |
| D-002 | WorkOrder依存 | **B: DAG型**。所属親子はTree、実行依存はDAG、改善ループは新規WorkOrderで表現 | M01, M08 |
| D-003 | 依存Scope | **C: Root独立 + Artifact共有**。Root間に実行依存辺を張らない。SKILL/ArtifactはImmutable DigestとVersion Pinで共有 | M01, M09, M12 |
| D-004 | Scheduler | **B: Active-Active + Worker Pull**。複数CoordinatorがPostgreSQLを共有し、Workerが仕事をPullする | M03, M08 |
| D-005 | オフライン自治 | **C: WorkOrder Policy制御**。オンライン必須操作と、事前配賦予算内のローカル投機計算を作業別に分ける | M08, M09 |
| D-006 | Worker登録 | **C: Open Enrollment + 隔離型**。未知Workerの登録申請は可能。認証・Trust・Authorityを分離 | M10 |
| D-007 | Quarantine昇格 | **C: 完全自動Trust形成型**。複数の独立証拠と固定された権限上限の範囲で自動昇格・降格 | M10, M11 |
| D-008 | Trust Consensus | **B: Risk-Adaptive Quorum**。操作リスクとTierに応じたEvidence要件。投票数より出所・独立性 | M11 |
| D-009 | Trust Policy更新 | **B: Bounded Self-Evolution**。固定Governance Kernelの許容範囲でのみ自律変更 | M06, M07 |
| D-010 | Policy適用一貫性 | **C: Hybrid Epoch + Scoped Canary**。実行はPolicy Digest固定、権限は最新有効Epochで検査、Scope/Root限定Canary | M05, M07 |
| D-011 | Rollout並列性 | **A: Single Active Rollout per Scope**。同一Scopeで有効化・監視・Rollbackは最大1件。候補生成/Shadowは並列可 | M02, M04, M07 |
| D-012 | 実装契約の正本 | **B: Contract First**。Go Domainの契約を先に固定し、永続化Adapterを実装する | M01, M03 |
| D-013 | PostgreSQLアクセス | **A: pgx Native**。ORM/sqlc必須化せず、明示SQLとpgxでTransactionを制御する | M02, M03 |
| D-014 | Repository Boundary | **新規の独立したPADDOCKリポジトリ**。`.HARNESS`は参照・流用のみ、黙示的な認可/規則継承なし | M00 |
| D-015 | Canonicalization/Signature Envelope | **RFC 8785 JCS**をBundle/Approval/Commandのcanonical bytesに採用。Domain Separation、schema version、anti-replayは引き続き必須。実装済みとは主張しない（S07 verifierまで未確認） | PDK-M06-S07 |

### D-014 / Repository Boundary — ACCEPTED (2026-10-12の独立Repo化依頼)

PADDOCKは**新規独立リポジトリ**。`letwir/config/.HARNESS` 内で実装しない。`.HARNESS` の `SIGMA/1: PIDGEN/text`、LRF、Issue状態管理、独立Verifier等は参照・必要に応じた再利用に限る。既存 `.HARNESS` の実行規則、ホスト固有制約、アカウント/エージェント配車方針、認可をPADDOCKへ黙示継承しない。

### D-015 / Canonicalization/Signature Envelope — ACCEPTED (2026-10-13の現在タスクでの明示選択)

ユーザーは現在のタスクで **RFC 8785 JCS** を選択した。Bundle/Approval/Commandのcanonical bytesにJCSを用いる。用途間の再利用を防ぐDomain Separation、署名対象のschema version、anti-replayは引き続き必須とする。これは設計判断の記録であり、実装が存在するとの主張ではない。実装はS07 verifierで確認されるまで未確認。

## 2. システム境界と責務（DESIGN_BASELINE）

| コンポーネント | 責務 | 明確な非責務 |
|---|---|---|
| Steward (候補: Qwen) | 依頼受付、目的解釈、WorkOrderへの分解、必要な仕事の提案 | Lease/権限の自家発行、DB正本更新の専有 |
| Coordinator / Scheduler | Root内DAG・Capability・Budget・優先度に基づく配車、Lease/Fencing、状態遷移の確定 | LLM出力の無条件信頼 |
| Worker | Pull、Attempt処理、ローカルCheckpoint、候補成果の提出 | DONEの単独確定、他Workerへの権限付与 |
| NAYA | 不足したSKILL・治具の発注・生成・再試行 | 自作物の無審査公開、自身へのTrust付与 |
| Independent Verifier | Artifact/Policy/Evidenceの別系統検証 | 署名者・実装者と同一であることを独立票として扱う行為 |
| Trust Engine | Evidence Graphから能力別Trustを決定論的に評価 | Credential発行、信頼根の独断変更 |
| Authority Broker / Gateway | 現行Policy、Issuer Ceiling、Root別認可Epoch、Security Epoch、Leaseで操作許可を強制 | 失効済みAttemptの外部副作用黙認 |
| Safety Plane（設計案） | 人間のbreak-glass、全体停止、Scope凍結、組込みdeny-allへの退避 | Agentによる停止拒否・通常Governance経路からの自己解除 |
| Registry / Storage | 不変SKILL/Artifact、Policy BundleとHash・署名・出所を保存 | 内容を書き換えて同じDigestを再利用 |
| PostgreSQL | 状態・イベント・Activation/Lease/Receiptのトランザクション正本 | 外部API副作用のExactly-once保証 |

GUI/CUI/APIは同じ契約を利用する。GUIはRTS/配車場的な監視・操作を想定するがPoCの必須機能ではない。実装候補はGo Modular Monolith、Coordinator 2プロセス、Worker Simulator 2体、PostgreSQL 1インスタンス（DB-HAは後続）。

## 3. WorkOrder / DAG（DESIGN_BASELINE）

論理Entity: `Definition`, `WorkOrder`, `Dependency`, `Attempt`, `Artifact`, `Event`, `Budget`。DefinitionはGitで版を固定でき、WorkOrderは作業の同一性、Attemptは個々の実行試行を示す。WorkOrder IDは再配車・再試行で変わらない。

- `parent_id` は所属Tree、`depends_on_id` は実行DAGを表す。**親であることは実行の先行条件ではない**。
- DAGの辺は同一`root_id`間にのみ作成可能。辺追加をRoot単位で直列化し、再帰到達性で循環禁止。
- 別Rootは不変Artifact/Skill Digestを共有できる。ただしRead AuthorityやRevocationは毎回検査。
- 例: Worker AがSKILL不足 → NAYA用子WorkOrderを生成 → AがNAYAのDONEに依存 → Verifierが検証 → A再配車。
- 状態候補: `QUEUED`, `READY`, `RUNNING`, `BLOCKED`, `RETRY_WAIT`, `VERIFYING`, `PUBLISHING`, `DONE`, `FAILED`。`PUBLISHING`は検証成功と反映成功を分けるため重要。失効/中止表現は実装時に調整。
- DONEの必要条件は「検証PASS + 必須の反映完了」。読み取り専用仕事は反映不要の場合あり。
- 1 WorkOrderに複数Attempt。`worker_id`, `session_id`, `attempt_id`, 単調増加する`lease_epoch`, `lease_expires_at`を別管理。

## 4. Event / Budget / Distributed Execution（DESIGN_BASELINE）

### Events

- Eventは確定事実の追記記録。Workerの`completed`という自己申告は確定イベントではない。
- 状態更新・Domain Event・Outbox挿入・Command Receipt確定は可能な限り**同一DB Transaction**。
- At-least-once配送、順不同・重複を許す。Consumer Inboxで冪等化。WorkOrder単位に`aggregate_version`を単調増加させる。全体順序は保証しない。
- Outbox Dispatcherの具体方式（Pollingのみ / Polling+NOTIFY / 外部Broker）は **OPEN**。現時点の推薦はPollingであり、採用決定ではない。
- Event EnvelopeとPolicy DSL、Approval Certificate、Command/Verification Receiptは`schema_version`を必須とし、未知の非互換版は拒否する設計案。Event/Outboxの保持・パーティション・再送/Inbox保護期間はO-009で決める。
- `LISTEN/NOTIFY`を導入する場合も起床ヒントとし、永続配送の正本にしない。
- 外部API等への副作用は別の`operation_id`/Idempotency Key、Gateway、結果照合、必要時補償処理で保護。Exactly-onceを無条件に主張しない。

### Budget

- Root → 子の予算はEscrow方式で委譲し、委譲だけで資源を増やさない。
- 資源別不変条件: `spent + reserved + delegated <= granted`。子孫消費を親で二重計上しない。
- 予算は費用、Token、Compute時間、Tool Call等を資源ごとに分離。Root以外にも全体の日/月Quotaが必要。
- 再帰制限: `max_spawn_depth`, `max_total_descendants`, `max_live_children`, `max_attempts`, `deadline`, `repeat_fingerprint`等。
- 子WorkerのAuthorityは親・Issuer・WorkOrder・環境Policyの交差を上限とする。

### Scheduler / Lease

- Active-Active Coordinator間の配車競合にDB行ロック・`FOR UPDATE SKIP LOCKED`などを利用。**Transaction中にモデル処理を待たない**。
- Worker PullでCapability、Trust、Authority、Budget、Slotを再検証して配車し、Attempt作成とLease発行を原子的に確定する。
- 古い`lease_epoch`の結果確定は拒否（Fencing）。旧Workerが既に実行した外部操作はFencingだけでは取消不能。
- オフラインモード: `ONLINE_REQUIRED`と`OFFLINE_COMPUTE`、`CHECKPOINTABLE`を作業ごとに組み合わせる。ネットワーク断≠処理停止。
- Offline Grantは事前配賦範囲のローカル計算・ローカルCheckpointだけを許可。公開・Git Push・機密操作等の外部副作用は禁止。
- Heartbeat、Lease TTL、Reaper間隔の会話中の数値は**仮値で未確定**。AndroidのDoze/Termux停止を正しい復旧の前提として試験する。
- **DB時刻を権威**とする（設計案）。Lease期限・HOLD/Monitoring期限判定でWorker側の時計を信用しない。PostgreSQLの`now()`はTransaction開始時刻、実経過が必要な判定は`clock_timestamp()`等と整合させる。Gateway認可Epochの許容stalenessはO-006で決定。

### Checkpoint

- `Semantic`を標準、`Runtime`は互換Runner限定の最適化。異機種再開は新Attempt。
- L0進捗、L1ローカル未同期、L2永続再開可能、L3Verifier合格・公開済みArtifactを区別。
- 意味的ステップ完了、外部副作用前、一定時間/予算消費後の次の安全地点で保存（時間だけでは途中のLLM計算状態を保存できない）。
- L1は再接続時に候補として検査し、失効済みAttemptから即座にL2/L3に昇格しない。

## 5. Worker Identity / Capability / Trust（DESIGN_BASELINE）

- `worker_id`は恒久識別子、`session_id`は起動セッション、`attempt_id`は試行。公開鍵所有の証明と短期Credentialを分離。
- CapabilityはStatic / Dynamic / Authority / Recoveryに分割。`Claim`と`Evidence`を分け、空きRAM/VRAM等の動的値は短期TTL。
- 認証・能力検査が通っても機密データや任意Shellへの実行権限を付与しない。
- Unknown WorkerのOpen EnrollmentはQuarantine(Q0)から開始。段階案: Q0 Quarantine → Q1 Probation → Q2 General → Q3 Scoped Trusted。Tierは能力別で、アクセス権ではない。
- T0 Declared / T1 Authenticated / T2 Probed / T3 Attestedは証拠の種類を表し、安全度の単純な順位ではない。
- Trust次元: Identity, Competence, Reliability, Integrity, Provenance, Independence。作業成績から管理権限を推定しない。
- Risk-Adaptive Quorumは**Evidence由来の独立性**を要求。同じ測定結果の多数再評価を多数票にしない。独立性不明ならQuorumに加算しない。
- 独立性はMeasurement DependencyとControl Dependencyを分ける。未知Workerの大量Sybil登録に対し全体Admission Budgetを持つ。
- Trust Engineは同じPolicy Digest・Evidence Snapshot・評価時刻なら同じ結果を返す決定論的評価器。判定は`PROMOTE / RETAIN / INSUFFICIENT / DEMOTE / SUSPEND / REVOKE`等。
- Trust Policy DSLは型付き・任意のeval禁止・未知フィールド拒否。統計的成功率（Beta等）は提案例で、閾値・事前分布は未確定。
- Worker Trust昇格はIssuer CeilingとKernelにより上限固定。Workerの評価結果や自己申告はIssuerを作れない。

## 6. Governance / Policy Activation（DESIGN_BASELINE）

### Self-Evolution

- Governance Kernel（Trust Anchor、Issuer Ceiling、署名検証、Revocation、Evolution Boundary）は通常の自律更新対象外。
- Evolutionary Policyだけを境界内で自律改善。緩和も固定下限・独立検証・影響解析・Rollback可能性を通れば候補になり得る。
- Candidateの審査に**Candidate自身の緩和した規則を使用してはいけない**（Pinned Governance）。Proposal、Builder、Verifier、Approval Aggregator、Release Controllerを分離する。
- リスクG0〜G3ごとに必要な評価/独立Quorumを変更。PoCでは独立ドメインを実装・証明できるまでG2/G3を許可しない。

### Policy Distribution

- 不変BundleはDigestと署名で固定。配布済みか（Downloaded/Verified/Ready）と有効権限があるかは別。
- Bundle/Request/Approvalの署名対象を、用途タグ付きの決定的バイト列（候補: RFC 8785 JCS）として固定する。異なる用途で同じ署名を使い回せないDomain Separationと署名対象`schema_version`が必要（詳細方式はO-008）。
- **Epochを3層に分ける設計基準案**: `scope_activation_epoch`はRollout順序、`root_authz_epoch`はRootの実効Policy/認可変更、`security_epoch`は全体緊急失効。以前のPolicy内容へRollbackしても各Epochは減らない。**D-010の実装解釈案であり、追加Accepted Decisionではない。**
- CanaryでRoot Bだけv2ならRoot Bの`root_authz_epoch`を進め、Root Aの認可世代は不変。Scope全体のActivation Epochだけを根拠に、Root AのGrantを拒否しない。Gatewayは`(root_id,effective_digest,root_authz_epoch,security_epoch,attempt_id,lease_epoch)`を評価する。
- Root単位でCanary割当。Scope基準のBaseline DigestとRoot対象のCandidate Digestを組み合わせ、Canary Trust評価はRoot-scoped Overlay。無関係Rootへ波及させない。
- Workerの作業履歴はPinned Policy Digestで再現可能とし、**新しい権限行使は現在の有効Generation/失効状態で再認可**。
- Gatewayが最新Authority状態を確認できなければ高リスク操作はFail Closed。オフライン既発行Grantの即時物理停止は保証できない。
- Rollout状態候補: `SHADOW`, `CANARY`, `MONITORING`, `COMPLETED`, `ROLLING_BACK`, `ROLLED_BACK`, `REJECTED`, `SAFE_STOPPED`。`HOLD/FAIL/ABORT/PASS`はCanary分析の**結果**であり、Rollout状態と混同しない。`HOLD`は監視の中断状態/Decisionとして期限を持ち、無限放置禁止。
- `MONITORING → COMPLETED`は規定観測期間・必要証拠・最終GateのPASSで遷移しScope slotを解放。`HOLD`は最大保持期限を持ち、超過でABORT→Rollback / Safe Stop。DB・Scheduler健全性などの公平性仮定がない場合、進行保証を主張しない。
- `ROLLING_BACK`の開始時はScopeを`FROZEN`にして高リスク操作を拒否。**Scope Epoch加算は最終的な実効Policy切替をDBで確定するときに1回**（40→41→42→43というFixture維持）。切替対象RootのRoot Epochも加算。停止開始から確定までの間はFreeze Gateが権限行使を拒否する。
- CanaryはPASS / FAIL / HOLD / ABORT。証拠不足はHOLDでありPASSではない。
- 同一ScopeのActive Rollout (`CANARY` / `MONITORING` / `ROLLING_BACK`、Deadline待ちのHOLD中を含む) 最大1件。Shadow候補は複数存在可能。`SAFE_STOPPED`は安全のため更新を禁止するScope Modeであり、通常の完了扱いにはしない。
- Rollbackは**事前に許可された安全側への遷移**であり、新しい通常Approval待ちで妨げない。LKG Bundleが署名失効/破損/禁止なら、組込みの`Safe Baseline`（deny-all + 信頼済み診断・復旧のみ）に退避する。Safe Baselineは通常の配布Bundle/期限署名を前提にしない。復旧/解除は人間認証済みSafety Plane経由。
- RollbackはCredential/Lease/Trustの再評価も伴う。DB障害・通信断ではGatewayがFail Closed、オフライン端末の物理停止は保証しない。外部副作用が遡及的に消えるわけではない。

### 固定シナリオ（PoC期待状態、未実測）

| Phase | Root A | Root B | Activation Epoch | Rollout |
|---|---|---|---:|---|
| Baseline | v1 | v1 | 40 | SHADOW |
| Root B Canary | v1 | v2 | 41 | CANARY |
| Promoted | v2 | v2 | 42 | MONITORING |
| Rollback | v1 | v1 | 43 | ROLLED_BACK |

数値40〜43はテストFixture用で、DBの現在値ではない。

## 7. Go / PostgreSQL実装上の基準案（未検証）

- Contract First。Go標準Domain型はDBやHTTPをimportしない。`Application Service`がUse Caseを指揮し、`GovernanceTx` Interfaceを`postgres` Adapterが実装。
- 推奨（未正式採用の詳細）: Go Modular Monolith、`cmd/coordinator`, `cmd/worker-sim`, `internal/governance`, `internal/scheduler`, `internal/authority`, `internal/storage/postgres`、`migrations`、`tests/integration`。
- pgx Nativeで明示SQL、Scoped Transaction、`SERIALIZABLE`での`40001`/`40P01`再試行。再試行Callbackには外部副作用を含めない。
- ロック順序の設計案: Command Receipt → Scope `FOR UPDATE` → Rollout `FOR UPDATE`。最終更新時にCASでEpoch/State照合。
- 初期テーブル案: `policy_bundles`, `policy_scopes`, `roots`, `policy_rollouts`, `rollout_targets`, `governance_approvals`, `command_receipts`, `domain_events`, `event_outbox`, `event_inbox`, `security_generation`。
- DB制約: `UNIQUE (rollout_id, scope_id)`と複合外部キーでCanary Root Scope一致; Partial Unique IndexでScope当たりActive Rollout最大1; `UNIQUE (aggregate_kind,aggregate_id,aggregate_version)`; `UNIQUE(command_id)`。
- `policy_scopes.live_rollout_id`、`policy_rollouts.last_activation_epoch`は**初期Migrationから整合**させる。過去の会話で提示されたDDLやAdapter断片は不完全・未実測なのでそのまま製品コードとして貼り付けない。
- `StartCanary`: 承認証拠検査 → Root所属検証 → Domain遷移 → Scope/Rollout/Target更新 → Event/Outbox/Receipt確定を同じDB Transactionで行う。
- `Promote`: CandidateをScope BaselineにしEpoch+1、Monitoringへ。`Rollback`: LKG Digestへ戻しEpoch+1、Credential等再評価。
- Commit応答喪失への対策は`command_id`と正規化Request Digest。**同一Command再送でEpochを再増分しない**。異なるRequestにID使い回しは拒否。
- Transaction整合性と外部副作用のExactly-onceは異なる。Gatewayに操作別Idempotency/再照合が必要。
- Policy署名/Approval署名の検証は本物の公開鍵による独立検証が必要。`approved:true`やダミー署名だけで本番相当の権限を通さない。
- DBテストは専用DBで実施し、`go test -race`単独ではCoordinator間競合の証拠にしない。

## 8. 明示的に未確定（OPEN Decision Backlog）

| ID | 論点 | 現状 | Issue |
|---|---|---|---|
| O-001 | Event Dispatcher | Polling / Polling+NOTIFY / 外部Brokerから**未選択**。Pollingは推薦のみ | PDK-M05-S02 |
| O-002 | Approval公開鍵の管理・鍵更新 | PoC専用Key Fixtureと本番Trust Anchorを分離して未決項目を閉じる | PDK-M06-S08 |
| O-003 | DSN・PostgreSQL version・Migration tool | Test DB環境/秘密値非記載/Migration Runner方式が未確定 | PDK-M02-S05 |
| O-004 | Worker Sandbox実装 | WASM/WASI・VM等は設計案。Termux PRootは安全な隔離境界とみなさない | PDK-M12-S01 |
| O-005 | UI/CUI、NAYA実モデル | PoC以降 | PDK-M13-S01, PDK-M13-S03 |
| O-006 | Token閾値/Lease秒数/Trust統計閾値 | 例示値のみ。Gateway認可キャッシュ最大staleness、HOLD/Monitoring期限も未決 | PDK-M07-S06, PDK-M08-S05, PDK-M11-S03 |
| O-007 | 公開先・CI・GitHubリポジトリ名 | 新規独立Repoであること以外は未決。Decision保護/Verifier of Recordの設計も必要 | PDK-M00-S07, PDK-M14-S04 |
| O-008 | Canonicalization/Signature Envelope | RFC 8785 JCSを選択済み（D-015）。Domain Separation、schema version、anti-replayは引き続き必須 | PDK-M06-S07 |
| O-009 | Event/Outbox retention・schema evolution | 保持期間・partition/archival/consumer replay対応を未決 | PDK-M05-S05 |
| O-010 | 安全停止の解除・人間鍵とTrust Rootの更新 | Safety Planeでの失効・復旧が必要。運用鍵/復旧Quorumは未決 | PDK-M00-S06, PDK-M06-S05 |

## 9. Main Design Review / 検証前の必須補強（DESIGN_BASELINE）

**追加の安全契約案（今回の設計改訂で提案。D-001〜D-014を置換する新しいACCEPTEDではない）:**

1. **Human Break-glass:** 自律更新系から独立した固定Safety Plane。人間の強認証・最小権限・二重承認の要否はO-010で確定。可能な場合にSecurity Epochを進め、新規配車・Credential・外部副作用を止め、停止解除には別の人間承認を要求。DB到達不能ならGatewayはローカルdeny-all; 再接続時に停止意図を永続化/照合。端末の物理停止は保証外。
2. **Safe Baseline:** LKG失効・破損・互換性欠落時でも停止可能な埋込deny-all。復旧・診断操作は固定の別経路のみで、通常のWorker Credentialを使わない。復帰は署名済み/検証済みPolicyに対する新規Activationとして実施。
3. **Risk/Threat Model:** [THREAT_MODEL.md](THREAT_MODEL.md)に信頼境界・prompt injection・未知Worker/Sybil/DoS・SKILL/Go依存のSupply Chain・Coordinator/DB/Clock・署名鍵漏洩・失効時の故障モデルを整理。`PDK-M00-S05`は実装前のゲート。
4. **Evidence Receipts:** Worker自己報告は証拠ではない。実際にコマンドを呼ぶRunnerがExit Code・Go version・Git treeとdirty-diff hash・対象Hashを生成し、独立したCIをVerifier of Recordにする（CI自体の信頼性、O-007は未確定）。否定的なCommand Receiptの保持/再送時の意味も契約化する。
5. **Validation:** Rollout×Epoch×Leaseの有限モデル検査、接続断/Commit-unknownの故障注入、Policy DSL native fuzz、Schema進化試験を追加。モデル検査のPASSは実装の正しさの証明にはならない。

## 10. PoC範囲と検証状態

**PoC v0.1（最小Vertical Slice）:** Coordinator 2プロセス + Worker Simulator 2体 + PostgreSQL 1インスタンス、Root A/Bでv1→v2 Shadow/Canary→全体反映→Fault Injection→Rollback。DB制約、Command冪等性、Event/Outbox原子性、Epoch単調性を検査。

**Deferred:** 実LLM、NAYA SKILL生成、実Worker自動登録、真の独立Trust Domain、Budget/Checkpoint実装、DB HA、GUI/CUI。

**Evidence status as of this snapshot:** 実装ファイル、Migration適用、Integration Test、独立Verifier実行の成功証拠はいずれも**未確認**。コード・DDLの会話中の提示は`DESIGN_BASELINE`に留まる。

## 11. 履歴

- 2026-10-12: D-001〜D-013を会話内の明示選択として整理。D-014独立Repo境界を追加。実装完了を示す記録ではない。
- 2026-10-12: 設計レビューに基づきSafety Plane、Safe Baseline、Root別Epoch、監視liveness、Threat Model等を**DESIGN_BASELINE**として追記。正式なACCEPTED Decisionは増やしていない。Git承認Commitは未確定。
- 2026-10-13: 現在タスクでのユーザー明示選択に基づきD-015を追記。RFC 8785 JCSをBundle/Approval/Commandのcanonical bytesに採用し、Domain Separation・schema version・anti-replayを必須として保持。実装はS07 verifierまで未確認。
