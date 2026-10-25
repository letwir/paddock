# PADDOCK — THREAT_MODEL.md

> SIGMA/1: PIDGEN/text · Threat Model / DESIGN_BASELINE · 2026-10-12
> **未検証の設計ベースライン**。ここに挙げたMitigationはまだ実装・ペンテスト済みではない。

## 0. Scope / 資産 / Trust Boundary

**対象:** Open Enrollment、Steward/NAYA/Verifier、WorkOrder/Attempt、Policy更新、Approval/Gateway、PostgreSQL、SKILL配布、CI/Receipt、通信断復旧。初期PoCはCoordinator×2、Worker Sim×2、Test DB×1、Root A/B。実LLM、外部公開Enrollment、機密RootはPoCでは有効化しない。

**守る資産:** 人間による非常停止権、Trust Anchor / Issuer権限、Policy BundleとDecision正本、Command Receipt、DB状態/Lease/Epoch、Credential・機密データ、Artifactの完全性、利用予算と可用性。

**境界:** (T1) 未知Worker/外部Artifact→LLM/Verifier、(T2) Worker→Coordinator Pull API、(T3) Agent提案→Trust Engine/Authority Broker、(T4) Governance更新→Gateway実効Policy、(T5) DB→Outbox→外部サービス、(T6) CI/署名鍵→Decision/Release。形式上のHandoff、プロンプト、Git上のMarkdownは認可主体ではない。

**攻撃者モデル:** 匿名のSybil Worker集団、悪意あるBuilder/Skill、侵害された既知Worker、誘導されるLLM、評価者結託、偽CI Receipt、古いCredential/Policyの再利用、ネットワーク分断/時計ずれ、依存パッケージの供給元侵害。DB管理者/OSホスト全体の侵害に対しては現PoCで完全防護を主張しない。

## 1. 脅威一覧と検証目標

| Threat | 守る資産 | 入口 / Trust Boundary | 失敗形 | 推奨Mitigation（実装前） | 残余リスク / 非保証 | 受入Issue |
|---|---|---|---|---|---|---|
| TM-001 Prompt Injection | 人間の非常停止権、Policy、Credential | Worker/外部Artifact→Steward・NAYA・Verifier (T1) | 成果物・検索結果・ログ・Skill説明の文章が命令として実行される | 未信頼入力をDataとして分離、構造化出力検証、Tool Gatewayで別認可、Artifactから権限を付与しない、敵対Fixture | モデルが構造化Dataを誤解する残余リスク。保証はGatewayの強制境界に限定 | PDK-M12-S05, PDK-M00-S05 |
| TM-002 SKILL/Go Supply Chain | Artifact完全性、Policy、実行環境 | Builder/依存元→Build/Verifier/配布 (T1,T6) | Digest固定後の悪性コード、依存置換、ビルド注入、署名者侵害 | 出所証拠、依存Pin/Lock、隔離Build、独立検証、SBOM、段階配布、Digest失効、最小権限 | 信頼された署名者・Build基盤の侵害、未知脆弱性は残る | PDK-M12-S02, PDK-M12-S05 |
| TM-003 Enrollment DoS | 可用性、利用予算、DB資源 | 匿名登録→Ingress/Challenge/DB (T1,T2) | 大量ChallengeがCPU/DB/メモリ/費用を枯渇させる | 未知Identity共有Quota、Ingress Rate Limit、Challenge TTL、Queue Limit、事前高負荷処理禁止、隔離 | 分散攻撃の完全遮断や容量保証はしない | PDK-M10-S05 |
| TM-004 Sybil/評価者結託 | Trust Anchor、Trust判断 | Worker/Verifier Identity→Evidence Graph/Trust Engine (T1,T3) | 複数Identityや結託票でTrustを水増しする | Control/Measurement Dependency別Evidence Graph、独立ドメイン証明、未知は票加算しない、信頼根固定 | 完全な独立Identity証明は保証対象外 | PDK-M11-S01, PDK-M11-S02 |
| TM-005 自己昇格・自己承認 | Issuer権限、Policy、Approval | Agent提案→Trust Engine/Authority Broker (T3) | 候補Policyが閾値を下げ、自身にIssuer権限を与える | Kernel Ceiling、Pinned Governance、署名Approval、決定論的判定、G2/G3はPoCで拒否 | Trust Anchorまたは人間承認経路の侵害は別途リスク | PDK-M06-S02, PDK-M06-S04 |
| TM-006 Break-glass拒否・解除 | 人間の非常停止権、外部副作用制御 | Human Safety Plane→Gateway/Agent (T4) | Agentが停止を拒否、または無権限で解除する | 独立Safety Plane、人間停止鍵、解除の別認可、Gateway Fail Closed | 切断端末の物理停止は非保証 | PDK-M06-S05 |
| TM-007 復帰先の死滅 | 可用性、安全なPolicy状態 | Rollback/LKG→Gateway実効Policy (T4) | LKGが失効・破損・削除されRollback不能 | 事前認可Rollback、埋込みdeny-all Safe Baseline、SAFE_STOPPED、人間による復帰 | Safe Baseline移行後の機能可用性は保証しない | PDK-M06-S06, PDK-M07-S04 |
| TM-008 Epoch/Root交差 | DB状態、Lease、RootごとのGrant | Root B Canary→Scope/Root Epoch判定 (T2,T4) | Scope Epoch更新がRoot A Grantを誤失効/誤許可 | Scope Activation / Root Authorization / Global Security Epoch分離、Effective Digest、Root Scope Bind | 実装不備はModel Checkingと故障注入まで残る | PDK-M01-S06, PDK-M07-S07 |
| TM-009 Replay/署名文脈混同 | Trust Anchor、Receipt、DB状態 | 署名入力/Command API→Verifier/Repository (T2,T3) | 署名を別用途へ再利用、正規化差異、Command再送で二重更新 | Canonical Encoding、用途タグ、Schema Version、固定Request Digest付きReceipt | 暗号実装・鍵漏洩のリスクは残る | PDK-M06-S07, PDK-M04-S05 |
| TM-010 Commit Unknown/DB分断 | DB状態、Lease、Receipt、Outbox | Coordinator→DB→応答経路 (T2,T5) | Commit直後の切断で二重更新または古いLeaseが確定 | Row Lock/CAS/Serializable Retry、同一Command ID再照会、Outbox+Inbox、Fault Injection | 外部API Exactly-onceは保証しない | PDK-M04-S06, PDK-M15-S07 |
| TM-011 Clock/Cache staleness | Lease、Credential、Epoch | Worker時計/Gateway Cache→権限判定 (T2,T4) | 時計偽装または古い失効情報で期限切れ権限を許可 | DB Clock、Gateway最大staleness制限、高リスク操作は最新取得不能時deny | DB/Host侵害時の時刻完全性は非保証 | PDK-M03-S06, PDK-M08-S05 |
| TM-012 偽Receipt・Decision改竄 | Decision正本、Receipt、Release権限 | Worker/CI→Receipt、Git→Decision/Release (T6) | Workerがexit 0を捏造、またはDecisionを無断変更 | Runner実観測、署名/Attestation、Protected Branch/CODEOWNERS、人間承認Commit照合 | CI管理者・署名鍵・承認者の侵害は別途残る。ローカル検証はCI Attestationではない | PDK-M14-S04, PDK-M00-S07 |
| TM-013 Active Slot永久占有 | Rollout可用性、DB状態 | HOLD/MONITORING→Scheduler/DB (T2,T4) | 状態が停止し、後続Rolloutが開始不能 | DB時刻Deadline、期限超過ABORT、Monitor完了条件、管理回復手順 | DB時刻/制御面の同時障害では手動復旧が必要 | PDK-M07-S06 |
| TM-014 オフライン失効不能 | Credential、外部副作用制御 | Coordinator断→Worker/Gateway (T2,T4) | 切断中Workerに停止・失効が届かない | 事前配賦ローカル計算だけ許可、外部副作用はGateway経由、期限付きOffline Grant | 切断端末への即時停止・物理停止は非保証 | PDK-M08-S04, PDK-M06-S05 |
| TM-015 データ露出 | Credential、機密データ、Artifact | DB/ログ/Artifact/Sandbox境界 (T1,T2,T5) | Credentialや秘密鍵が保存・ログ・配布物へ混入 | 短期鍵束縛Credential、ログRedaction、Sandbox default deny、Data Zone Policy、隔離検査 | ホストroot侵害時の完全秘匿は非保証 | PDK-M10-S02, PDK-M12-S01 |

## 2. Safety Planeの設計境界

1. **Human Emergency Stop:** 通常Policyの変更許容範囲に属さない固定の停止経路。Agentが自ら発行/解除できる権限とはしない。PoC用Keyと運用Keyを分離し、鍵漏洩・紛失・人間の本人確認/解除QuorumはO-010で決める。
2. **Stop時の強制範囲:** Gatewayでの高リスク副作用、新規Lease/Grant/Policy有効化を禁止。DB稼働中はSecurity Epochを単調増加。DB不在時はGateway側deny-allを優先し、DB復旧後に停止理由・Epochを照合する。
3. **Safe Baseline:** 通常Policy Bundleに依存しない埋込みのdeny-all。診断/復旧は独立した人間認可経路のみ。Agentには通常のTool権限を渡さない。
4. **安全停止の解除:** 自動Rollback成功や経過時間だけで自動解除してはいけない。独立承認と現行署名・Kernel検証後の新Activationを要求。
5. **限界:** Android/Termux等の通信断端末は物理停止できない。直接ネットワーク到達可能な外部副作用経路は、Gateway強制設計に違反するため別途遮断が必要。

## 3. 保証境界・試験ゲート

- **Prevent:** Domain/Ceiling/SQLの不変条件、Signer Identity、Gateway権限、署名用途分離。
- **Detect:** Signed Evidence、Independent Verifier、CI Attestation、Event/Outbox、Prompt Injection/DoS異常検知。
- **Recover:** Emergency Stop、Scope Freeze、Signed LKG、埋込Safe Baseline、Root/Global Epoch、再接続照合。
- **Verify:** TLA+/Alloy有限ModelのSafety/Liveness、単独DB/Coordinator故障注入、Go native fuzz、Clock skew、Prompt Injection・SKILL改竄・Sybilの攻撃Fixture。

**Risk Acceptance:** 未検証の実装や模擬Workerを本番信頼とみなさない。DB Admin/Host compromise、完全な独立Identity証明、外部API Exactly-once、オフライン端末の物理停止は現PoCの保証対象外。`PDK-M00-S05`の独立レビューと承認/ブロッカー記録なしに本番相当のOpen Enrollmentを有効化しない。

## 4. Provenance / Status

2026-10-12のレビュー指摘に対する**新規Threat Model草案**。署名された人間承認Commit、独立Verifier評価、実攻撃テストは未実施。設計への反映は `decisions.md` のDESIGN_BASELINEおよび`Issues.md`で管理する。
