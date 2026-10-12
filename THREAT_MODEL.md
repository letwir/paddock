# PADDOCK — THREAT_MODEL.md

> SIGMA/1: PIDGEN/text · Threat Model / DESIGN_BASELINE · 2026-10-12
> **未検証の設計ベースライン**。ここに挙げたMitigationはまだ実装・ペンテスト済みではない。

## 0. Scope / 資産 / Trust Boundary

**対象:** Open Enrollment、Steward/NAYA/Verifier、WorkOrder/Attempt、Policy更新、Approval/Gateway、PostgreSQL、SKILL配布、CI/Receipt、通信断復旧。初期PoCはCoordinator×2、Worker Sim×2、Test DB×1、Root A/B。実LLM、外部公開Enrollment、機密RootはPoCでは有効化しない。

**守る資産:** 人間による非常停止権、Trust Anchor / Issuer権限、Policy BundleとDecision正本、Command Receipt、DB状態/Lease/Epoch、Credential・機密データ、Artifactの完全性、利用予算と可用性。

**境界:** (T1) 未知Worker/外部Artifact→LLM/Verifier、(T2) Worker→Coordinator Pull API、(T3) Agent提案→Trust Engine/Authority Broker、(T4) Governance更新→Gateway実効Policy、(T5) DB→Outbox→外部サービス、(T6) CI/署名鍵→Decision/Release。形式上のHandoff、プロンプト、Git上のMarkdownは認可主体ではない。

**攻撃者モデル:** 匿名のSybil Worker集団、悪意あるBuilder/Skill、侵害された既知Worker、誘導されるLLM、評価者結託、偽CI Receipt、古いCredential/Policyの再利用、ネットワーク分断/時計ずれ、依存パッケージの供給元侵害。DB管理者/OSホスト全体の侵害に対しては現PoCで完全防護を主張しない。

## 1. 脅威一覧と検証目標

| Threat | Entry / 失敗形 | 推奨Mitigation（実装前） | 受入Issue |
|---|---|---|---|
| TM-001 Prompt Injection | 未知Workerの成果物/検索結果/ログ/Skill説明→Steward、NAYA、Verifierに『指示』として混入 | 未信頼入力をDataとして分離、構造化出力検証、Tool Gatewayの別認可、Artifact経由で権限を付与しない、敵対Fixture | PDK-M12-S05, PDK-M00-S05 |
| TM-002 SKILL/Go Supply Chain | Digest固定済みの悪性コード、依存置換、ビルド注入、署名者侵害 | 出所証拠、依存Pin/Lock、Build隔離、独立検証、SBOM、段階配布、Digest失効、生成物は最小権限 | PDK-M12-S02, PDK-M12-S05 |
| TM-003 Enrollment DoS | 公開登録への大量Challenge、CPU/DB/メモリ/費用枯渇 | 未知Identityの共有Quota、Ingress Rate Limit、Challenge TTL、Queue Limit、事前高負荷処理禁止、隔離 | PDK-M10-S05 |
| TM-004 Sybil/評価者結託 | 攻撃者が複数Identity/Verifierを作りTrustを水増し | Control/Measurement Dependency別Evidence Graph、独立ドメインの証明、未知は票加算しない、信頼根固定 | PDK-M11-S01, PDK-M11-S02 |
| TM-005 自己昇格・自己承認 | 候補Policyが自身の審査閾値を下げ、Issuer権限を生成 | Kernel Ceiling、Pinned Governance、署名済みApproval、決定論的判定、G2/G3はPoCで拒否 | PDK-M06-S02, PDK-M06-S04 |
| TM-006 Break-glass拒否・解除 | AgentがEmergency Stopに従わない/解除する | 独立Safety Plane、停止用人間鍵、解除の別認可、Gateway Fail Closed、オフライン物理停止は非保証 | PDK-M06-S05 |
| TM-007 復帰先の死滅 | LKGが署名失効・破損・削除されRollback不能 | 事前認可Rollback、組込みdeny-all Safe Baseline、SAFE_STOPPED、復帰は人間経路 | PDK-M06-S06, PDK-M07-S04 |
| TM-008 Epoch/Root交差 | Root B CanaryでScope Epochが進みRoot A Grant誤失効/誤許可 | Scope Activation / Root Authorization / Global Security Epochの分離、Effective Digest、Root Scope Bind | PDK-M01-S06, PDK-M07-S07 |
| TM-009 Replay/署名文脈混同 | 署名の別用途への再利用、JSON正規化差異、Command ID再送混乱 | Canonical Encoding、用途タグ、Schema Version、Command Receiptと固定Request Digest | PDK-M06-S07, PDK-M04-S05 |
| TM-010 Commit Unknown/DB分断 | Commit直後の切断、二重更新・古いLeaseでの確定 | DB Row Lock/CAS/Serializable Retry、同じCommand ID再照会、Outbox+Inbox、Fault Injection | PDK-M04-S06, PDK-M15-S07 |
| TM-011 Clock/Cache staleness | Worker時計の偽装、Gateway失効情報の旧キャッシュ | DB Clock、Gateway最大staleness制限、高リスク操作は最新取得不能でdeny | PDK-M03-S06, PDK-M08-S05 |
| TM-012 偽Receipt・Decision改竄 | Workerがexit_code 0を捏造、decisions.mdを無断編集 | CI Runner実観測Receipt、署名/Attestation、Protected Branch/CODEOWNERS、人間承認Commit照合 | PDK-M14-S04, PDK-M00-S07 |
| TM-013 Active Slot永久占有 | HOLD/MONITORINGが停止し次Rolloutが開始不可 | DB時刻ベースDeadline、期限超過でABORT、Monitor完了、管理回復手順 | PDK-M07-S06 |
| TM-014 オフライン失効不能 | 切断中Workerへ停止命令が届かない | 事前配賦されたローカル計算だけ許可、外部副作用はGateway越し、期限付きOffline Grant | PDK-M08-S04, PDK-M06-S05 |
| TM-015 データ露出 | Credential/Artifact/ログに機密や秘密鍵が混入 | 短期鍵束縛Credential、ログRedaction、Sandbox default deny、Data Zone Policy、隔離検査 | PDK-M10-S02, PDK-M12-S01 |

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
