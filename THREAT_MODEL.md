# PADDOCK — Threat Model

> SIGMA/1: PIDGEN/text · Threat Model / DESIGN_BASELINE · 2026-10-12
> **Status: unverified proposed design baseline.** This entire document is a proposal for future PADDOCK behavior, not a statement of current product requirements, implementation, or agent instructions. Its mitigations and constraints are recommendations for future design, not current authority. No mitigation below is represented as implemented or penetration-tested.

## TM-0. Document semantics and status

- **DESIGN_BASELINE** means proposed future product constraints and mitigations, not an ACCEPTED decision and not a present operational authorization.
- Any **MUST / MUST_NOT** words in this document describe proposed PADDOCK product design only. They do not state current implementation requirements or instructions for agents, and do not grant authority to an agent, worker, GitHub, or a production system.
- Threat rows are records `TM-001` through `TM-015`. Each row associates its asset, entry/trust boundary, failure mode, recommended pre-implementation mitigation, residual risk/non-guarantee, and acceptance Issue references. Row content and associations are retained below.
- T-boundary identifiers are defined in TM-0.3 and used as references in threat records.

### TM-0.1 Scope

**In scope:** Open Enrollment; Steward/NAYA/Verifier; WorkOrder/Attempt; Policy updates; Approval/Gateway; PostgreSQL; SKILL distribution; CI/Receipt; recovery from network interruption.

**Initial PoC configuration:** two Coordinators, two Worker Simulators, one Test DB, and Root A/B. Real LLMs, external/public Enrollment, and confidential Roots are not enabled in the PoC.

### TM-0.2 Protected assets

- Human emergency-stop authority.
- Trust Anchor / Issuer authority.
- Policy Bundle and canonical Decision record.
- Command Receipt.
- DB state, Lease, and Epoch.
- Credentials and confidential data.
- Artifact integrity.
- Resource budget and availability.

### TM-0.3 Trust boundaries

| ID | Boundary |
|---|---|
| T1 | Unknown Worker / external Artifact → LLM / Verifier |
| T2 | Worker → Coordinator Pull API |
| T3 | Agent proposal → Trust Engine / Authority Broker |
| T4 | Governance update → effective Gateway Policy |
| T5 | DB → Outbox → external service |
| T6 | CI / signing key → Decision / Release |

Formal Handoff, prompts, and Markdown in Git are not authorization principals.

### TM-0.4 Attacker model

The model includes anonymous Sybil Worker groups; malicious Builders or Skills; compromised known Workers; an LLM susceptible to manipulation; colluding evaluators; forged CI Receipts; reuse of stale Credentials or Policy; network partition / clock skew; and compromise of dependency suppliers. The PoC does not claim complete protection against compromise of the DB administrator or the entire OS host.

## TM-1. Threat records and verification targets

The table is the canonical record set. Mitigations are recommendations before implementation; residual-risk statements are explicit non-guarantees, not claims of mitigation effectiveness.

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

## TM-2. Safety Plane design recommendations (DESIGN_BASELINE)

The following five items are proposed product-design constraints only. They are not live operational authorization, current-agent policy, or claims that the constraints are implemented:

1. **Human Emergency Stop.** The proposed design constraint is a fixed stop path outside ordinary Policy modification, which ordinary Agents cannot issue or release. PoC keys and operational keys are separate. O-010 handles compromise/loss and human identity/quorum decisions.
2. **Enforcement during Stop.** Stop forbids high-risk side effects, new Leases/Grants, and Policy activation. The Security Epoch is monotonic while the DB is up. When the DB is down, the Gateway denies all; on recovery, the stop reason and Epoch are reconciled.
3. **Safe Baseline.** The proposed design includes an embedded deny-all independent of ordinary Policy Bundles. Recovery is available only through a separate human-authorized path, with no ordinary Agent tools.
4. **Release from safe stop.** Safe stop is not auto-released merely because rollback succeeds or time passes. Release requires independent approval and a new Activation after signature and Kernel validation.
5. **Limits.** Physical stop of disconnected Android/Termux devices is not guaranteed. Direct network paths to external side effects bypass Gateway enforcement by design and must be blocked separately.

## TM-3. Prevention, detection, recovery, verification

These are proposed design dimensions and possible checks, not completed controls or test results.

- **Prevent:** Domain/Ceiling/SQL invariants; Signer Identity; Gateway authorization; signature-purpose separation.
- **Detect:** Signed Evidence; Independent Verifier; CI Attestation; Event/Outbox; anomaly detection for Prompt Injection / DoS.
- **Recover:** Emergency Stop; Scope Freeze; Signed LKG; embedded Safe Baseline; Root/Global Epoch; reconnect reconciliation.
- **Verify:** TLA+/Alloy finite-model Safety/Liveness; isolated DB/Coordinator fault injection; Go native fuzzing; clock skew; attack fixtures for Prompt Injection, SKILL tampering, and Sybil.

## TM-4. Risk acceptance and non-guarantees

As a DESIGN_BASELINE recommendation, do not treat an unverified implementation or simulated Worker as production trust. DB Admin/Host compromise, complete independent Identity proof, external API Exactly-once behavior, and physical stopping of offline devices are outside the current PoC guarantee. Production-equivalent Open Enrollment must not be enabled absent independent review and an approval/blocker record for `PDK-M00-S05`. These are proposed product-design constraints only, not live operational authorization, current-agent policy, or claims of implementation.

## TM-5. Provenance and verification status

This is a **Threat Model draft** responding to review comments dated 2026-10-12. As of this 2026-10-12 draft, no signed approval commit, independent verifier assessment, or real attack testing had been performed. Design incorporation is tracked as DESIGN_BASELINE in `decisions.md` and in `Issues.md`. The source status/date and unverified caveat remain applicable to this restructured document.
