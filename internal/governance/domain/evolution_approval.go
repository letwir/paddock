package domain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	EvolutionApprovalGraphSchema = "paddock.evolution-approval-graph/1"
	EvolutionReviewSchema        = "paddock.evolution-review/1"
	EvolutionApprovalSchema      = "paddock.evolution-approval/1"
	EvolutionVerifierRole        = "VERIFIER"
	EvolutionApproverRole        = "APPROVER"
	EvolutionPassVerdict         = "PASS"
)

var ErrEvolutionApproval = errors.New("invalid evolution approval")

// EvolutionRuleBound fixes one existing policy rule's permitted value ranges.
// Slices supplied to or returned from the immutable config are deep copied.
type EvolutionRuleBound struct {
	RiskTier          GovernanceTier        `json:"risk_tier"`
	Capability        string                `json:"capability"`
	Q1Min             uint64                `json:"q1_min"`
	Q1Max             uint64                `json:"q1_max"`
	Q2Min             uint64                `json:"q2_min"`
	Q2Max             uint64                `json:"q2_max"`
	Q3Min             uint64                `json:"q3_min"`
	Q3Max             uint64                `json:"q3_max"`
	IntegrityDemoteTo []CapabilityTrustTier `json:"integrity_demote_to"`
}

type EvolutionRiskQuorum struct {
	RiskTier                  GovernanceTier `json:"risk_tier"`
	MinVerifierControlDomains uint64         `json:"min_verifier_control_domains"`
	MinApproverControlDomains uint64         `json:"min_approver_control_domains"`
}

type evolutionConfigDocument struct {
	RuleBounds  []EvolutionRuleBound  `json:"rule_bounds"`
	RiskQuorums []EvolutionRiskQuorum `json:"risk_quorums"`
}

// EvolutionKernelConfig is immutable. Its zero value cannot authorize evolution.
// Quorums are S04 control-domain counts, never legacy Kernel signer thresholds.
type EvolutionKernelConfig struct{ document evolutionConfigDocument }

func copyEvolutionBounds(bounds []EvolutionRuleBound) []EvolutionRuleBound {
	out := append([]EvolutionRuleBound(nil), bounds...)
	for i := range out {
		out[i].IntegrityDemoteTo = append([]CapabilityTrustTier(nil), bounds[i].IntegrityDemoteTo...)
	}
	return out
}

func NewEvolutionKernelConfig(bounds []EvolutionRuleBound, quorums []EvolutionRiskQuorum) (EvolutionKernelConfig, error) {
	c := EvolutionKernelConfig{document: evolutionConfigDocument{copyEvolutionBounds(bounds), append([]EvolutionRiskQuorum(nil), quorums...)}}
	if err := c.validate(); err != nil {
		return EvolutionKernelConfig{}, err
	}
	return c, nil
}

func (c EvolutionKernelConfig) RuleBounds() []EvolutionRuleBound {
	return copyEvolutionBounds(c.document.RuleBounds)
}
func (c EvolutionKernelConfig) RiskQuorums() []EvolutionRiskQuorum {
	return append([]EvolutionRiskQuorum(nil), c.document.RiskQuorums...)
}
func (c EvolutionKernelConfig) MarshalJSON() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c.document)
}
func (c *EvolutionKernelConfig) UnmarshalJSON(input []byte) error {
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(input)
	if err != nil {
		return fmt.Errorf("%w: config JSON: %v", ErrEvolutionApproval, err)
	}
	if err := evolutionConfigFields(cb); err != nil {
		return err
	}
	var doc evolutionConfigDocument
	if err := json.Unmarshal(cb, &doc); err != nil {
		return fmt.Errorf("%w: config decode: %v", ErrEvolutionApproval, err)
	}
	value, err := NewEvolutionKernelConfig(doc.RuleBounds, doc.RiskQuorums)
	if err != nil {
		return err
	}
	*c = value
	return nil
}

func evolutionBoundLess(a, b EvolutionRuleBound) bool {
	return a.RiskTier < b.RiskTier || (a.RiskTier == b.RiskTier && a.Capability < b.Capability)
}
func (c EvolutionKernelConfig) validate() error {
	if len(c.document.RuleBounds) == 0 || len(c.document.RiskQuorums) != 4 {
		return fmt.Errorf("%w: missing bounds/quorums", ErrEvolutionApproval)
	}
	for i, b := range c.document.RuleBounds {
		if !validTrustRiskTier(b.RiskTier) || !capabilityText(b.Capability) || (i > 0 && !evolutionBoundLess(c.document.RuleBounds[i-1], b)) {
			return fmt.Errorf("%w: invalid or unsorted bound key", ErrEvolutionApproval)
		}
		if b.Q1Min < 2 || b.Q1Min > b.Q1Max || b.Q1Max > maxTrustPolicySafeInteger || b.Q2Min < 1 || b.Q2Min > b.Q2Max || b.Q2Max > maxTrustPolicySafeInteger || b.Q3Min < 1 || b.Q3Min > b.Q3Max || b.Q3Max > maxTrustPolicySafeInteger {
			return fmt.Errorf("%w: invalid bound ranges", ErrEvolutionApproval)
		}
		// The lexically smallest feasible prefix decides existence without search.
		q2 := b.Q2Min
		if q2 <= b.Q1Min {
			q2 = b.Q1Min + 1
		}
		q3 := b.Q3Min
		if q3 <= q2 {
			q3 = q2 + 1
		}
		if q2 > b.Q2Max || q3 > b.Q3Max {
			return fmt.Errorf("%w: infeasible q ordering", ErrEvolutionApproval)
		}
		if len(b.IntegrityDemoteTo) == 0 {
			return fmt.Errorf("%w: empty demotion set", ErrEvolutionApproval)
		}
		for j, tier := range b.IntegrityDemoteTo {
			if !validIntegrityDemoteTo(tier) || (j > 0 && b.IntegrityDemoteTo[j-1] >= tier) {
				return fmt.Errorf("%w: invalid demotion set", ErrEvolutionApproval)
			}
		}
	}
	for i, q := range c.document.RiskQuorums {
		if q.RiskTier != []GovernanceTier{TierG0, TierG1, TierG2, TierG3}[i] || q.MinVerifierControlDomains == 0 || q.MinApproverControlDomains == 0 || q.MinVerifierControlDomains > maxTrustPolicySafeInteger || q.MinApproverControlDomains > maxTrustPolicySafeInteger {
			return fmt.Errorf("%w: invalid risk quorum", ErrEvolutionApproval)
		}
	}
	return nil
}

func validateEvolutionKernel(s KernelSnapshot) error {
	if s.SchemaVersion != KernelSnapshotSchemaV2 || s.EvolutionKernelConfig == nil {
		return fmt.Errorf("%w: v2 config required", ErrEvolutionApproval)
	}
	// Reuse, rather than reinterpret, the complete legacy base-Kernel rules.
	legacy := s
	legacy.SchemaVersion, legacy.EvolutionKernelConfig = KernelSnapshotSchema, nil
	if err := validateKernel(legacy); err != nil {
		return err
	}
	if err := s.EvolutionKernelConfig.validate(); err != nil {
		return err
	}
	for _, q := range s.EvolutionKernelConfig.document.RiskQuorums {
		if q.MinVerifierControlDomains > uint64(len(s.Signers)) || q.MinApproverControlDomains > uint64(len(s.Signers)) {
			return fmt.Errorf("%w: quorum exceeds pinned signer count", ErrEvolutionApproval)
		}
	}
	return nil
}

// evolutionObjectFields also rejects null values, which encoding/json would
// otherwise silently accept for scalar fields and slices.
func evolutionObjectFields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if err := exactJSONObjectKeys(raw, keys...); err != nil {
		return nil, fmt.Errorf("%w: fields: %v", ErrEvolutionApproval, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%w: object: %v", ErrEvolutionApproval, err)
	}
	for _, key := range keys {
		if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return nil, fmt.Errorf("%w: null %s", ErrEvolutionApproval, key)
		}
	}
	return fields, nil
}
func evolutionArrayFields(raw []byte, keys ...string) error {
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil || records == nil {
		return fmt.Errorf("%w: expected record array", ErrEvolutionApproval)
	}
	for _, record := range records {
		fields, err := evolutionObjectFields(record, keys...)
		if err != nil {
			return err
		}
		for _, key := range []string{"signature", "public_key"} {
			if value, exists := fields[key]; exists {
				var text string
				if err := json.Unmarshal(value, &text); err != nil {
					return fmt.Errorf("%w: %s must be base64 text", ErrEvolutionApproval, key)
				}
				decoded, err := base64.StdEncoding.Strict().DecodeString(text)
				if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
					return fmt.Errorf("%w: noncanonical base64 %s", ErrEvolutionApproval, key)
				}
			}
		}
		if value, exists := fields["capabilities"]; exists {
			var capabilities []string
			if err := json.Unmarshal(value, &capabilities); err != nil || capabilities == nil {
				return fmt.Errorf("%w: capabilities must be an array", ErrEvolutionApproval)
			}
		}
	}
	return nil
}
func evolutionConfigFields(raw []byte) error {
	fields, err := evolutionObjectFields(raw, "rule_bounds", "risk_quorums")
	if err != nil {
		return err
	}
	if err := evolutionArrayFields(fields["rule_bounds"], "risk_tier", "capability", "q1_min", "q1_max", "q2_min", "q2_max", "q3_min", "q3_max", "integrity_demote_to"); err != nil {
		return err
	}
	return evolutionArrayFields(fields["risk_quorums"], "risk_tier", "min_verifier_control_domains", "min_approver_control_domains")
}
func evolutionKernelFields(raw []byte) error {
	// Only called after JCS has validated the original entire document.
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return err
	}
	keys := []string{"schema_version", "version", "signers", "thresholds", "capabilities", "issuer_ceilings"}
	switch header.SchemaVersion {
	case KernelSnapshotSchema:
	case KernelSnapshotSchemaV2:
		keys = append(keys, "evolution_kernel_config")
	default:
		return fmt.Errorf("%w: unsupported kernel schema", ErrEvolutionApproval)
	}
	fields, err := evolutionObjectFields(raw, keys...)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		key  string
		keys []string
	}{
		{"signers", []string{"id", "public_key"}}, {"thresholds", []string{"tier", "threshold"}}, {"issuer_ceilings", []string{"issuer_id", "capabilities"}},
	} {
		if err := evolutionArrayFields(fields[item.key], item.keys...); err != nil {
			return err
		}
	}
	if header.SchemaVersion == KernelSnapshotSchemaV2 {
		return evolutionConfigFields(fields["evolution_kernel_config"])
	}
	return nil
}

type EvolutionApprovalContext struct {
	SchemaVersion    string         `json:"schema_version"`
	KernelDigest     Digest         `json:"kernel_digest"`
	BasePolicyDigest Digest         `json:"base_policy_digest"`
	CandidateDigest  Digest         `json:"candidate_digest"`
	RiskTier         GovernanceTier `json:"risk_tier"`
	BuilderID        string         `json:"builder_id"`
	ProposalID       string         `json:"proposal_id"`
	Nonce            string         `json:"nonce"`
}

func (c EvolutionApprovalContext) validate() error {
	if c.SchemaVersion != EvolutionApprovalGraphSchema || c.KernelDigest.Validate() != nil || c.BasePolicyDigest.Validate() != nil || c.CandidateDigest.Validate() != nil || !validTrustRiskTier(c.RiskTier) || validateID(c.BuilderID) != nil || validateID(c.ProposalID) != nil || validateID(c.Nonce) != nil {
		return fmt.Errorf("%w: invalid context", ErrEvolutionApproval)
	}
	return nil
}
func (c EvolutionApprovalContext) Digest() (Digest, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	b, err := evolutionCanonical(c)
	if err != nil {
		return "", err
	}
	return evolutionDigest(b), nil
}

type EvolutionReview struct {
	ReviewerID     string `json:"reviewer_id"`
	Role           string `json:"role"`
	Verdict        string `json:"verdict"`
	EvidenceDigest Digest `json:"evidence_digest"`
	Signature      []byte `json:"signature"`
}
type EvolutionApproval struct {
	ApproverID string `json:"approver_id"`
	Role       string `json:"role"`
	Signature  []byte `json:"signature"`
}
type evolutionGraphDocument struct {
	SchemaVersion string                   `json:"schema_version"`
	Context       EvolutionApprovalContext `json:"context"`
	Reviews       []EvolutionReview        `json:"reviews"`
	Approvals     []EvolutionApproval      `json:"approvals"`
}

// EvolutionApprovalGraph is a copied immutable context -> reviews -> approvals
// DAG. No arbitrary edges, policy application, persistence or replay ledger exist.
type EvolutionApprovalGraph struct{ document evolutionGraphDocument }

func copyEvolutionReviews(in []EvolutionReview) []EvolutionReview {
	out := append([]EvolutionReview(nil), in...)
	for i := range out {
		out[i].Signature = append([]byte(nil), in[i].Signature...)
	}
	return out
}
func copyEvolutionApprovals(in []EvolutionApproval) []EvolutionApproval {
	out := append([]EvolutionApproval(nil), in...)
	for i := range out {
		out[i].Signature = append([]byte(nil), in[i].Signature...)
	}
	return out
}
func NewEvolutionApprovalGraph(context EvolutionApprovalContext, reviews []EvolutionReview, approvals []EvolutionApproval) (EvolutionApprovalGraph, error) {
	g := EvolutionApprovalGraph{document: evolutionGraphDocument{EvolutionApprovalGraphSchema, context, copyEvolutionReviews(reviews), copyEvolutionApprovals(approvals)}}
	if err := g.validate(); err != nil {
		return EvolutionApprovalGraph{}, err
	}
	return g, nil
}
func (g EvolutionApprovalGraph) Context() EvolutionApprovalContext { return g.document.Context }
func (g EvolutionApprovalGraph) Reviews() []EvolutionReview {
	return copyEvolutionReviews(g.document.Reviews)
}
func (g EvolutionApprovalGraph) Approvals() []EvolutionApproval {
	return copyEvolutionApprovals(g.document.Approvals)
}
func (g EvolutionApprovalGraph) validate() error {
	if g.document.SchemaVersion != EvolutionApprovalGraphSchema {
		return fmt.Errorf("%w: graph schema", ErrEvolutionApproval)
	}
	if err := g.document.Context.validate(); err != nil {
		return err
	}
	if len(g.document.Reviews) == 0 || len(g.document.Approvals) == 0 {
		return fmt.Errorf("%w: missing role records", ErrEvolutionApproval)
	}
	seen := make(map[string]bool)
	for i, r := range g.document.Reviews {
		if validateID(r.ReviewerID) != nil || r.Role != EvolutionVerifierRole || r.Verdict != EvolutionPassVerdict || r.EvidenceDigest.Validate() != nil || len(r.Signature) != ed25519.SignatureSize || (i > 0 && g.document.Reviews[i-1].ReviewerID >= r.ReviewerID) {
			return fmt.Errorf("%w: malformed or unsorted review", ErrEvolutionApproval)
		}
		seen[r.ReviewerID] = true
	}
	for i, a := range g.document.Approvals {
		if validateID(a.ApproverID) != nil || a.Role != EvolutionApproverRole || len(a.Signature) != ed25519.SignatureSize || seen[a.ApproverID] || (i > 0 && g.document.Approvals[i-1].ApproverID >= a.ApproverID) {
			return fmt.Errorf("%w: malformed, repeated or unsorted approver", ErrEvolutionApproval)
		}
	}
	return nil
}
func (g EvolutionApprovalGraph) MarshalJSON() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(g.document)
}
func DecodeEvolutionApprovalGraph(input []byte) (EvolutionApprovalGraph, error) {
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(input)
	if err != nil {
		return EvolutionApprovalGraph{}, fmt.Errorf("%w: graph JSON: %v", ErrEvolutionApproval, err)
	}
	fields, err := evolutionObjectFields(cb, "schema_version", "context", "reviews", "approvals")
	if err != nil {
		return EvolutionApprovalGraph{}, err
	}
	if _, err := evolutionObjectFields(fields["context"], "schema_version", "kernel_digest", "base_policy_digest", "candidate_digest", "risk_tier", "builder_id", "proposal_id", "nonce"); err != nil {
		return EvolutionApprovalGraph{}, err
	}
	if err := evolutionArrayFields(fields["reviews"], "reviewer_id", "role", "verdict", "evidence_digest", "signature"); err != nil {
		return EvolutionApprovalGraph{}, err
	}
	if err := evolutionArrayFields(fields["approvals"], "approver_id", "role", "signature"); err != nil {
		return EvolutionApprovalGraph{}, err
	}
	var doc evolutionGraphDocument
	if err := json.Unmarshal(cb, &doc); err != nil {
		return EvolutionApprovalGraph{}, fmt.Errorf("%w: graph decode: %v", ErrEvolutionApproval, err)
	}
	g := EvolutionApprovalGraph{document: doc}
	if err := g.validate(); err != nil {
		return EvolutionApprovalGraph{}, err
	}
	return g, nil
}
func (g *EvolutionApprovalGraph) UnmarshalJSON(input []byte) error {
	value, err := DecodeEvolutionApprovalGraph(input)
	if err != nil {
		return err
	}
	*g = value
	return nil
}
func (g EvolutionApprovalGraph) CanonicalBytes() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	return evolutionCanonical(g.document)
}
func (g EvolutionApprovalGraph) Digest() (Digest, error) {
	b, err := g.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return evolutionDigest(b), nil
}
func (g EvolutionApprovalGraph) ReviewSetDigest() (Digest, error) {
	if err := g.validate(); err != nil {
		return "", err
	}
	return EvolutionReviewSetDigest(g.document.Reviews)
}

func evolutionCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrEvolutionApproval, err)
	}
	return canonical.NewJCSCodec().CanonicalizeJSON(raw)
}
func evolutionDigest(cb []byte) Digest {
	sum := sha256.Sum256(cb)
	return Digest(hex.EncodeToString(sum[:]))
}

// EvolutionPolicyDigest uses validated ORIGINAL raw policy JSON, never a map
// reconstruction (which would lose the order of rules in the signed document).
func EvolutionPolicyDigest(raw []byte) (Digest, error) {
	if _, err := DecodeTrustPolicy(raw); err != nil {
		return "", err
	}
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	return evolutionDigest(cb), nil
}

func evolutionEnvelope(context EvolutionApprovalContext, schema string, payload any) ([]byte, error) {
	if err := context.validate(); err != nil {
		return nil, err
	}
	cb, err := evolutionCanonical(payload)
	if err != nil {
		return nil, err
	}
	return canonical.Envelope(canonical.NewJCSCodec(), canonical.DomainApproval, canonical.Context{SchemaVersion: schema, Audience: "governance", RequestID: context.ProposalID, Nonce: context.Nonce}, cb)
}
func EvolutionReviewSigningBytes(context EvolutionApprovalContext, review EvolutionReview) ([]byte, error) {
	if validateID(review.ReviewerID) != nil || review.Role != EvolutionVerifierRole || review.Verdict != EvolutionPassVerdict || review.EvidenceDigest.Validate() != nil {
		return nil, fmt.Errorf("%w: invalid review payload", ErrEvolutionApproval)
	}
	cd, err := context.Digest()
	if err != nil {
		return nil, err
	}
	return evolutionEnvelope(context, EvolutionReviewSchema, struct {
		ContextDigest  Digest `json:"context_digest"`
		ReviewerID     string `json:"reviewer_id"`
		Role           string `json:"role"`
		Verdict        string `json:"verdict"`
		EvidenceDigest Digest `json:"evidence_digest"`
	}{cd, review.ReviewerID, review.Role, review.Verdict, review.EvidenceDigest})
}
func EvolutionReviewSetDigest(reviews []EvolutionReview) (Digest, error) {
	if len(reviews) == 0 {
		return "", fmt.Errorf("%w: empty reviews", ErrEvolutionApproval)
	}
	for i, r := range reviews {
		if validateID(r.ReviewerID) != nil || r.Role != EvolutionVerifierRole || r.Verdict != EvolutionPassVerdict || r.EvidenceDigest.Validate() != nil || len(r.Signature) != ed25519.SignatureSize || (i > 0 && reviews[i-1].ReviewerID >= r.ReviewerID) {
			return "", fmt.Errorf("%w: invalid review set", ErrEvolutionApproval)
		}
	}
	cb, err := evolutionCanonical(reviews)
	if err != nil {
		return "", err
	}
	return evolutionDigest(cb), nil
}
func EvolutionApprovalSigningBytes(context EvolutionApprovalContext, reviewSet Digest, approval EvolutionApproval) ([]byte, error) {
	if reviewSet.Validate() != nil || validateID(approval.ApproverID) != nil || approval.Role != EvolutionApproverRole {
		return nil, fmt.Errorf("%w: invalid approval payload", ErrEvolutionApproval)
	}
	cd, err := context.Digest()
	if err != nil {
		return nil, err
	}
	return evolutionEnvelope(context, EvolutionApprovalSchema, struct {
		ContextDigest   Digest `json:"context_digest"`
		ReviewSetDigest Digest `json:"review_set_digest"`
		ApproverID      string `json:"approver_id"`
		Role            string `json:"role"`
	}{cd, reviewSet, approval.ApproverID, approval.Role})
}

func validateEvolutionPolicies(config EvolutionKernelConfig, base, candidate TrustPolicy) error {
	if err := base.validate(); err != nil {
		return err
	}
	if err := candidate.validate(); err != nil {
		return err
	}
	if len(base.rules) != len(candidate.rules) || len(base.rules) != len(config.document.RuleBounds) {
		return fmt.Errorf("%w: changed policy rule keys", ErrEvolutionApproval)
	}
	for _, b := range config.document.RuleBounds {
		key := trustPolicyRuleKey{risk: b.RiskTier, capability: b.Capability}
		_, exists := base.rules[key]
		rule, candidateExists := candidate.rules[key]
		if !exists || !candidateExists {
			return fmt.Errorf("%w: missing or changed rule key", ErrEvolutionApproval)
		}
		if rule.q1MinIndependent < b.Q1Min || rule.q1MinIndependent > b.Q1Max || rule.q2MinIndependent < b.Q2Min || rule.q2MinIndependent > b.Q2Max || rule.q3MinIndependent < b.Q3Min || rule.q3MinIndependent > b.Q3Max {
			return fmt.Errorf("%w: candidate outside bounds", ErrEvolutionApproval)
		}
		allowed := false
		for _, tier := range b.IntegrityDemoteTo {
			if rule.integrityDemoteTo == tier {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%w: candidate demotion outside bounds", ErrEvolutionApproval)
		}
	}
	return nil
}

// EvolutionApprovalEvidence contains only value fields and no aliases to inputs.
type EvolutionApprovalEvidence struct {
	KernelDigest           Digest
	BasePolicyDigest       Digest
	CandidateDigest        Digest
	ContextDigest          Digest
	ReviewSetDigest        Digest
	FinalGraphDigest       Digest
	VerifierControlDomains uint64
	ApproverControlDomains uint64
}

// VerifyEvolutionApprovalGraph is a pure deterministic check. Expected digests,
// proposer identity and domain labels are caller-trusted; it cannot authenticate
// that source, prove freshness/real-world independence, or prevent replay.
func VerifyEvolutionApprovalGraph(snapshot KernelSnapshot, expectedKernel, expectedBase Digest, baseJSON, candidateJSON []byte, proposal ProposalContext, domains ControlDomainSnapshot, graph EvolutionApprovalGraph) (EvolutionApprovalEvidence, error) {
	var ev EvolutionApprovalEvidence
	if err := validateEvolutionKernel(snapshot); err != nil {
		return ev, err
	}
	if err := graph.validate(); err != nil {
		return ev, err
	}
	kd, err := snapshot.Digest()
	if err != nil {
		return ev, err
	}
	if expectedKernel.Validate() != nil || expectedBase.Validate() != nil || kd != expectedKernel {
		return ev, fmt.Errorf("%w: expected kernel mismatch", ErrEvolutionApproval)
	}
	base, err := DecodeTrustPolicy(baseJSON)
	if err != nil {
		return ev, err
	}
	candidate, err := DecodeTrustPolicy(candidateJSON)
	if err != nil {
		return ev, err
	}
	if err := validateEvolutionPolicies(*snapshot.EvolutionKernelConfig, base, candidate); err != nil {
		return ev, err
	}
	bd, err := EvolutionPolicyDigest(baseJSON)
	if err != nil {
		return ev, err
	}
	cd, err := EvolutionPolicyDigest(candidateJSON)
	if err != nil {
		return ev, err
	}
	ctx := graph.document.Context
	if bd != expectedBase || ctx.KernelDigest != expectedKernel || ctx.BasePolicyDigest != expectedBase || ctx.CandidateDigest != cd || validateID(proposal.ProposerID) != nil || ctx.BuilderID != proposal.ProposerID {
		return ev, fmt.Errorf("%w: context/expected digest mismatch", ErrEvolutionApproval)
	}
	keys := make(map[string]ed25519.PublicKey, len(snapshot.Signers))
	for _, signer := range snapshot.Signers {
		keys[signer.ID] = signer.PublicKey
	}
	for signer, label := range domains.domains {
		if _, exists := keys[string(signer)]; !exists || !evidenceText(string(signer)) || !evidenceText(string(label)) {
			return ev, fmt.Errorf("%w: malformed or outside-kernel mapping", ErrEvolutionApproval)
		}
	}
	builderDomain, known := domains.domains[EvidenceSignerID(ctx.BuilderID)]
	if _, exists := keys[ctx.BuilderID]; !exists || !known {
		return ev, fmt.Errorf("%w: unknown builder/domain", ErrEvolutionApproval)
	}
	verifierDomains, approverDomains := map[EvidenceControlDomainID]bool{}, map[EvidenceControlDomainID]bool{}
	// Missing non-builder mappings are allowed but contribute zero. Known builder
	// domains are prohibited participants, not merely discounted from the count.
	countRole := func(id string, own, other map[EvidenceControlDomainID]bool) error {
		if _, exists := keys[id]; !exists || id == ctx.BuilderID {
			return fmt.Errorf("%w: unknown or builder signer", ErrEvolutionApproval)
		}
		label, known := domains.domains[EvidenceSignerID(id)]
		if !known {
			return nil
		}
		if label == builderDomain || other[label] {
			return fmt.Errorf("%w: excluded or overlapping domain", ErrEvolutionApproval)
		}
		own[label] = true
		return nil
	}
	for _, review := range graph.document.Reviews {
		if err := countRole(review.ReviewerID, verifierDomains, approverDomains); err != nil {
			return ev, err
		}
		msg, err := EvolutionReviewSigningBytes(ctx, review)
		if err != nil {
			return ev, err
		}
		if !ed25519.Verify(keys[review.ReviewerID], msg, review.Signature) {
			return ev, fmt.Errorf("%w: review signature", ErrEvolutionApproval)
		}
	}
	rsd, err := graph.ReviewSetDigest()
	if err != nil {
		return ev, err
	}
	for _, approval := range graph.document.Approvals {
		if err := countRole(approval.ApproverID, approverDomains, verifierDomains); err != nil {
			return ev, err
		}
		msg, err := EvolutionApprovalSigningBytes(ctx, rsd, approval)
		if err != nil {
			return ev, err
		}
		if !ed25519.Verify(keys[approval.ApproverID], msg, approval.Signature) {
			return ev, fmt.Errorf("%w: approval signature", ErrEvolutionApproval)
		}
	}
	var quorum EvolutionRiskQuorum
	for _, q := range snapshot.EvolutionKernelConfig.document.RiskQuorums {
		if q.RiskTier == ctx.RiskTier {
			quorum = q
		}
	}
	if uint64(len(verifierDomains)) < quorum.MinVerifierControlDomains || uint64(len(approverDomains)) < quorum.MinApproverControlDomains {
		return ev, fmt.Errorf("%w: insufficient distinct-domain quorum", ErrEvolutionApproval)
	}
	contextDigest, err := ctx.Digest()
	if err != nil {
		return ev, err
	}
	gd, err := graph.Digest()
	if err != nil {
		return ev, err
	}
	return EvolutionApprovalEvidence{kd, bd, cd, contextDigest, rsd, gd, uint64(len(verifierDomains)), uint64(len(approverDomains))}, nil
}
