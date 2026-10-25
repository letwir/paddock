package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	TrustPolicySchemaVersion             = "paddock.trust-policy/1"
	TrustPolicyTypeThresholdTable        = "risk_adaptive_threshold_table"
	maxTrustPolicySafeInteger     uint64 = 9007199254740991
)

var ErrTrustPolicy = errors.New("invalid Trust Policy or evaluation input")

type trustPolicyRuleKey struct {
	risk       GovernanceTier
	capability string
}

type trustPolicyRule struct {
	risk              GovernanceTier
	capability        string
	q1MinIndependent  uint64
	q2MinIndependent  uint64
	q3MinIndependent  uint64
	integrityDemoteTo CapabilityTrustTier
}

// TrustPolicy is an immutable, strictly decoded risk/capability threshold table.
// Its zero value is invalid; construct it with DecodeTrustPolicy.
type TrustPolicy struct {
	rules map[trustPolicyRuleKey]trustPolicyRule
}

type trustPolicyDocument struct {
	SchemaVersion string                    `json:"schema_version"`
	PolicyType    string                    `json:"policy_type"`
	Rules         []trustPolicyRuleDocument `json:"rules"`
}

type trustPolicyRuleDocument struct {
	RiskTier          GovernanceTier      `json:"risk_tier"`
	Capability        string              `json:"capability"`
	Q1MinIndependent  uint64              `json:"q1_min_independent"`
	Q2MinIndependent  uint64              `json:"q2_min_independent"`
	Q3MinIndependent  uint64              `json:"q3_min_independent"`
	IntegrityDemoteTo CapabilityTrustTier `json:"integrity_demote_to"`
}

func validTrustRiskTier(tier GovernanceTier) bool {
	switch tier {
	case TierG0, TierG1, TierG2, TierG3:
		return true
	default:
		return false
	}
}

func validTrustThresholds(q1, q2, q3 uint64) bool {
	return q1 >= 2 && q1 < q2 && q2 < q3 &&
		q1 <= maxTrustPolicySafeInteger && q2 <= maxTrustPolicySafeInteger && q3 <= maxTrustPolicySafeInteger
}

func validIntegrityDemoteTo(tier CapabilityTrustTier) bool {
	return tier == CapabilityTrustQ0 || tier == CapabilityTrustQ1 || tier == CapabilityTrustQ2
}

func exactJSONObjectKeys(raw json.RawMessage, expected ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if fields == nil || len(fields) != len(expected) {
		return fmt.Errorf("%w: object has missing or unknown fields", ErrTrustPolicy)
	}
	for _, key := range expected {
		if _, exists := fields[key]; !exists {
			return fmt.Errorf("%w: missing field %q", ErrTrustPolicy, key)
		}
	}
	return nil
}

// DecodeTrustPolicy validates JCS-safe JSON before decoding the exact closed
// schema. Canonicalization rejects duplicate members/trailing values; it does
// not authenticate the source or grant policy-update authority.
func DecodeTrustPolicy(input []byte) (TrustPolicy, error) {
	canonicalBytes, err := canonical.NewJCSCodec().CanonicalizeJSON(input)
	if err != nil {
		return TrustPolicy{}, fmt.Errorf("decode Trust Policy JSON: %w", err)
	}
	if err := exactJSONObjectKeys(canonicalBytes, "schema_version", "policy_type", "rules"); err != nil {
		return TrustPolicy{}, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(canonicalBytes, &root); err != nil {
		return TrustPolicy{}, fmt.Errorf("%w: decode root fields: %v", ErrTrustPolicy, err)
	}
	var rawRules []json.RawMessage
	if err := json.Unmarshal(root["rules"], &rawRules); err != nil || len(rawRules) == 0 {
		return TrustPolicy{}, fmt.Errorf("%w: rules must be a nonempty array", ErrTrustPolicy)
	}
	const (
		fieldRisk       = "risk_tier"
		fieldCapability = "capability"
		fieldQ1         = "q1_min_independent"
		fieldQ2         = "q2_min_independent"
		fieldQ3         = "q3_min_independent"
		fieldDemote     = "integrity_demote_to"
	)
	for _, rawRule := range rawRules {
		if err := exactJSONObjectKeys(rawRule, fieldRisk, fieldCapability, fieldQ1, fieldQ2, fieldQ3, fieldDemote); err != nil {
			return TrustPolicy{}, err
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(canonicalBytes))
	decoder.DisallowUnknownFields()
	var document trustPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return TrustPolicy{}, fmt.Errorf("decode Trust Policy document: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return TrustPolicy{}, fmt.Errorf("%w: trailing policy data", ErrTrustPolicy)
	}
	if document.SchemaVersion != TrustPolicySchemaVersion || document.PolicyType != TrustPolicyTypeThresholdTable || len(document.Rules) != len(rawRules) {
		return TrustPolicy{}, fmt.Errorf("%w: unsupported schema/type or malformed rules", ErrTrustPolicy)
	}

	rules := make(map[trustPolicyRuleKey]trustPolicyRule, len(document.Rules))
	for _, item := range document.Rules {
		if !validTrustRiskTier(item.RiskTier) || !capabilityText(item.Capability) ||
			!validTrustThresholds(item.Q1MinIndependent, item.Q2MinIndependent, item.Q3MinIndependent) ||
			!validIntegrityDemoteTo(item.IntegrityDemoteTo) {
			return TrustPolicy{}, fmt.Errorf("%w: malformed risk/capability thresholds", ErrTrustPolicy)
		}
		key := trustPolicyRuleKey{risk: item.RiskTier, capability: item.Capability}
		if _, exists := rules[key]; exists {
			return TrustPolicy{}, fmt.Errorf("%w: duplicate risk/capability rule", ErrTrustPolicy)
		}
		rules[key] = trustPolicyRule{
			risk: item.RiskTier, capability: item.Capability,
			q1MinIndependent: item.Q1MinIndependent, q2MinIndependent: item.Q2MinIndependent,
			q3MinIndependent: item.Q3MinIndependent, integrityDemoteTo: item.IntegrityDemoteTo,
		}
	}
	return TrustPolicy{rules: rules}, nil
}

func (p TrustPolicy) validate() error {
	if len(p.rules) == 0 {
		return fmt.Errorf("%w: empty Trust Policy", ErrTrustPolicy)
	}
	for key, rule := range p.rules {
		if !validTrustRiskTier(rule.risk) || !capabilityText(rule.capability) ||
			!validTrustThresholds(rule.q1MinIndependent, rule.q2MinIndependent, rule.q3MinIndependent) ||
			!validIntegrityDemoteTo(rule.integrityDemoteTo) ||
			key != (trustPolicyRuleKey{risk: rule.risk, capability: rule.capability}) {
			return fmt.Errorf("%w: malformed stored Trust Policy rule", ErrTrustPolicy)
		}
	}
	return nil
}

type TrustEvidenceDisposition string

const (
	TrustEvidenceVerified           TrustEvidenceDisposition = "VERIFIED"
	TrustEvidenceUnavailable        TrustEvidenceDisposition = "UNAVAILABLE"
	TrustEvidenceIntegrityViolation TrustEvidenceDisposition = "INTEGRITY_VIOLATION"
)

// TrustCapabilityEvidence is a caller-trusted assessment for one capability.
// IndependentCount is the upstream M11-S02 declared-control-domain count; it is
// not proof of real-world independence or the truth of the disposition.
type TrustCapabilityEvidence struct {
	Capability       string
	Disposition      TrustEvidenceDisposition
	IndependentCount uint64
	ObservedAt       time.Time
	ValidUntil       time.Time
}

// TrustSnapshot supplies the explicit inputs for one pure evaluation. The caller
// is responsible for binding facts/counts to the correct Worker and capability.
type TrustSnapshot struct {
	WorkerID            WorkerID
	RiskTier            GovernanceTier
	CurrentProfile      WorkerCapabilityTrustProfile
	RequestedCapability []string
	Evidence            []TrustCapabilityEvidence
}

func (s TrustSnapshot) validate() (map[string]CapabilityTrustTier, map[string]TrustCapabilityEvidence, []string, error) {
	if ValidateEnrollmentWorkerID(s.WorkerID) != nil || !validTrustRiskTier(s.RiskTier) || s.CurrentProfile.WorkerID() != s.WorkerID || len(s.RequestedCapability) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: malformed TrustSnapshot identity/risk/request", ErrTrustPolicy)
	}
	capabilities := append([]string(nil), s.RequestedCapability...)
	requested := make(map[string]struct{}, len(capabilities))
	current := make(map[string]CapabilityTrustTier, len(capabilities))
	for _, capability := range capabilities {
		if !capabilityText(capability) {
			return nil, nil, nil, fmt.Errorf("%w: malformed requested capability", ErrTrustPolicy)
		}
		if _, exists := requested[capability]; exists {
			return nil, nil, nil, fmt.Errorf("%w: duplicate requested capability", ErrTrustPolicy)
		}
		requested[capability] = struct{}{}
		tier, err := s.CurrentProfile.Tier(capability)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: current profile: %v", ErrTrustPolicy, err)
		}
		current[capability] = tier
	}

	facts := make(map[string]TrustCapabilityEvidence, len(s.Evidence))
	for _, fact := range s.Evidence {
		if !capabilityText(fact.Capability) {
			return nil, nil, nil, fmt.Errorf("%w: malformed evidence capability", ErrTrustPolicy)
		}
		if _, requestedCapability := requested[fact.Capability]; !requestedCapability {
			return nil, nil, nil, fmt.Errorf("%w: evidence for unrequested capability", ErrTrustPolicy)
		}
		if _, exists := facts[fact.Capability]; exists {
			return nil, nil, nil, fmt.Errorf("%w: duplicate capability evidence", ErrTrustPolicy)
		}
		switch fact.Disposition {
		case TrustEvidenceUnavailable:
			if fact.IndependentCount != 0 || !fact.ObservedAt.IsZero() || !fact.ValidUntil.IsZero() {
				return nil, nil, nil, fmt.Errorf("%w: unavailable evidence must not contain count or interval", ErrTrustPolicy)
			}
		case TrustEvidenceVerified, TrustEvidenceIntegrityViolation:
			if !capabilityTime(fact.ObservedAt) || !capabilityTime(fact.ValidUntil) || !fact.ObservedAt.Before(fact.ValidUntil) {
				return nil, nil, nil, fmt.Errorf("%w: malformed evidence interval", ErrTrustPolicy)
			}
		default:
			return nil, nil, nil, fmt.Errorf("%w: unknown evidence disposition", ErrTrustPolicy)
		}
		facts[fact.Capability] = fact
	}
	sort.Strings(capabilities)
	return current, facts, capabilities, nil
}

type TrustDecisionAction string

const (
	TrustDecisionPromote      TrustDecisionAction = "PROMOTE"
	TrustDecisionRetain       TrustDecisionAction = "RETAIN"
	TrustDecisionInsufficient TrustDecisionAction = "INSUFFICIENT"
	TrustDecisionDemote       TrustDecisionAction = "DEMOTE"
)

type TrustDecisionReason string

const (
	TrustReasonNoPolicyRule            TrustDecisionReason = "NO_POLICY_RULE"
	TrustReasonEvidenceMissing         TrustDecisionReason = "EVIDENCE_MISSING"
	TrustReasonEvidenceUnavailable     TrustDecisionReason = "EVIDENCE_UNAVAILABLE"
	TrustReasonEvidenceNotCurrent      TrustDecisionReason = "EVIDENCE_NOT_CURRENT"
	TrustReasonBelowQ1Threshold        TrustDecisionReason = "BELOW_Q1_THRESHOLD"
	TrustReasonPromotionThresholdMet   TrustDecisionReason = "PROMOTION_THRESHOLD_MET"
	TrustReasonCurrentTierAtOrAbove    TrustDecisionReason = "CURRENT_TIER_AT_OR_ABOVE_TARGET"
	TrustReasonIntegrityCountBelowQ1   TrustDecisionReason = "INTEGRITY_COUNT_BELOW_Q1"
	TrustReasonIntegrityDemotion       TrustDecisionReason = "INTEGRITY_DEMOTION"
	TrustReasonIntegrityTargetNotLower TrustDecisionReason = "INTEGRITY_TARGET_NOT_LOWER"
)

type TrustDecision struct {
	Capability   string
	Action       TrustDecisionAction
	PreviousTier CapabilityTrustTier
	TargetTier   CapabilityTrustTier
	Reason       TrustDecisionReason
}

type TrustEvaluationResult struct {
	WorkerID    WorkerID
	RiskTier    GovernanceTier
	EvaluatedAt time.Time
	Decisions   []TrustDecision
}

// EvaluateTrust returns deterministic per-capability proposals from immutable
// caller-trusted inputs. It never mutates the current profile or grants Authority.
func EvaluateTrust(snapshot TrustSnapshot, policy TrustPolicy, evaluatedAt time.Time) (TrustEvaluationResult, error) {
	if !capabilityTime(evaluatedAt) {
		return TrustEvaluationResult{}, fmt.Errorf("%w: invalid evaluatedAt", ErrTrustPolicy)
	}
	if err := policy.validate(); err != nil {
		return TrustEvaluationResult{}, err
	}
	current, facts, capabilities, err := snapshot.validate()
	if err != nil {
		return TrustEvaluationResult{}, err
	}

	decisions := make([]TrustDecision, 0, len(capabilities))
	for _, capability := range capabilities {
		previous := current[capability]
		rule, hasRule := policy.rules[trustPolicyRuleKey{risk: snapshot.RiskTier, capability: capability}]
		if !hasRule {
			decisions = append(decisions, insufficientTrustDecision(capability, previous, TrustReasonNoPolicyRule))
			continue
		}
		fact, hasFact := facts[capability]
		if !hasFact {
			decisions = append(decisions, insufficientTrustDecision(capability, previous, TrustReasonEvidenceMissing))
			continue
		}
		if fact.Disposition == TrustEvidenceUnavailable {
			decisions = append(decisions, insufficientTrustDecision(capability, previous, TrustReasonEvidenceUnavailable))
			continue
		}
		if evaluatedAt.Before(fact.ObservedAt) || !evaluatedAt.Before(fact.ValidUntil) {
			decisions = append(decisions, insufficientTrustDecision(capability, previous, TrustReasonEvidenceNotCurrent))
			continue
		}
		if fact.IndependentCount < rule.q1MinIndependent {
			reason := TrustReasonBelowQ1Threshold
			if fact.Disposition == TrustEvidenceIntegrityViolation {
				reason = TrustReasonIntegrityCountBelowQ1
			}
			decisions = append(decisions, insufficientTrustDecision(capability, previous, reason))
			continue
		}

		if fact.Disposition == TrustEvidenceIntegrityViolation {
			if rule.integrityDemoteTo < previous {
				decisions = append(decisions, TrustDecision{Capability: capability, Action: TrustDecisionDemote, PreviousTier: previous, TargetTier: rule.integrityDemoteTo, Reason: TrustReasonIntegrityDemotion})
			} else {
				decisions = append(decisions, TrustDecision{Capability: capability, Action: TrustDecisionRetain, PreviousTier: previous, TargetTier: previous, Reason: TrustReasonIntegrityTargetNotLower})
			}
			continue
		}

		target := CapabilityTrustQ0
		switch {
		case fact.IndependentCount >= rule.q3MinIndependent:
			target = CapabilityTrustQ3
		case fact.IndependentCount >= rule.q2MinIndependent:
			target = CapabilityTrustQ2
		case fact.IndependentCount >= rule.q1MinIndependent:
			target = CapabilityTrustQ1
		}
		if target == CapabilityTrustQ0 {
			decisions = append(decisions, insufficientTrustDecision(capability, previous, TrustReasonBelowQ1Threshold))
		} else if target > previous {
			decisions = append(decisions, TrustDecision{Capability: capability, Action: TrustDecisionPromote, PreviousTier: previous, TargetTier: target, Reason: TrustReasonPromotionThresholdMet})
		} else {
			decisions = append(decisions, TrustDecision{Capability: capability, Action: TrustDecisionRetain, PreviousTier: previous, TargetTier: previous, Reason: TrustReasonCurrentTierAtOrAbove})
		}
	}
	return TrustEvaluationResult{WorkerID: snapshot.WorkerID, RiskTier: snapshot.RiskTier, EvaluatedAt: evaluatedAt, Decisions: decisions}, nil
}

func insufficientTrustDecision(capability string, current CapabilityTrustTier, reason TrustDecisionReason) TrustDecision {
	return TrustDecision{Capability: capability, Action: TrustDecisionInsufficient, PreviousTier: current, TargetTier: current, Reason: reason}
}
