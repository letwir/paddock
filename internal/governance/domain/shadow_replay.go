package domain

import "sort"

// ShadowRequestID identifies the same fixed logical request in both evaluations.
// The caller supplies the decisions; this classifier does not execute policies.
type ShadowRequestID string

type ShadowPolicyDecision string

const (
	ShadowAllow ShadowPolicyDecision = "ALLOW"
	ShadowDeny  ShadowPolicyDecision = "DENY"
)

type ShadowReplayRequest struct {
	RequestID ShadowRequestID      `json:"request_id"`
	Decision  ShadowPolicyDecision `json:"decision"`
}

// ShadowAttackAssessment is an explicit fixture assertion, not a verified fact.
// Both the zero value and UNKNOWN represent incomplete evidence, never CLEAR.
type ShadowAttackAssessment string

const (
	ShadowAttackUnknown  ShadowAttackAssessment = "UNKNOWN"
	ShadowAttackClear    ShadowAttackAssessment = "CLEAR"
	ShadowAttackDetected ShadowAttackAssessment = "DETECTED"
)

type ShadowReplayEvidence struct {
	RequestID       ShadowRequestID        `json:"request_id"`
	Sybil           ShadowAttackAssessment `json:"sybil"`
	ForgedEvaluator ShadowAttackAssessment `json:"forged_evaluator"`
}

// ShadowReplayInput contains fixed baseline/candidate decisions and per-request
// evidence. Request sets must be nonempty, unique and identical. Evidence may
// be missing (HOLD), but may not be duplicated or refer to an unrelated request.
type ShadowReplayInput struct {
	Baseline  []ShadowReplayRequest  `json:"baseline"`
	Candidate []ShadowReplayRequest  `json:"candidate"`
	Evidence  []ShadowReplayEvidence `json:"evidence"`
}

// ShadowReplayOutcome is separate from rollout monitoring and grants no approval.
type ShadowReplayOutcome string

const (
	ShadowReplayPass  ShadowReplayOutcome = "PASS"
	ShadowReplayFail  ShadowReplayOutcome = "FAIL"
	ShadowReplayHold  ShadowReplayOutcome = "HOLD"
	ShadowReplayAbort ShadowReplayOutcome = "ABORT"
)

type ShadowReplayReason string

const (
	ShadowReasonEmptyRequests         ShadowReplayReason = "EMPTY_REQUESTS"
	ShadowReasonInvalidRequest        ShadowReplayReason = "INVALID_REQUEST"
	ShadowReasonDuplicateBaseline     ShadowReplayReason = "DUPLICATE_BASELINE_REQUEST"
	ShadowReasonDuplicateCandidate    ShadowReplayReason = "DUPLICATE_CANDIDATE_REQUEST"
	ShadowReasonRequestSetMismatch    ShadowReplayReason = "REQUEST_SET_MISMATCH"
	ShadowReasonInvalidEvidence       ShadowReplayReason = "INVALID_EVIDENCE"
	ShadowReasonDuplicateEvidence     ShadowReplayReason = "DUPLICATE_EVIDENCE"
	ShadowReasonEvidenceMismatch      ShadowReplayReason = "EVIDENCE_REQUEST_MISMATCH"
	ShadowReasonDenyToAllow           ShadowReplayReason = "DENY_TO_ALLOW"
	ShadowReasonSybil                 ShadowReplayReason = "SYBIL_EVIDENCE"
	ShadowReasonForgedEvaluator       ShadowReplayReason = "FORGED_EVALUATOR_EVIDENCE"
	ShadowReasonIncompleteEvidence    ShadowReplayReason = "INCOMPLETE_EVIDENCE"
	ShadowReasonCompleteValidEvidence ShadowReplayReason = "COMPLETE_VALID_EVIDENCE"
)

// ShadowSemanticDiff contains only changed decisions, ordered by RequestID.
// ALLOW to DENY is reported but is not the selected regression condition.
type ShadowSemanticDiff struct {
	RequestID ShadowRequestID      `json:"request_id"`
	Baseline  ShadowPolicyDecision `json:"baseline"`
	Candidate ShadowPolicyDecision `json:"candidate"`
}

type ShadowReplayResult struct {
	Outcome     ShadowReplayOutcome  `json:"outcome"`
	ReasonCodes []ShadowReplayReason `json:"reason_codes"`
	Diffs       []ShadowSemanticDiff `json:"diffs,omitempty"`
}

// EvaluateShadowReplay is a pure deterministic fixture policy classifier. It
// performs no cryptographic verification, operational Sybil detection, policy
// execution, persistence or authorization. All evidence is caller-supplied data.
//
// Structural errors take precedence (ABORT, with no partial diff). Otherwise any
// DENY to ALLOW change or explicit attack evidence is FAIL, even with incomplete
// evidence; absent those conditions, incomplete evidence is HOLD, not PASS.
// Only complete valid evidence can PASS. Reasons are unique and lexicographically
// sorted, including incomplete evidence alongside FAIL when applicable. Input
// order is irrelevant, and neither input slices nor their elements are mutated.
func EvaluateShadowReplay(input ShadowReplayInput) ShadowReplayResult {
	reasons := make(map[ShadowReplayReason]bool)
	baseline := indexShadowRequests(input.Baseline, ShadowReasonDuplicateBaseline, reasons)
	candidate := indexShadowRequests(input.Candidate, ShadowReasonDuplicateCandidate, reasons)
	if len(input.Baseline) == 0 || len(input.Candidate) == 0 {
		reasons[ShadowReasonEmptyRequests] = true
	}
	for id := range baseline {
		if _, ok := candidate[id]; !ok {
			reasons[ShadowReasonRequestSetMismatch] = true
		}
	}
	for id := range candidate {
		if _, ok := baseline[id]; !ok {
			reasons[ShadowReasonRequestSetMismatch] = true
		}
	}

	evidence := make(map[ShadowRequestID]ShadowReplayEvidence, len(input.Evidence))
	for _, item := range input.Evidence {
		if validateID(string(item.RequestID)) != nil ||
			!validShadowAssessment(item.Sybil) || !validShadowAssessment(item.ForgedEvaluator) {
			reasons[ShadowReasonInvalidEvidence] = true
		}
		if _, exists := evidence[item.RequestID]; exists {
			reasons[ShadowReasonDuplicateEvidence] = true
		}
		if _, exists := baseline[item.RequestID]; !exists {
			reasons[ShadowReasonEvidenceMismatch] = true
		}
		evidence[item.RequestID] = item
	}
	if len(reasons) != 0 {
		return shadowReplayResult(ShadowReplayAbort, reasons, nil)
	}

	var diffs []ShadowSemanticDiff
	failed, incomplete := false, false
	for id, before := range baseline {
		after := candidate[id]
		if before != after {
			diffs = append(diffs, ShadowSemanticDiff{RequestID: id, Baseline: before, Candidate: after})
		}
		if before == ShadowDeny && after == ShadowAllow {
			reasons[ShadowReasonDenyToAllow] = true
			failed = true
		}
		item, present := evidence[id]
		if !present || item.Sybil == "" || item.Sybil == ShadowAttackUnknown ||
			item.ForgedEvaluator == "" || item.ForgedEvaluator == ShadowAttackUnknown {
			incomplete = true
			reasons[ShadowReasonIncompleteEvidence] = true
		}
		if item.Sybil == ShadowAttackDetected {
			failed = true
			reasons[ShadowReasonSybil] = true
		}
		if item.ForgedEvaluator == ShadowAttackDetected {
			failed = true
			reasons[ShadowReasonForgedEvaluator] = true
		}
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].RequestID < diffs[j].RequestID })
	if failed {
		return shadowReplayResult(ShadowReplayFail, reasons, diffs)
	}
	if incomplete {
		return shadowReplayResult(ShadowReplayHold, reasons, diffs)
	}
	reasons[ShadowReasonCompleteValidEvidence] = true
	return shadowReplayResult(ShadowReplayPass, reasons, diffs)
}

func indexShadowRequests(requests []ShadowReplayRequest, duplicate ShadowReplayReason, reasons map[ShadowReplayReason]bool) map[ShadowRequestID]ShadowPolicyDecision {
	indexed := make(map[ShadowRequestID]ShadowPolicyDecision, len(requests))
	for _, request := range requests {
		if validateID(string(request.RequestID)) != nil ||
			(request.Decision != ShadowAllow && request.Decision != ShadowDeny) {
			reasons[ShadowReasonInvalidRequest] = true
		}
		if _, exists := indexed[request.RequestID]; exists {
			reasons[duplicate] = true
		}
		indexed[request.RequestID] = request.Decision
	}
	return indexed
}

func validShadowAssessment(value ShadowAttackAssessment) bool {
	switch value {
	case "", ShadowAttackUnknown, ShadowAttackClear, ShadowAttackDetected:
		return true
	default:
		return false
	}
}

func shadowReplayResult(outcome ShadowReplayOutcome, reasons map[ShadowReplayReason]bool, diffs []ShadowSemanticDiff) ShadowReplayResult {
	codes := make([]ShadowReplayReason, 0, len(reasons))
	for code := range reasons {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	return ShadowReplayResult{Outcome: outcome, ReasonCodes: codes, Diffs: diffs}
}
