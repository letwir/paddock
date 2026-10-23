package domain

// CanaryCheckID names a caller-selected required check, not a measurement or
// evidence identity. IDs follow the domain's nonempty, unpadded ID convention.
type CanaryCheckID string

func (id CanaryCheckID) Validate() error { return validateID(string(id)) }

// CanaryCheckState is an already-evaluated assertion supplied by the caller.
// Only these three explicit states are valid; the zero value is malformed.
type CanaryCheckState string

const (
	CanaryCheckUnknown CanaryCheckState = "UNKNOWN"
	CanaryCheckPass    CanaryCheckState = "PASS"
	CanaryCheckFail    CanaryCheckState = "FAIL"
)

type CanaryCheck struct {
	ID    CanaryCheckID
	State CanaryCheckState
}

// CanaryGateInput declares a nonempty set of required checks. Checks may omit
// required IDs (incomplete evidence), but may not repeat IDs or add other IDs.
type CanaryGateInput struct {
	RequiredChecks []CanaryCheckID
	Checks         []CanaryCheck
}

// CanaryGateOutcome is distinct from Shadow Replay and rollout state changes.
// A PASS classifies supplied assertions; it does not authorize activation.
type CanaryGateOutcome string

const (
	CanaryGatePass  CanaryGateOutcome = "PASS"
	CanaryGateFail  CanaryGateOutcome = "FAIL"
	CanaryGateHold  CanaryGateOutcome = "HOLD"
	CanaryGateAbort CanaryGateOutcome = "ABORT"
)

type CanaryGateReason string

const (
	CanaryGateInvalidInput     CanaryGateReason = "INVALID_INPUT"
	CanaryGateFailedCheck      CanaryGateReason = "FAILED_CHECK"
	CanaryGateIncompleteChecks CanaryGateReason = "INCOMPLETE_CHECKS"
	CanaryGateAllChecksPassed  CanaryGateReason = "ALL_CHECKS_PASSED"
)

// CanaryGateDecision is a deterministic in-memory record, not a persisted
// Receipt or cryptographic attestation. It retains no references to the input.
type CanaryGateDecision struct {
	Outcome CanaryGateOutcome
	Reason  CanaryGateReason
}

// EvaluateCanaryGate only classifies caller-supplied check states. It performs
// no metric measurement, policy execution, cryptographic verification or IO.
// Structural errors take precedence over FAIL, which takes precedence over
// missing/UNKNOWN evidence (HOLD). PASS requires every required check to PASS.
// Duplicate IDs, including contradictory states, are always structural errors.
// Neither input order nor repeated evaluation changes the decision; input
// slices and their elements are never mutated.
func EvaluateCanaryGate(input CanaryGateInput) CanaryGateDecision {
	abort := CanaryGateDecision{Outcome: CanaryGateAbort, Reason: CanaryGateInvalidInput}
	if len(input.RequiredChecks) == 0 {
		return abort
	}
	required := make(map[CanaryCheckID]struct{}, len(input.RequiredChecks))
	for _, id := range input.RequiredChecks {
		if id.Validate() != nil {
			return abort
		}
		if _, duplicate := required[id]; duplicate {
			return abort
		}
		required[id] = struct{}{}
	}

	seen := make(map[CanaryCheckID]struct{}, len(input.Checks))
	failed, unknown := false, false
	for _, check := range input.Checks {
		if _, ok := required[check.ID]; !ok {
			return abort
		}
		if _, duplicate := seen[check.ID]; duplicate {
			return abort
		}
		seen[check.ID] = struct{}{}
		switch check.State {
		case CanaryCheckPass:
		case CanaryCheckFail:
			failed = true
		case CanaryCheckUnknown:
			unknown = true
		default:
			return abort
		}
	}
	if failed {
		return CanaryGateDecision{Outcome: CanaryGateFail, Reason: CanaryGateFailedCheck}
	}
	if unknown || len(seen) != len(required) {
		return CanaryGateDecision{Outcome: CanaryGateHold, Reason: CanaryGateIncompleteChecks}
	}
	return CanaryGateDecision{Outcome: CanaryGatePass, Reason: CanaryGateAllChecksPassed}
}
