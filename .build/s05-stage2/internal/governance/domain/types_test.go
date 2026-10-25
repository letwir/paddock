package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDigestCanonicalSHA256(t *testing.T) {
	valid := strings.Repeat("a", 64)
	got, err := ParseDigest(valid)
	if err != nil || got != Digest(valid) {
		t.Fatalf("ParseDigest: got %q, %v", got, err)
	}
	for _, invalid := range []string{strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, err := ParseDigest(invalid); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("ParseDigest(%q) error = %v", invalid, err)
		}
	}
	if err := (Digest("")).Validate(); !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("zero digest error = %v", err)
	}
}

func TestEpochNext(t *testing.T) {
	if got, err := Epoch(40).Next(); err != nil || got != 41 {
		t.Fatalf("Next = %d, %v", got, err)
	}
	max := Epoch(^uint64(0))
	if got, err := max.Next(); got != max || !errors.Is(err, ErrEpochOverflow) {
		t.Fatalf("overflow Next = %d, %v", got, err)
	}
}

func TestIdentifiers(t *testing.T) {
	for _, id := range []ScopeID{"scope-a", "root/production"} {
		if err := id.Validate(); err != nil {
			t.Errorf("ScopeID %q: %v", id, err)
		}
	}
	for _, id := range []RolloutID{"rollout-a", "r-1"} {
		if err := id.Validate(); err != nil {
			t.Errorf("RolloutID %q: %v", id, err)
		}
	}
	if err := ScopeID("").Validate(); !errors.Is(err, ErrInvalidID) {
		t.Errorf("empty ScopeID error = %v", err)
	}
	if err := RolloutID(" padded ").Validate(); !errors.Is(err, ErrInvalidID) {
		t.Errorf("padded RolloutID error = %v", err)
	}
}

func TestScopeAndRolloutValues(t *testing.T) {
	scope := Scope{ID: ScopeID("scope-a")}
	if err := scope.Validate(); err != nil {
		t.Fatalf("valid Scope rejected: %v", err)
	}
	if err := (Scope{}).Validate(); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("empty Scope ID error = %v", err)
	}
	rollout := Rollout{ID: RolloutID("rollout-a"), Scope: scope.ID, State: RolloutShadow}
	if err := rollout.Validate(); err != nil {
		t.Fatalf("valid Rollout rejected: %v", err)
	}
	for _, invalid := range []Rollout{
		{Scope: scope.ID, State: RolloutShadow},
		{ID: "rollout-a", State: RolloutShadow},
		{ID: "rollout-a", Scope: scope.ID, State: "UNKNOWN"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("invalid Rollout accepted: %+v", invalid)
		}
	}
}

func TestRolloutAcceptanceStatesAndHoldOutcome(t *testing.T) {
	for _, state := range []RolloutState{RolloutShadow, RolloutCanary, RolloutMonitoring, RolloutCompleted, RolloutRollingBack, RolloutRolledBack, RolloutSafeStopped} {
		if err := state.Validate(); err != nil {
			t.Errorf("acceptance state %q rejected: %v", state, err)
		}
	}
	for _, decision := range []MonitoringDecision{DecisionPass, DecisionFail, DecisionHold, DecisionAbort} {
		if err := decision.Validate(); err != nil {
			t.Errorf("decision %q rejected: %v", decision, err)
		}
	}
	if err := RolloutState(DecisionHold).Validate(); err == nil {
		t.Error("HOLD must not be a rollout state")
	}
	if err := RolloutState("UNKNOWN").Validate(); err == nil {
		t.Error("unknown rollout state accepted")
	}
}

func TestAcceptanceStatePathsAreRepresentable(t *testing.T) {
	paths := [][]RolloutState{
		{RolloutShadow, RolloutCanary, RolloutMonitoring, RolloutCompleted},
		{RolloutCanary, RolloutMonitoring, RolloutRollingBack, RolloutRolledBack},
		{RolloutCanary, RolloutMonitoring, RolloutRollingBack, RolloutSafeStopped},
	}
	for _, path := range paths {
		for _, state := range path {
			if err := state.Validate(); err != nil {
				t.Errorf("state path %v contains invalid state %q: %v", path, state, err)
			}
		}
	}
}
