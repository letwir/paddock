package domain

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func TestCanaryGateOutcomesAndStructure(t *testing.T) {
	pass := CanaryCheck{ID: "a", State: CanaryCheckPass}
	fail := CanaryCheck{ID: "a", State: CanaryCheckFail}
	unknown := CanaryCheck{ID: "a", State: CanaryCheckUnknown}
	tests := []struct {
		name     string
		required []CanaryCheckID
		checks   []CanaryCheck
		outcome  CanaryGateOutcome
	}{
		{"complete pass", []CanaryCheckID{"a"}, []CanaryCheck{pass}, CanaryGatePass},
		{"explicit fail", []CanaryCheckID{"a"}, []CanaryCheck{fail}, CanaryGateFail},
		{"unknown", []CanaryCheckID{"a"}, []CanaryCheck{unknown}, CanaryGateHold},
		{"missing", []CanaryCheckID{"a"}, nil, CanaryGateHold},
		{"empty evidence", []CanaryCheckID{"a"}, []CanaryCheck{}, CanaryGateHold},
		{"pass plus missing", []CanaryCheckID{"a", "b"}, []CanaryCheck{pass}, CanaryGateHold},
		{"fail plus missing", []CanaryCheckID{"a", "b"}, []CanaryCheck{fail}, CanaryGateFail},
		{"fail plus unknown", []CanaryCheckID{"a", "b"}, []CanaryCheck{fail, {ID: "b", State: CanaryCheckUnknown}}, CanaryGateFail},
		{"nil required", nil, nil, CanaryGateAbort},
		{"empty required", []CanaryCheckID{}, []CanaryCheck{pass}, CanaryGateAbort},
		{"empty required ID", []CanaryCheckID{""}, nil, CanaryGateAbort},
		{"blank required ID", []CanaryCheckID{" \t"}, nil, CanaryGateAbort},
		{"padded required ID", []CanaryCheckID{"a "}, nil, CanaryGateAbort},
		{"duplicate required", []CanaryCheckID{"a", "a"}, []CanaryCheck{pass}, CanaryGateAbort},
		{"out of set", []CanaryCheckID{"b"}, []CanaryCheck{pass}, CanaryGateAbort},
		{"empty check ID", []CanaryCheckID{"a"}, []CanaryCheck{{State: CanaryCheckPass}}, CanaryGateAbort},
		{"padded check ID", []CanaryCheckID{"a"}, []CanaryCheck{{ID: " a", State: CanaryCheckPass}}, CanaryGateAbort},
		{"duplicate pass", []CanaryCheckID{"a"}, []CanaryCheck{pass, pass}, CanaryGateAbort},
		{"duplicate unknown", []CanaryCheckID{"a"}, []CanaryCheck{unknown, unknown}, CanaryGateAbort},
		{"duplicate fail", []CanaryCheckID{"a"}, []CanaryCheck{fail, fail}, CanaryGateAbort},
		{"contradictory pass fail", []CanaryCheckID{"a"}, []CanaryCheck{pass, fail}, CanaryGateAbort},
		{"contradictory pass unknown", []CanaryCheckID{"a"}, []CanaryCheck{pass, unknown}, CanaryGateAbort},
		{"contradictory fail unknown", []CanaryCheckID{"a"}, []CanaryCheck{fail, unknown}, CanaryGateAbort},
		{"zero check state", []CanaryCheckID{"a"}, []CanaryCheck{{ID: "a"}}, CanaryGateAbort},
		{"invalid check state", []CanaryCheckID{"a"}, []CanaryCheck{{ID: "a", State: "pass"}}, CanaryGateAbort},
		{"hold is not check state", []CanaryCheckID{"a"}, []CanaryCheck{{ID: "a", State: "HOLD"}}, CanaryGateAbort},
		{"abort is not check state", []CanaryCheckID{"a"}, []CanaryCheck{{ID: "a", State: "ABORT"}}, CanaryGateAbort},
		{"invalid dominates fail", []CanaryCheckID{"a", "b"}, []CanaryCheck{fail, {ID: "b", State: "invalid"}}, CanaryGateAbort},
		{"extra check dominates fail", []CanaryCheckID{"a"}, []CanaryCheck{fail, {ID: "b", State: CanaryCheckPass}}, CanaryGateAbort},
		{"duplicate required dominates fail", []CanaryCheckID{"a", "a"}, []CanaryCheck{fail}, CanaryGateAbort},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertCanaryGatePermutations(t, CanaryGateInput{RequiredChecks: tc.required, Checks: tc.checks}, tc.outcome)
		})
	}
}

// Exhaust all combinations of absent, UNKNOWN, PASS, FAIL and malformed states
// for three required checks. Only the all-present/all-PASS combination may PASS.
func TestCanaryGateStateCombinationsNoFalsePass(t *testing.T) {
	states := []CanaryCheckState{"missing", CanaryCheckUnknown, CanaryCheckPass, CanaryCheckFail, "", "invalid"}
	for _, a := range states {
		for _, b := range states {
			for _, c := range states {
				t.Run(fmt.Sprintf("%q_%q_%q", a, b, c), func(t *testing.T) {
					input := CanaryGateInput{RequiredChecks: []CanaryCheckID{"a", "b", "c"}}
					invalid, failed, incomplete := false, false, false
					for i, state := range []CanaryCheckState{a, b, c} {
						if state != "missing" {
							input.Checks = append(input.Checks, CanaryCheck{ID: input.RequiredChecks[i], State: state})
						}
						invalid = invalid || state == "" || state == "invalid"
						failed = failed || state == CanaryCheckFail
						incomplete = incomplete || state == "missing" || state == CanaryCheckUnknown
					}
					want := CanaryGatePass
					switch {
					case invalid:
						want = CanaryGateAbort
					case failed:
						want = CanaryGateFail
					case incomplete:
						want = CanaryGateHold
					}
					assertCanaryGatePermutations(t, input, want)
				})
			}
		}
	}
}

func assertCanaryGatePermutations(t *testing.T, input CanaryGateInput, outcome CanaryGateOutcome) {
	t.Helper()
	reasons := map[CanaryGateOutcome]CanaryGateReason{
		CanaryGatePass: CanaryGateAllChecksPassed, CanaryGateFail: CanaryGateFailedCheck,
		CanaryGateHold: CanaryGateIncompleteChecks, CanaryGateAbort: CanaryGateInvalidInput,
	}
	want := CanaryGateDecision{Outcome: outcome, Reason: reasons[outcome]}
	// Independently rotate and reverse both slices to cover every permutation
	// for inputs of up to three elements, including contradictory duplicates.
	for requiredOrder := 0; requiredOrder < 6; requiredOrder++ {
		for checkOrder := 0; checkOrder < 6; checkOrder++ {
			permuted := CanaryGateInput{
				RequiredChecks: canaryGateTestPermutation(input.RequiredChecks, requiredOrder),
				Checks:         canaryGateTestPermutation(input.Checks, checkOrder),
			}
			before := CanaryGateInput{RequiredChecks: slices.Clone(permuted.RequiredChecks), Checks: slices.Clone(permuted.Checks)}
			for repeat := 0; repeat < 2; repeat++ {
				if got := EvaluateCanaryGate(permuted); got != want {
					t.Fatalf("orders=%d/%d repeat=%d: got %+v, want %+v", requiredOrder, checkOrder, repeat, got, want)
				}
				if !reflect.DeepEqual(permuted, before) {
					t.Fatal("evaluation mutated caller input")
				}
			}
		}
	}
}

func canaryGateTestPermutation[T any](items []T, order int) []T {
	result := slices.Clone(items)
	if order%2 != 0 {
		slices.Reverse(result)
	}
	for rotation := 0; rotation < order/2 && len(result) > 0; rotation++ {
		first := result[0]
		copy(result, result[1:])
		result[len(result)-1] = first
	}
	return result
}
