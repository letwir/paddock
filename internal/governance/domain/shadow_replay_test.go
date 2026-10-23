package domain

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"slices"
	"testing"
)

type shadowReplayCase struct {
	Name  string             `json:"name"`
	Input ShadowReplayInput  `json:"input"`
	Want  ShadowReplayResult `json:"want"`
}

func loadShadowReplayCases(t *testing.T) []shadowReplayCase {
	t.Helper()
	data, err := os.ReadFile("testdata/shadow_replay_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cases []shadowReplayCase
	if err := decoder.Decode(&cases); err != nil {
		t.Fatalf("decode fixed shadow replay fixture: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("fixture must contain exactly one JSON value: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("empty shadow replay fixture")
	}
	return cases
}

func cloneShadowReplayInput(input ShadowReplayInput) ShadowReplayInput {
	return ShadowReplayInput{
		Baseline: slices.Clone(input.Baseline), Candidate: slices.Clone(input.Candidate),
		Evidence: slices.Clone(input.Evidence),
	}
}

func TestShadowReplayFixedFixture(t *testing.T) {
	names := make(map[string]bool)
	outcomes := make(map[ShadowReplayOutcome]bool)
	for _, tc := range loadShadowReplayCases(t) {
		if tc.Name == "" || names[tc.Name] {
			t.Fatalf("empty or duplicate fixture name %q", tc.Name)
		}
		names[tc.Name] = true
		outcomes[tc.Want.Outcome] = true
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			before := cloneShadowReplayInput(tc.Input)
			got := EvaluateShadowReplay(tc.Input)
			if !reflect.DeepEqual(got, tc.Want) {
				t.Fatalf("EvaluateShadowReplay() = %#v; want %#v", got, tc.Want)
			}
			if !reflect.DeepEqual(tc.Input, before) {
				t.Fatal("evaluation mutated caller input")
			}
			if got.Outcome == ShadowReplayAbort && len(got.Diffs) != 0 {
				t.Fatal("ABORT exposed a partial diff")
			}
		})
	}
	for _, outcome := range []ShadowReplayOutcome{ShadowReplayPass, ShadowReplayFail, ShadowReplayHold, ShadowReplayAbort} {
		if !outcomes[outcome] {
			t.Errorf("fixed fixture does not cover %s", outcome)
		}
	}
}

func TestShadowReplayOrderIndependentAndRepeatable(t *testing.T) {
	for _, tc := range loadShadowReplayCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			// Reverse each of the three input slices independently, including
			// conflicting duplicates. Neither map iteration nor last-write order
			// may alter the result, and repeated evaluations share no state.
			for mask := 0; mask < 8; mask++ {
				input := cloneShadowReplayInput(tc.Input)
				if mask&1 != 0 {
					slices.Reverse(input.Baseline)
				}
				if mask&2 != 0 {
					slices.Reverse(input.Candidate)
				}
				if mask&4 != 0 {
					slices.Reverse(input.Evidence)
				}
				before := cloneShadowReplayInput(input)
				for repeat := 0; repeat < 5; repeat++ {
					if got := EvaluateShadowReplay(input); !reflect.DeepEqual(got, tc.Want) {
						t.Fatalf("mask=%d repeat=%d: got %#v, want %#v", mask, repeat, got, tc.Want)
					}
				}
				if !reflect.DeepEqual(input, before) {
					t.Fatalf("mask=%d: caller input mutated", mask)
				}
			}
		})
	}
}

func TestShadowReplayDecisionAndEvidenceBoundaries(t *testing.T) {
	assessments := []ShadowAttackAssessment{"", ShadowAttackUnknown, ShadowAttackClear, ShadowAttackDetected, "invalid"}
	for _, before := range []ShadowPolicyDecision{ShadowDeny, ShadowAllow} {
		for _, after := range []ShadowPolicyDecision{ShadowDeny, ShadowAllow} {
			for _, sybil := range assessments {
				for _, forged := range assessments {
					name := string(before) + "_" + string(after) + "_sybil=" + string(sybil) + "_forged=" + string(forged)
					t.Run(name, func(t *testing.T) {
						input := ShadowReplayInput{
							Baseline:  []ShadowReplayRequest{{RequestID: "a", Decision: before}},
							Candidate: []ShadowReplayRequest{{RequestID: "a", Decision: after}},
							Evidence:  []ShadowReplayEvidence{{RequestID: "a", Sybil: sybil, ForgedEvaluator: forged}},
						}
						want := ShadowReplayHold
						switch {
						case sybil == "invalid" || forged == "invalid":
							want = ShadowReplayAbort
						case before == ShadowDeny && after == ShadowAllow,
							sybil == ShadowAttackDetected, forged == ShadowAttackDetected:
							want = ShadowReplayFail
						case sybil == ShadowAttackClear && forged == ShadowAttackClear:
							want = ShadowReplayPass
						}
						got := EvaluateShadowReplay(input)
						if got.Outcome != want || len(got.ReasonCodes) == 0 {
							t.Fatalf("got %#v; want %s with reasons", got, want)
						}
						var wantDiffs []ShadowSemanticDiff
						if before != after && want != ShadowReplayAbort {
							wantDiffs = []ShadowSemanticDiff{{RequestID: "a", Baseline: before, Candidate: after}}
						}
						if !reflect.DeepEqual(got.Diffs, wantDiffs) {
							t.Fatalf("diffs = %#v; want %#v", got.Diffs, wantDiffs)
						}
					})
				}
			}
		}
	}
}

func TestShadowReplayMalformedRequestsFailClosed(t *testing.T) {
	for _, decision := range []ShadowPolicyDecision{"", "allow", "DENY ", "UNKNOWN", "PASS"} {
		for _, id := range []ShadowRequestID{"", " a", "a ", "\t", "a"} {
			for _, side := range []string{"baseline", "candidate"} {
				t.Run(side+"/"+string(id)+"/"+string(decision), func(t *testing.T) {
					input := ShadowReplayInput{
						Baseline:  []ShadowReplayRequest{{RequestID: "a", Decision: ShadowDeny}},
						Candidate: []ShadowReplayRequest{{RequestID: "a", Decision: ShadowDeny}},
						Evidence:  []ShadowReplayEvidence{{RequestID: "a", Sybil: ShadowAttackClear, ForgedEvaluator: ShadowAttackClear}},
					}
					invalid := ShadowReplayRequest{RequestID: id, Decision: decision}
					if side == "baseline" {
						input.Baseline[0] = invalid
					} else {
						input.Candidate[0] = invalid
					}
					got := EvaluateShadowReplay(input)
					if got.Outcome != ShadowReplayAbort || !slices.Contains(got.ReasonCodes, ShadowReasonInvalidRequest) {
						t.Fatalf("malformed request must ABORT: %#v", got)
					}
				})
			}
		}
	}
}

func TestShadowReplayResultsDoNotShareMutableState(t *testing.T) {
	for _, tc := range loadShadowReplayCases(t) {
		result := EvaluateShadowReplay(tc.Input)
		result.ReasonCodes[0] = "tampered"
		if len(result.Diffs) != 0 {
			result.Diffs[0].RequestID = "tampered"
		}
		if got := EvaluateShadowReplay(tc.Input); !reflect.DeepEqual(got, tc.Want) {
			t.Fatalf("%s: modifying prior result affected future evaluation: %#v", tc.Name, got)
		}
	}
}
