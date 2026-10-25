package domain

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const trustPolicyTestWorker WorkerID = "worker_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var trustPolicyEvaluationTime = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func trustPolicyRuleJSON(risk, capability string, q1, q2, q3 uint64, demote string) string {
	return fmt.Sprintf(`{"risk_tier":%q,"capability":%q,"q1_min_independent":%d,"q2_min_independent":%d,"q3_min_independent":%d,"integrity_demote_to":%q}`, risk, capability, q1, q2, q3, demote)
}

func trustPolicyJSON(rules ...string) []byte {
	return []byte(`{"schema_version":"paddock.trust-policy/1","policy_type":"risk_adaptive_threshold_table","rules":[` + strings.Join(rules, ",") + `]}`)
}

func mustTrustPolicy(t *testing.T, rules ...string) TrustPolicy {
	t.Helper()
	policy, err := DecodeTrustPolicy(trustPolicyJSON(rules...))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustTrustProfile(t *testing.T, worker WorkerID, entries ...CapabilityTrustEntry) WorkerCapabilityTrustProfile {
	t.Helper()
	profile, err := NewWorkerCapabilityTrustProfile(worker, entries)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func makeTrustSnapshot(worker WorkerID, risk GovernanceTier, profile WorkerCapabilityTrustProfile, capabilities []string, facts ...TrustCapabilityEvidence) TrustSnapshot {
	return TrustSnapshot{
		WorkerID: worker, RiskTier: risk, CurrentProfile: profile,
		RequestedCapability: append([]string(nil), capabilities...), Evidence: append([]TrustCapabilityEvidence(nil), facts...),
	}
}

func cloneTrustSnapshotForTest(snapshot TrustSnapshot) TrustSnapshot {
	snapshot.CurrentProfile = snapshot.CurrentProfile.clone()
	snapshot.RequestedCapability = append([]string(nil), snapshot.RequestedCapability...)
	snapshot.Evidence = append([]TrustCapabilityEvidence(nil), snapshot.Evidence...)
	return snapshot
}

func cloneTrustPolicyForTest(policy TrustPolicy) TrustPolicy {
	clone := TrustPolicy{rules: make(map[trustPolicyRuleKey]trustPolicyRule, len(policy.rules))}
	for key, rule := range policy.rules {
		clone.rules[key] = rule
	}
	return clone
}

func TestDecodeTrustPolicyAcceptsMaximumJCSSafeThreshold(t *testing.T) {
	policy := mustTrustPolicy(t, trustPolicyRuleJSON("G0", "cpu.probe", 2, 3, maxTrustPolicySafeInteger, "Q0"))
	if err := policy.validate(); err != nil {
		t.Fatalf("max JCS-safe threshold policy invalid: %v", err)
	}
}

func currentTrustFact(capability string, disposition TrustEvidenceDisposition, count uint64) TrustCapabilityEvidence {
	return TrustCapabilityEvidence{
		Capability: capability, Disposition: disposition, IndependentCount: count,
		ObservedAt: trustPolicyEvaluationTime.Add(-time.Minute), ValidUntil: trustPolicyEvaluationTime.Add(time.Minute),
	}
}

func unavailableTrustFact(capability string) TrustCapabilityEvidence {
	return TrustCapabilityEvidence{Capability: capability, Disposition: TrustEvidenceUnavailable}
}

func decisionFor(t *testing.T, result TrustEvaluationResult, capability string) TrustDecision {
	t.Helper()
	for _, decision := range result.Decisions {
		if decision.Capability == capability {
			return decision
		}
	}
	t.Fatalf("decision for %q not found in %+v", capability, result.Decisions)
	return TrustDecision{}
}

func TestDecodeTrustPolicyRejectsUnknownFieldsTypesDuplicatesAndTrailingData(t *testing.T) {
	valid := trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0")
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "unknown schema", data: strings.Replace(string(trustPolicyJSON(valid)), TrustPolicySchemaVersion, "paddock.trust-policy/2", 1)},
		{name: "unknown policy type", data: strings.Replace(string(trustPolicyJSON(valid)), TrustPolicyTypeThresholdTable, "arbitrary_eval", 1)},
		{name: "unknown root field", data: strings.Replace(string(trustPolicyJSON(valid)), `"rules":[`, `"extra":true,"rules":[`, 1)},
		{name: "unknown nested field", data: string(trustPolicyJSON(strings.Replace(valid, `"capability":`, `"extra":true,"capability":`, 1)))},
		{name: "case-variant root field", data: strings.Replace(string(trustPolicyJSON(valid)), `"schema_version":`, `"Schema_version":`, 1)},
		{name: "duplicate root member", data: strings.Replace(string(trustPolicyJSON(valid)), `"policy_type":`, `"policy_type":"risk_adaptive_threshold_table","policy_type":`, 1)},
		{name: "duplicate rule member", data: string(trustPolicyJSON(strings.Replace(valid, `"capability":`, `"capability":"cpu.probe","capability":`, 1)))},
		{name: "trailing value", data: string(trustPolicyJSON(valid)) + ` {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeTrustPolicy([]byte(tc.data)); err == nil {
				t.Fatal("expected strict Trust Policy decode error")
			}
		})
	}
}

func TestDecodeTrustPolicyRejectsEmptyDuplicateAndMalformedRules(t *testing.T) {
	valid := trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0")
	for _, tc := range []struct {
		name  string
		rules []string
	}{
		{name: "empty table"},
		{name: "duplicate risk capability", rules: []string{valid, valid}},
		{name: "unsupported risk", rules: []string{trustPolicyRuleJSON("G4", "cpu.probe", 2, 4, 8, "Q0")}},
		{name: "empty capability", rules: []string{trustPolicyRuleJSON("G0", "", 2, 4, 8, "Q0")}},
		{name: "nontrimmed capability", rules: []string{trustPolicyRuleJSON("G0", " cpu.probe", 2, 4, 8, "Q0")}},
		{name: "q1 below D007 floor", rules: []string{trustPolicyRuleJSON("G0", "cpu.probe", 1, 4, 8, "Q0")}},
		{name: "q1 not less than q2", rules: []string{trustPolicyRuleJSON("G0", "cpu.probe", 4, 4, 8, "Q0")}},
		{name: "q2 not less than q3", rules: []string{trustPolicyRuleJSON("G0", "cpu.probe", 2, 8, 8, "Q0")}},
		{name: "unsafe JCS integer", rules: []string{trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 9007199254740992, "Q0")}},
		{name: "demotion target Q3", rules: []string{trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q3")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeTrustPolicy(trustPolicyJSON(tc.rules...)); err == nil {
				t.Fatal("expected invalid policy error")
			}
		})
	}
}

func TestEvaluateTrustPromotesPerCapabilityAndReplaysDeterministically(t *testing.T) {
	policy := mustTrustPolicy(t,
		trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"),
		trustPolicyRuleJSON("G0", "disk.read", 2, 4, 8, "Q0"),
	)
	profile := mustTrustProfile(t, trustPolicyTestWorker,
		CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ0},
		CapabilityTrustEntry{Capability: "disk.read", Tier: CapabilityTrustQ1},
	)
	cpuEvidence := currentTrustFact("cpu.probe", TrustEvidenceVerified, 4)
	cpuEvidence.ObservedAt = trustPolicyEvaluationTime
	snapshot := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile,
		[]string{"disk.read", "cpu.probe"},
		cpuEvidence,
		currentTrustFact("disk.read", TrustEvidenceVerified, 8),
	)
	first, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical replay differed: first=%+v second=%+v", first, second)
	}
	if len(first.Decisions) != 2 || first.Decisions[0].Capability != "cpu.probe" || first.Decisions[1].Capability != "disk.read" {
		t.Fatalf("decisions not sorted: %+v", first.Decisions)
	}
	cpu := decisionFor(t, first, "cpu.probe")
	if cpu.Action != TrustDecisionPromote || cpu.PreviousTier != CapabilityTrustQ0 || cpu.TargetTier != CapabilityTrustQ2 || cpu.Reason != TrustReasonPromotionThresholdMet {
		t.Fatalf("CPU decision = %+v, want Q0→Q2 PROMOTE", cpu)
	}
	disk := decisionFor(t, first, "disk.read")
	if disk.Action != TrustDecisionPromote || disk.PreviousTier != CapabilityTrustQ1 || disk.TargetTier != CapabilityTrustQ3 {
		t.Fatalf("disk decision = %+v, want Q1→Q3 PROMOTE", disk)
	}
}

func TestEvaluateTrustInsufficientCasesPreserveCurrentTier(t *testing.T) {
	policy := mustTrustPolicy(t, trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"))
	profile := mustTrustProfile(t, trustPolicyTestWorker,
		CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ2},
		CapabilityTrustEntry{Capability: "disk.read", Tier: CapabilityTrustQ2},
	)
	stale := currentTrustFact("cpu.probe", TrustEvidenceVerified, 8)
	stale.ValidUntil = trustPolicyEvaluationTime
	future := currentTrustFact("cpu.probe", TrustEvidenceVerified, 8)
	future.ObservedAt = trustPolicyEvaluationTime.Add(time.Second)
	future.ValidUntil = trustPolicyEvaluationTime.Add(2 * time.Second)
	cases := []struct {
		name     string
		snapshot TrustSnapshot
		want     TrustDecisionReason
	}{
		{name: "missing policy rule", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"disk.read"}), want: TrustReasonNoPolicyRule},
		{name: "missing evidence fact", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}), want: TrustReasonEvidenceMissing},
		{name: "unavailable evidence", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, unavailableTrustFact("cpu.probe")), want: TrustReasonEvidenceUnavailable},
		{name: "stale evidence", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, stale), want: TrustReasonEvidenceNotCurrent},
		{name: "future evidence", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, future), want: TrustReasonEvidenceNotCurrent},
		{name: "zero independent count", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, currentTrustFact("cpu.probe", TrustEvidenceVerified, 0)), want: TrustReasonBelowQ1Threshold},
		{name: "below q1", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, currentTrustFact("cpu.probe", TrustEvidenceVerified, 1)), want: TrustReasonBelowQ1Threshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := EvaluateTrust(tc.snapshot, policy, trustPolicyEvaluationTime)
			if err != nil {
				t.Fatal(err)
			}
			decision := decisionFor(t, result, tc.snapshot.RequestedCapability[0])
			if decision.Action != TrustDecisionInsufficient || decision.PreviousTier != CapabilityTrustQ2 || decision.TargetTier != CapabilityTrustQ2 || decision.Reason != tc.want {
				t.Fatalf("decision = %+v, want INSUFFICIENT/preserve Q2/reason %s", decision, tc.want)
			}
		})
	}
}

func TestEvaluateTrustAcceptsFullUint64EvidenceCounts(t *testing.T) {
	policy := mustTrustPolicy(t,
		trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"),
		trustPolicyRuleJSON("G0", "disk.read", 2, 4, 8, "Q0"),
	)
	profile := mustTrustProfile(t, trustPolicyTestWorker,
		CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ0},
		CapabilityTrustEntry{Capability: "disk.read", Tier: CapabilityTrustQ2},
	)
	snapshot := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile,
		[]string{"cpu.probe", "disk.read"},
		currentTrustFact("cpu.probe", TrustEvidenceVerified, ^uint64(0)),
		currentTrustFact("disk.read", TrustEvidenceIntegrityViolation, ^uint64(0)),
	)
	result, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if got := decisionFor(t, result, "cpu.probe"); got.Action != TrustDecisionPromote || got.TargetTier != CapabilityTrustQ3 {
		t.Fatalf("max uint64 verified count = %+v, want promotion to Q3", got)
	}
	if got := decisionFor(t, result, "disk.read"); got.Action != TrustDecisionDemote || got.TargetTier != CapabilityTrustQ0 {
		t.Fatalf("max uint64 Integrity count = %+v, want demotion to Q0", got)
	}
}

func TestEvaluateTrustSupportsEveryGovernanceRiskTier(t *testing.T) {
	rules := make([]string, 0, 4)
	for _, risk := range []string{"G0", "G1", "G2", "G3"} {
		rules = append(rules, trustPolicyRuleJSON(risk, "cpu.probe", 2, 4, 8, "Q0"))
	}
	policy := mustTrustPolicy(t, rules...)
	profile := mustTrustProfile(t, trustPolicyTestWorker, CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ0})
	for _, risk := range []GovernanceTier{TierG0, TierG1, TierG2, TierG3} {
		snapshot := makeTrustSnapshot(trustPolicyTestWorker, risk, profile, []string{"cpu.probe"}, currentTrustFact("cpu.probe", TrustEvidenceVerified, 2))
		result, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime)
		if err != nil {
			t.Fatalf("risk %s: %v", risk, err)
		}
		if got := decisionFor(t, result, "cpu.probe"); got.Action != TrustDecisionPromote || got.TargetTier != CapabilityTrustQ1 {
			t.Fatalf("risk %s decision = %+v, want Q0→Q1 PROMOTE", risk, got)
		}
	}
}

func TestEvaluateTrustIntegrityGateAndTargetAreCapabilityScoped(t *testing.T) {
	policy := mustTrustPolicy(t,
		trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"),
		trustPolicyRuleJSON("G0", "disk.read", 2, 4, 8, "Q0"),
	)
	profile := mustTrustProfile(t, trustPolicyTestWorker,
		CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ2},
		CapabilityTrustEntry{Capability: "disk.read", Tier: CapabilityTrustQ0},
	)
	integrity := currentTrustFact("cpu.probe", TrustEvidenceIntegrityViolation, 2)
	verified := currentTrustFact("disk.read", TrustEvidenceVerified, 2)
	snapshot := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"disk.read", "cpu.probe"}, integrity, verified)
	result, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	cpu := decisionFor(t, result, "cpu.probe")
	if cpu.Action != TrustDecisionDemote || cpu.TargetTier != CapabilityTrustQ0 || cpu.Reason != TrustReasonIntegrityDemotion {
		t.Fatalf("Integrity decision = %+v, want only CPU Q2→Q0 DEMOTE", cpu)
	}
	disk := decisionFor(t, result, "disk.read")
	if disk.Action != TrustDecisionPromote || disk.TargetTier != CapabilityTrustQ1 {
		t.Fatalf("disk decision = %+v, want independent Q0→Q1 PROMOTE", disk)
	}

	below := currentTrustFact("cpu.probe", TrustEvidenceIntegrityViolation, 1)
	belowResult, err := EvaluateTrust(makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, below), policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	decision := decisionFor(t, belowResult, "cpu.probe")
	if decision.Action != TrustDecisionInsufficient || decision.TargetTier != CapabilityTrustQ2 || decision.Reason != TrustReasonIntegrityCountBelowQ1 {
		t.Fatalf("below-q1 Integrity decision = %+v", decision)
	}
	zero := currentTrustFact("cpu.probe", TrustEvidenceIntegrityViolation, 0)
	zeroResult, err := EvaluateTrust(makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, zero), policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	zeroDecision := decisionFor(t, zeroResult, "cpu.probe")
	if zeroDecision.Action != TrustDecisionInsufficient || zeroDecision.TargetTier != CapabilityTrustQ2 || zeroDecision.Reason != TrustReasonIntegrityCountBelowQ1 {
		t.Fatalf("zero-count Integrity decision = %+v", zeroDecision)
	}
}

func TestEvaluateTrustRetainsWhenIntegrityTargetIsNotLower(t *testing.T) {
	policy := mustTrustPolicy(t, trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q2"))
	profile := mustTrustProfile(t, trustPolicyTestWorker, CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ1})
	fact := currentTrustFact("cpu.probe", TrustEvidenceIntegrityViolation, 2)
	result, err := EvaluateTrust(makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, fact), policy, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	got := decisionFor(t, result, "cpu.probe")
	if got.Action != TrustDecisionRetain || got.TargetTier != CapabilityTrustQ1 || got.Reason != TrustReasonIntegrityTargetNotLower {
		t.Fatalf("Integrity target above current = %+v, want RETAIN current Q1", got)
	}
}

func TestDecodeTrustPolicyJCSObjectOrderIsIrrelevant(t *testing.T) {
	first := trustPolicyJSON(trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"))
	second := []byte(`{"rules":[{"integrity_demote_to":"Q0","q3_min_independent":8,"q2_min_independent":4,"q1_min_independent":2,"capability":"cpu.probe","risk_tier":"G0"}],"policy_type":"risk_adaptive_threshold_table","schema_version":"paddock.trust-policy/1"}`)
	p1, err := DecodeTrustPolicy(first)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := DecodeTrustPolicy(second)
	if err != nil {
		t.Fatal(err)
	}
	profile := mustTrustProfile(t, trustPolicyTestWorker)
	snapshot := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, currentTrustFact("cpu.probe", TrustEvidenceVerified, 4))
	r1, err := EvaluateTrust(snapshot, p1, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := EvaluateTrust(snapshot, p2, trustPolicyEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("JSON field order changed result: %#v != %#v", r1, r2)
	}
}

func TestEvaluateTrustRejectsMalformedPolicyAndSnapshot(t *testing.T) {
	validRule := trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0")
	invalidPolicies := [][]byte{
		trustPolicyJSON(),
		[]byte(strings.Replace(string(trustPolicyJSON(validRule)), TrustPolicySchemaVersion, "paddock.trust-policy/2", 1)),
		[]byte(strings.Replace(string(trustPolicyJSON(validRule)), TrustPolicyTypeThresholdTable, "unknown", 1)),
		[]byte(strings.Replace(string(trustPolicyJSON(validRule)), `"policy_type":`, `"unknown":true,"policy_type":`, 1)),
		[]byte(strings.Replace(string(trustPolicyJSON(validRule)), `"policy_type":`, `"policy_type":"risk_adaptive_threshold_table","policy_type":`, 1)),
	}
	for i, raw := range invalidPolicies {
		if _, err := DecodeTrustPolicy(raw); err == nil {
			t.Errorf("invalid policy %d unexpectedly decoded", i)
		}
	}
	policy := mustTrustPolicy(t, validRule)
	profile := mustTrustProfile(t, trustPolicyTestWorker)
	validFact := currentTrustFact("cpu.probe", TrustEvidenceVerified, 2)
	invalidSnapshots := []struct {
		name     string
		snapshot TrustSnapshot
		at       time.Time
	}{
		{name: "worker profile mismatch", snapshot: makeTrustSnapshot("worker_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TierG0, profile, []string{"cpu.probe"}, validFact), at: trustPolicyEvaluationTime},
		{name: "risk outside G0-G3", snapshot: makeTrustSnapshot(trustPolicyTestWorker, "G4", profile, []string{"cpu.probe"}, validFact), at: trustPolicyEvaluationTime},
		{name: "duplicate requested capability", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe", "cpu.probe"}, validFact), at: trustPolicyEvaluationTime},
		{name: "duplicate fact", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, validFact, validFact), at: trustPolicyEvaluationTime},
		{name: "fact for unrequested capability", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, validFact, currentTrustFact("disk.read", TrustEvidenceVerified, 2)), at: trustPolicyEvaluationTime},
		{name: "unknown evidence disposition", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, TrustCapabilityEvidence{Capability: "cpu.probe", Disposition: "UNKNOWN"}), at: trustPolicyEvaluationTime},
		{name: "zero evaluation time", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, validFact), at: time.Time{}},
		{name: "invalid evidence interval", snapshot: makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, func() TrustCapabilityEvidence {
			f := currentTrustFact("cpu.probe", TrustEvidenceVerified, 2)
			f.ValidUntil = f.ObservedAt
			return f
		}()), at: trustPolicyEvaluationTime},
	}
	for _, tc := range invalidSnapshots {
		t.Run(tc.name, func(t *testing.T) {
			result, err := EvaluateTrust(tc.snapshot, policy, tc.at)
			if !errors.Is(err, ErrTrustPolicy) {
				t.Fatalf("EvaluateTrust error=%v, want ErrTrustPolicy", err)
			}
			if !reflect.DeepEqual(result, TrustEvaluationResult{}) {
				t.Fatalf("invalid input returned partial decisions: %+v", result)
			}
		})
	}
	unavailableWithTimes := currentTrustFact("cpu.probe", TrustEvidenceUnavailable, 0)
	badUnavailable := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, unavailableWithTimes)
	result, err := EvaluateTrust(badUnavailable, policy, trustPolicyEvaluationTime)
	if !errors.Is(err, ErrTrustPolicy) {
		t.Fatalf("unavailable fact with timestamps error=%v, want ErrTrustPolicy", err)
	}
	if !reflect.DeepEqual(result, TrustEvaluationResult{}) {
		t.Fatalf("unavailable fact with timestamps returned partial result: %+v", result)
	}
	unavailableWithCount := TrustCapabilityEvidence{Capability: "cpu.probe", Disposition: TrustEvidenceUnavailable, IndependentCount: 1}
	badUnavailable = makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile, []string{"cpu.probe"}, unavailableWithCount)
	result, err = EvaluateTrust(badUnavailable, policy, trustPolicyEvaluationTime)
	if !errors.Is(err, ErrTrustPolicy) {
		t.Fatalf("unavailable fact with count error=%v, want ErrTrustPolicy", err)
	}
	if !reflect.DeepEqual(result, TrustEvaluationResult{}) {
		t.Fatalf("unavailable fact with count returned partial result: %+v", result)
	}
}

func TestEvaluateTrustDoesNotMutateSnapshotProfileOrPolicy(t *testing.T) {
	policy := mustTrustPolicy(t,
		trustPolicyRuleJSON("G0", "cpu.probe", 2, 4, 8, "Q0"),
		trustPolicyRuleJSON("G0", "disk.read", 2, 4, 8, "Q0"),
	)
	profile := mustTrustProfile(t, trustPolicyTestWorker,
		CapabilityTrustEntry{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
		CapabilityTrustEntry{Capability: "disk.read", Tier: CapabilityTrustQ2},
	)
	snapshot := makeTrustSnapshot(trustPolicyTestWorker, TierG0, profile,
		[]string{"disk.read", "cpu.probe"},
		currentTrustFact("cpu.probe", TrustEvidenceVerified, 4),
		currentTrustFact("disk.read", TrustEvidenceVerified, 8),
	)
	snapshotBefore := cloneTrustSnapshotForTest(snapshot)
	profileBefore := profile.clone()
	policyBefore := cloneTrustPolicyForTest(policy)
	if _, err := EvaluateTrust(snapshot, policy, trustPolicyEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot, snapshotBefore) {
		t.Fatalf("EvaluateTrust mutated snapshot: before=%#v after=%#v", snapshotBefore, snapshot)
	}
	if !reflect.DeepEqual(profile, profileBefore) {
		t.Fatal("EvaluateTrust mutated caller profile")
	}
	if !reflect.DeepEqual(policy, policyBefore) {
		t.Fatal("EvaluateTrust mutated caller policy")
	}

	invalid := cloneTrustSnapshotForTest(snapshot)
	invalid.RiskTier = "G4"
	invalidBefore := cloneTrustSnapshotForTest(invalid)
	result, err := EvaluateTrust(invalid, policy, trustPolicyEvaluationTime)
	if !errors.Is(err, ErrTrustPolicy) || !reflect.DeepEqual(result, TrustEvaluationResult{}) {
		t.Fatalf("invalid input result = (%+v,%v), want zero result and ErrTrustPolicy", result, err)
	}
	if !reflect.DeepEqual(invalid, invalidBefore) {
		t.Fatal("EvaluateTrust mutated invalid input while rejecting it")
	}
}
