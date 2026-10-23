package domain

import (
	"math"
	"reflect"
	"testing"
	"time"
)

func TestMonitoringDecisionRevisionOrderingAndOverflow(t *testing.T) {
	_, r, at := monitoringFixture(t)
	if r.Monitoring.DecisionRevision != 0 {
		t.Fatal("initial revision is not zero")
	}
	for want := int64(1); want <= 3; want++ {
		r = recordMonitoring(t, r, DecisionHold, at)
		if r.Monitoring.DecisionRevision != want {
			t.Fatalf("equal-time HOLD revision=%d, want %d", r.Monitoring.DecisionRevision, want)
		}
	}
	r.Monitoring.DecisionRevision = math.MaxInt64 - 1
	r = recordMonitoring(t, r, DecisionHold, at)
	if r.Monitoring.DecisionRevision != math.MaxInt64 {
		t.Fatal("last representable revision rejected")
	}
	if out, err := RecordMonitoringDecision(r, DecisionPass, digestOf('e'), at); err == nil || !reflect.DeepEqual(out, r) {
		t.Fatal("overflow did not fail without mutation", err)
	}
	if out, _, err := EvaluateMonitoring(r, r.Monitoring.HoldDeadline); err == nil || !reflect.DeepEqual(out, r) {
		t.Fatal("expiry revision overflow did not fail closed", err)
	}
	r.Monitoring.DecisionRevision = 3
	out, outcome, err := EvaluateMonitoring(r, r.Monitoring.HoldDeadline)
	if err != nil || outcome != MonitoringSafeRollback || out.Monitoring.DecisionRevision != 4 {
		t.Fatal("expiry ABORT must advance once", outcome, err)
	}
	again, _, err := EvaluateMonitoring(out, out.Monitoring.LastObservedAt)
	if err != nil || again.Monitoring.DecisionRevision != 4 {
		t.Fatal("sticky ABORT advanced twice", err)
	}
	r.Monitoring.DecisionRevision = -1
	if r.Monitoring.Validate() == nil {
		t.Fatal("negative revision accepted")
	}
}

func TestMonitoringDecisionRevisionValidation(t *testing.T) {
	_, initial, at := monitoringFixture(t)
	for _, decision := range []MonitoringDecision{"", DecisionPass, DecisionHold, DecisionFail, DecisionAbort} {
		name := string(decision)
		r := initial
		if decision == "" {
			name = "no decision"
		} else {
			r = recordMonitoring(t, r, decision, at)
			if r.Monitoring.DecisionRevision != 1 {
				t.Fatalf("%s did not advance the initial revision exactly once", decision)
			}
		}
		t.Run(name, func(t *testing.T) {
			for _, revision := range []int64{-1, 0, 1, 2, math.MaxInt64} {
				m := r.Monitoring
				m.DecisionRevision = revision
				wantValid := revision >= 1
				if decision == "" {
					wantValid = revision == 0
				}
				if err := m.Validate(); (err == nil) != wantValid {
					t.Errorf("revision=%d: Validate()=%v, want valid=%t", revision, err, wantValid)
				}
			}
		})
	}
	// Expiry ABORT may legitimately have no evidence, but still needs a revision.
	expired, _, err := EvaluateMonitoring(initial, initial.Monitoring.ObservationDeadline)
	if err != nil || expired.Monitoring.Validate() != nil || expired.Monitoring.DecisionRevision != 1 {
		t.Fatal("invalid expiry ABORT", err)
	}
	expired.Monitoring.DecisionRevision = 0
	if expired.Monitoring.Validate() == nil {
		t.Fatal("expiry ABORT without evidence accepted revision zero")
	}
}

func TestMonitoringHoldExtendPreservesDecisionRevision(t *testing.T) {
	q, ids, keys, _ := safetyFixture(t)
	s, r, at := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, at)
	sigs := signHoldExtend(t, r, ids[:2], keys[:2])
	out, err := q.HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, sigs, at)
	if err != nil || out.Validate() != nil {
		t.Fatal("HOLD_EXTEND failed", err)
	}
	if out.Monitoring.DecisionRevision != r.Monitoring.DecisionRevision {
		t.Fatal("HOLD_EXTEND changed the decision revision")
	}
}

func monitoringFixture(t *testing.T) (AuthorityState, PolicyRollout, time.Time) {
	t.Helper()
	s, r, err := StartCanary(rolloutFixture(), "monitor-1", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}

	s, r, err = Promote(s, r)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 123, time.UTC)
	r, err = StartMonitoring(r, now)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, now
}

func recordMonitoring(t *testing.T, r PolicyRollout, d MonitoringDecision, at time.Time) PolicyRollout {
	t.Helper()
	out, err := RecordMonitoringDecision(r, d, digestOf('e'), at)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMonitoringActiveWindowAndCompletion(t *testing.T) {
	_, initial, start := monitoringFixture(t)
	r := recordMonitoring(t, initial, DecisionPass, start.Add(time.Second))
	for _, tc := range []struct {
		name    string
		at      time.Time
		outcome MonitoringOutcome
		state   RolloutState
	}{
		{"early", start.Add(MonitoringActivePeriod - time.Nanosecond), MonitoringContinue, RolloutMonitoring},
		{"boundary stale pass", start.Add(MonitoringActivePeriod), MonitoringSafeRollback, RolloutMonitoring},
		{"late reaper stale pass", start.Add(MonitoringActivePeriod + time.Hour), MonitoringSafeRollback, RolloutMonitoring},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, result, err := EvaluateMonitoring(r, tc.at)
			if err != nil || result != tc.outcome || out.State != tc.state || out.Validate() != nil {
				t.Fatalf("%s %+v %v", result, out, err)
			}
			if tc.state == RolloutCompleted {
				if _, _, err := EvaluateMonitoring(out, tc.at); err == nil {
					t.Fatal("completed rollout replay accepted")
				}
			}
		})
	}
	if initial.Monitoring.Decision != "" || r.Monitoring.LastObservedAt != start.Add(time.Second) {
		t.Fatal("input mutated")
	}
	// A PASS arriving exactly on or after the observation boundary is fresh;
	// a stale PASS already on the snapshot cannot complete the window.
	for _, at := range []time.Time{start.Add(MonitoringActivePeriod), start.Add(MonitoringActivePeriod + time.Nanosecond)} {
		out := recordMonitoring(t, initial, DecisionPass, at)
		if _, result, err := EvaluateMonitoring(out, at); err != nil || result != MonitoringComplete {
			t.Fatal(result, err)
		}
	}
	if got, err := RecordMonitoringDecision(initial, DecisionPass, digestOf('e'), start.Add(MonitoringActivePeriod+time.Nanosecond)); err != nil {
		t.Fatal("fresh PASS after boundary rejected", err)
	} else if got.Monitoring.DecisionAt != start.Add(MonitoringActivePeriod+time.Nanosecond) {
		t.Fatal("fresh PASS timestamp not recorded")
	}
	if got, err := RecordMonitoringDecision(initial, DecisionHold, digestOf('e'), start.Add(MonitoringActivePeriod+time.Nanosecond)); err != nil || got.Monitoring.Decision != DecisionHold {
		t.Fatal("HOLD after observation boundary rejected", err)
	}
	if got, err := RecordMonitoringDecision(initial, DecisionPass, digestOf('e'), start.Add(MonitoringActivePeriod+time.Nanosecond)); err != nil || !reflect.DeepEqual(got, recordMonitoring(t, initial, DecisionPass, start.Add(MonitoringActivePeriod+time.Nanosecond))) {
		t.Fatal("PASS after boundary was not recorded consistently", err)
	}
	if got, err := RecordMonitoringDecision(initial, DecisionPass, digestOf('e'), start.Add(MonitoringActivePeriod+time.Nanosecond)); err != nil {
		t.Fatal("late PASS rejected", err)
	} else if got.Monitoring.Decision != DecisionPass {
		t.Fatal("late PASS not recorded")
	}
}

func TestMonitoringMultipleHoldsShareBudgetAndPauseExactly(t *testing.T) {
	_, r, start := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, start.Add(24*time.Hour))
	first := r
	// Repeated HOLD evidence must not reset the episode or its deadline.
	r = recordMonitoring(t, r, DecisionHold, start.Add(25*time.Hour))
	if r.Monitoring.HoldSince != first.Monitoring.HoldSince || r.Monitoring.HoldDeadline != first.Monitoring.HoldDeadline {
		t.Fatal("HOLD reset")
	}
	r = recordMonitoring(t, r, DecisionPass, start.Add(30*time.Hour+time.Nanosecond))
	held := 6*time.Hour + time.Nanosecond
	if r.Monitoring.HoldUsed != held || !r.Monitoring.ObservationDeadline.Equal(start.Add(MonitoringActivePeriod+held)) {
		t.Fatal(r.Monitoring)
	}
	r = recordMonitoring(t, r, DecisionHold, start.Add(48*time.Hour))
	if !r.Monitoring.HoldDeadline.Equal(start.Add(48*time.Hour + MonitoringHoldBudget - held)) {
		t.Fatal("budget reset per episode")
	}
	if _, outcome, err := EvaluateMonitoring(r, r.Monitoring.HoldDeadline); err != nil || outcome != MonitoringSafeRollback {
		t.Fatal("expired hold did not abort", outcome, err)
	}
	r = recordMonitoring(t, r, DecisionPass, start.Add(50*time.Hour))
	held += 2 * time.Hour
	if r.Monitoring.HoldUsed != held {
		t.Fatal(r.Monitoring)
	}
	for _, tc := range []struct {
		at   time.Time
		want MonitoringOutcome
	}{
		{start.Add(MonitoringActivePeriod), MonitoringContinue},
		{start.Add(MonitoringActivePeriod + held - time.Nanosecond), MonitoringContinue},
		{start.Add(MonitoringActivePeriod + held), MonitoringSafeRollback},
	} {
		if _, outcome, err := EvaluateMonitoring(r, tc.at); err != nil || outcome != tc.want {
			t.Fatal(outcome, err)
		}
	}
	if first.Monitoring.HoldUsed != 0 || first.Monitoring.Decision != DecisionHold {
		t.Fatal("snapshot mutated")
	}
}

func TestMonitoringFailureAndExpiryAreSafeOnly(t *testing.T) {
	_, initial, start := monitoringFixture(t)
	for _, decision := range []MonitoringDecision{DecisionFail, DecisionAbort} {
		t.Run(string(decision), func(t *testing.T) {
			r := recordMonitoring(t, initial, decision, start.Add(time.Second))
			got, result, err := EvaluateMonitoring(r, start.Add(2*time.Second))
			if err != nil || result != MonitoringSafeRollback || got.State != RolloutMonitoring || got.Monitoring.Decision != decision {
				t.Fatal(result, err)
			}
			if out, err := RecordMonitoringDecision(r, DecisionPass, digestOf('e'), start.Add(3*time.Second)); err == nil || !reflect.DeepEqual(out, r) {
				t.Fatal("terminal decision overwritten")
			}
		})
	}
	for _, late := range []time.Duration{0, time.Nanosecond, 1000 * time.Hour} {
		got, result, err := EvaluateMonitoring(initial, start.Add(MonitoringActivePeriod+late))
		if err != nil || result != MonitoringSafeRollback || got.Monitoring.Decision != DecisionAbort || got.Validate() != nil {
			t.Fatal(result, err)
		}
	}
	hold := recordMonitoring(t, initial, DecisionHold, start.Add(time.Hour))
	deadline := hold.Monitoring.HoldDeadline
	if _, result, err := EvaluateMonitoring(hold, deadline.Add(-time.Nanosecond)); err != nil || result != MonitoringContinue {
		t.Fatal(result, err)
	}
	for _, late := range []time.Duration{0, time.Nanosecond, 1000 * time.Hour} {
		got, result, err := EvaluateMonitoring(hold, deadline.Add(late))
		if err != nil || result != MonitoringSafeRollback || got.Monitoring.Decision != DecisionAbort || got.Monitoring.HoldUsed != MonitoringHoldBudget || got.Validate() != nil {
			t.Fatal(result, got.Monitoring, err)
		}
		if !got.Monitoring.ObservationDeadline.Equal(start.Add(MonitoringActivePeriod + MonitoringHoldBudget)) {
			t.Fatal("late reaper overflowed budget")
		}
	}
	for _, decision := range []MonitoringDecision{DecisionPass, DecisionHold, DecisionFail, DecisionAbort} {
		if got, err := RecordMonitoringDecision(hold, decision, digestOf('e'), deadline); err == nil || !reflect.DeepEqual(got, hold) {
			t.Fatal("expired hold accepted update", decision)
		}
	}
}

func TestMonitoringRejectsInvalidSnapshotsAndClock(t *testing.T) {
	_, initial, start := monitoringFixture(t)
	cases := []struct {
		name   string
		change func(*PolicyRollout)
	}{
		{"unknown state", func(r *PolicyRollout) { r.State = "OTHER" }},
		{"missing monitoring", func(r *PolicyRollout) { r.Monitoring = MonitoringWindow{} }},
		{"unknown decision", func(r *PolicyRollout) { r.Monitoring.Decision = "OTHER" }},
		{"negative used", func(r *PolicyRollout) { r.Monitoring.HoldUsed = -1 }},
		{"cap overflow", func(r *PolicyRollout) { r.Monitoring.HoldUsed = MonitoringExtendedCap + 1 }},
		{"unapproved budget", func(r *PolicyRollout) { r.Monitoring.HoldBudget = MonitoringExtendedCap }},
		{"unbound extension", func(r *PolicyRollout) { r.Monitoring.ExtensionUsed = true }},
		{"deadline tamper", func(r *PolicyRollout) { r.Monitoring.ObservationDeadline = start.Add(time.Hour) }},
		{"stray hold deadline", func(r *PolicyRollout) { r.Monitoring.HoldDeadline = start.Add(time.Hour) }},
		{"stray evidence", func(r *PolicyRollout) { r.Monitoring.EvidenceDigest = digestOf('e') }},
		{"future observation", func(r *PolicyRollout) { r.Monitoring.LastObservedAt = start.Add(2 * time.Hour) }},
		{"premature completed", func(r *PolicyRollout) { r.State = RolloutCompleted }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := initial
			tc.change(&r)
			before := r
			got, err := RecordMonitoringDecision(r, DecisionPass, digestOf('e'), start.Add(time.Hour))
			if err == nil || !reflect.DeepEqual(got, before) || !reflect.DeepEqual(r, before) {
				t.Fatal("invalid update accepted or mutated")
			}
			got, _, err = EvaluateMonitoring(r, start.Add(time.Hour))
			if err == nil || !reflect.DeepEqual(got, before) {
				t.Fatal("invalid evaluation accepted")
			}
		})
	}
	for _, at := range []time.Time{{}, start.Add(-time.Nanosecond), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if got, _, err := EvaluateMonitoring(initial, at); err == nil || !reflect.DeepEqual(got, initial) {
			t.Fatal("invalid clock accepted")
		}
	}
	for _, tc := range []struct {
		d        MonitoringDecision
		evidence Digest
		at       time.Time
	}{
		{"OTHER", digestOf('e'), start.Add(time.Second)},
		{DecisionPass, "bad", start.Add(time.Second)},
	} {
		if got, err := RecordMonitoringDecision(initial, tc.d, tc.evidence, tc.at); err == nil || !reflect.DeepEqual(got, initial) {
			t.Fatal("bad command accepted")
		}
	}
	if got, err := StartMonitoring(initial, start.Add(time.Hour)); err == nil || !reflect.DeepEqual(got, initial) {
		t.Fatal("monitoring reset")
	}
}

func TestMonitoringFailureWhileHeldAccountsTime(t *testing.T) {
	_, r, start := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, start.Add(time.Hour))
	for _, d := range []MonitoringDecision{DecisionFail, DecisionAbort} {
		out := recordMonitoring(t, r, d, start.Add(3*time.Hour))
		if out.Monitoring.HoldUsed != 2*time.Hour || !out.Monitoring.HoldSince.IsZero() {
			t.Fatal(out.Monitoring)
		}
		if _, result, err := EvaluateMonitoring(out, start.Add(3*time.Hour)); err != nil || result != MonitoringSafeRollback {
			t.Fatal(result, err)
		}
	}
}

func TestMonitoringAllowsEqualTimestampAndRejectsBackwardsTime(t *testing.T) {
	_, initial, start := monitoringFixture(t)
	first, err := RecordMonitoringDecision(initial, DecisionPass, digestOf('e'), start)
	if err != nil {
		t.Fatal("first decision at initial observation time rejected:", err)
	}
	second, err := RecordMonitoringDecision(first, DecisionPass, digestOf('f'), start)
	if err != nil {
		t.Fatal("equal-time decision rejected:", err)
	}
	if second.Monitoring.Decision != DecisionPass || second.Monitoring.LastObservedAt != start {
		t.Fatal("equal-time decision did not update state")
	}
	got, err := RecordMonitoringDecision(second, DecisionPass, digestOf('g'), start.Add(-time.Nanosecond))
	if err == nil || !reflect.DeepEqual(got, second) {
		t.Fatal("backwards-time decision accepted or changed input")
	}
}
