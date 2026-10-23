package application

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type deadlineStoreFake struct {
	mu           sync.Mutex
	candidates   []port.RolloutDeadlineCandidate
	err          error
	calls, limit int
}

func (s *deadlineStoreFake) ListRolloutDeadlines(ctx context.Context, limit int) ([]port.RolloutDeadlineCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.limit = limit
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("unbounded listing")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]port.RolloutDeadlineCandidate(nil), s.candidates...), s.err
}
func deadlineHint(f *monitoringTxFake) port.RolloutDeadlineCandidate {
	return port.RolloutDeadlineCandidate{Scope: f.scope.ScopeID, Rollout: f.rollout.ID, Monitoring: f.rollout.Monitoring}
}
func newTestReaper(t *testing.T, f *monitoringTxFake, store *deadlineStoreFake, lkg LKGVerifier) *RolloutDeadlineReaper {
	t.Helper()
	f.requireDeadline = true
	r, err := NewRolloutDeadlineReaper(f, store, lkg, time.Millisecond, time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func putMonitoringDecision(t *testing.T, f *monitoringTxFake, decision domain.MonitoringDecision, at time.Time) {
	t.Helper()
	ro, err := domain.RecordMonitoringDecision(rolloutDomain(f.scope, f.rollout), decision, testDigest(), at)
	if err != nil {
		t.Fatal(err)
	}
	f.rollout.Monitoring = ro.Monitoring
}

func TestRolloutDeadlineReaperObservationFreshnessAndHoldBudget(t *testing.T) {
	for _, scenario := range []string{"no pass", "early pass", "fresh pass", "expired hold", "paused hold", "extended hold expired"} {
		t.Run(scenario, func(t *testing.T) {
			_, f, _ := newMonitoringFixture(t)
			deadline := f.rollout.Monitoring.ObservationDeadline
			f.now = deadline
			switch scenario {
			case "early pass":
				putMonitoringDecision(t, f, domain.DecisionPass, deadline.Add(-time.Second))
			case "fresh pass":
				putMonitoringDecision(t, f, domain.DecisionPass, deadline)
			case "expired hold":
				putMonitoringDecision(t, f, domain.DecisionHold, f.rollout.Monitoring.StartedAt)
				f.now = f.rollout.Monitoring.HoldDeadline.Add(time.Hour)
			case "paused hold":
				putMonitoringDecision(t, f, domain.DecisionHold, deadline.Add(-time.Hour))
			case "extended hold expired":
				// Use the approved Domain snapshot from an actual service extension.
				safetyService, extendedTx, request := newHoldExtendFixture(t)
				if _, err := safetyService.HoldExtend(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				f.rollout = extendedTx.rollout
				f.scope = extendedTx.scope
				f.now = f.rollout.Monitoring.HoldDeadline.Add(time.Hour)
			}
			store := &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{deadlineHint(f)}}
			r := newTestReaper(t, f, store, nil)
			count, err := r.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "paused hold" {
				if count != 0 || f.scope.LiveRolloutID == nil || len(f.events) != 0 {
					t.Fatal("HOLD did not pause observation")
				}
				return
			}
			want := domain.RolloutSafeStopped
			if scenario == "fresh pass" {
				want = domain.RolloutCompleted
			}
			if count != 1 || f.rollout.State != want || f.scope.LiveRolloutID != nil {
				t.Fatal(count, f.rollout, err)
			}
			if scenario != "fresh pass" && f.rollout.Monitoring.Decision != domain.DecisionAbort {
				t.Fatal("expiry did not record ABORT")
			}
			if scenario == "expired hold" && f.rollout.Monitoring.HoldUsed != domain.MonitoringHoldBudget {
				t.Fatal("late processing exceeded HOLD cap")
			}
			if scenario == "extended hold expired" && f.rollout.Monitoring.HoldUsed != domain.MonitoringExtendedCap {
				t.Fatal("extension cap exceeded")
			}
			if len(f.receipts) != 0 {
				t.Fatal("Reaper invented command receipt")
			}
			if again, err := r.Sweep(context.Background()); err != nil || again != 0 {
				t.Fatal("duplicate hint reapplied", again, err)
			}
		})
	}
}

func TestRolloutDeadlineReaperConcurrentFencingAndShortTransactions(t *testing.T) {
	_, f, _ := newMonitoringFixture(t)
	f.now = f.rollout.Monitoring.ObservationDeadline
	hint := deadlineHint(f)
	store := &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{hint, hint}}
	a, b := newTestReaper(t, f, store, nil), newTestReaper(t, f, store, nil)
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, r := range []*RolloutDeadlineReaper{a, b} {
		wg.Add(1)
		go func(r *RolloutDeadlineReaper) {
			defer wg.Done()
			n, err := r.Sweep(context.Background())
			counts <- n
			errs <- err
		}(r)
	}
	wg.Wait()
	close(counts)
	close(errs)
	total := 0
	for n := range counts {
		total += n
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != 1 || len(f.events) != 2 || f.rollout.Monitoring.DecisionRevision != 1 || f.begins != 4 {
		t.Fatal("concurrent/duplicate hints were not fenced", total, f.begins, len(f.events))
	}
}

func TestRolloutDeadlineReaperFencesChangedDecisionAndExtension(t *testing.T) {
	for _, change := range []string{"decision", "extension"} {
		t.Run(change, func(t *testing.T) {
			svc, f, q := newHoldExtendFixture(t)
			hint := deadlineHint(f)
			if change == "decision" {
				putMonitoringDecision(t, f, domain.DecisionHold, f.now)
			} else {
				if _, err := svc.HoldExtend(context.Background(), q); err != nil {
					t.Fatal(err)
				}
			}
			old := f.rollout
			events := len(f.events)
			f.now = hint.Monitoring.HoldDeadline
			r := newTestReaper(t, f, &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{hint}}, nil)
			if n, err := r.Sweep(context.Background()); err != nil || n != 0 || !reflect.DeepEqual(f.rollout, old) || len(f.events) != events {
				t.Fatal("stale hint used", n, err)
			}
		})
	}
}

func TestRolloutDeadlineReaperRollbackUsesVerifiedLKGOrSafeBaseline(t *testing.T) {
	for _, status := range []string{"usable", "invalid", "unavailable", "wrong digest", "verifier error"} {
		t.Run(status, func(t *testing.T) {
			_, f, _ := newMonitoringFixture(t)
			f.now = f.rollout.Monitoring.ObservationDeadline
			calls := 0
			verifier := localLKGFunc(func(ctx context.Context, d domain.Digest) (domain.LKGAssessment, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded verifier")
				}
				a := domain.LKGAssessment{Status: domain.LKGUsable, Digest: d}
				switch status {
				case "invalid":
					a.Status = domain.LKGInvalid
				case "unavailable":
					a.Status = domain.LKGUnavailable
				case "wrong digest":
					a.Digest = testDigest()
				case "verifier error":
					return a, errors.New("unavailable")
				}
				return a, nil
			})
			r := newTestReaper(t, f, &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{deadlineHint(f)}}, verifier)
			n, err := r.Sweep(context.Background())
			want := domain.RolloutSafeStopped
			if status == "usable" {
				want = domain.RolloutRolledBack
			}
			if err != nil || n != 1 || f.rollout.State != want || calls == 0 || f.scope.ActivationEpoch != 43 || f.scope.LiveRolloutID != nil {
				t.Fatal(n, err, f.rollout.State)
			}
		})
	}
}

func TestRolloutDeadlineReaperFailuresAreAtomicAndNotHidden(t *testing.T) {
	for _, operation := range []string{"scope lock", "rollout lock", "roots lock", "DB clock", "scope CAS", "rollout CAS", "MonitoringDecisionRecorded", "MonitoringTerminated", "commit"} {
		t.Run(operation, func(t *testing.T) {
			_, f, _ := newMonitoringFixture(t)
			f.now = f.rollout.Monitoring.ObservationDeadline
			oldScope, oldRollout := f.scope, f.rollout
			f.fail = operation
			if operation == "commit" {
				f.commitErr = f.cause
			}
			r := newTestReaper(t, f, &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{deadlineHint(f)}}, nil)
			if n, err := r.Sweep(context.Background()); n != 0 || !errors.Is(err, f.cause) {
				t.Fatal(n, err)
			}
			if !reflect.DeepEqual(f.scope, oldScope) || !reflect.DeepEqual(f.rollout, oldRollout) || len(f.events) != 0 {
				t.Fatal("partial Reaper exit")
			}
		})
	}
}

func TestRolloutDeadlineReaperBoundsClockAndCancellation(t *testing.T) {
	_, f, _ := newMonitoringFixture(t)
	for _, batch := range []int{0, port.MaxRolloutDeadlineBatch + 1} {
		if _, err := NewRolloutDeadlineReaper(f, &deadlineStoreFake{}, nil, time.Second, time.Second, batch); err == nil {
			t.Fatal("invalid bound accepted")
		}
	}
	for _, scenario := range []string{"overfull", "malformed", "list error", "cancelled", "early DB clock", "unknown commit"} {
		t.Run(scenario, func(t *testing.T) {
			_, f, _ := newMonitoringFixture(t)
			f.now = f.rollout.Monitoring.ObservationDeadline
			hint := deadlineHint(f)
			store := &deadlineStoreFake{candidates: []port.RolloutDeadlineCandidate{hint}}
			r := newTestReaper(t, f, store, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "overfull":
				store.candidates = make([]port.RolloutDeadlineCandidate, 5)
			case "malformed":
				store.candidates[0].Scope = ""
			case "list error":
				store.err = f.cause
			case "cancelled":
				cancel()
			case "early DB clock":
				f.now = f.rollout.Monitoring.StartedAt
			case "unknown commit":
				f.commitErr = errors.Join(port.ErrCommitOutcomeUnknown, f.cause)
			}
			n, err := r.Sweep(ctx)
			if n != 0 {
				t.Fatal("claimed uncommitted exit", n)
			}
			if scenario == "early DB clock" {
				if err != nil || len(f.events) != 0 {
					t.Fatal("local time overrode DB clock", err)
				}
				return
			}
			if err == nil {
				t.Fatal("failure hidden")
			}
			if scenario == "unknown commit" {
				if !errors.Is(err, port.ErrCommitOutcomeUnknown) {
					t.Fatal("lost uncertainty", err)
				}
				f.commitErr = nil
				if n, err := r.Sweep(context.Background()); err != nil || n != 0 || len(f.events) != 2 {
					t.Fatal("unknown commit replay reapplied", n, err)
				}
			} else if f.begins != 0 {
				t.Fatal("invalid listing started transaction")
			}
		})
	}
}

func TestRolloutDeadlineReaperRunCancellationAndFailure(t *testing.T) {
	_, f, _ := newMonitoringFixture(t)
	store := &deadlineStoreFake{}
	r := newTestReaper(t, f, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run ignored cancellation")
	}
	store.err = f.cause
	if err := r.Run(context.Background()); !errors.Is(err, f.cause) {
		t.Fatal("Run swallowed listing error", err)
	}
}
