package application

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// Transactional in-memory model only, not evidence of PostgreSQL behavior.
// Serialize callbacks to model locked rows; restore all durable state on failure.
type monitoringTxFake struct {
	*rolloutTxFake
	mu              sync.Mutex
	now             time.Time
	fail            string
	cause           error
	commitErr       error
	log             []string
	requireDeadline bool
}

func (f *monitoringTxFake) WithinRolloutTransaction(ctx context.Context, fn func(port.RolloutTx) error) error {
	return f.WithinTransaction(ctx, func(port.GovernanceTx) error { return fn(f) })
}

func (f *monitoringTxFake) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requireDeadline {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("unbounded transaction")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oldScope, oldRollout := f.scope, f.rollout
	oldEvents := append([]domain.Event(nil), f.events...)
	oldReceipts := make(map[string]port.CommandReceipt, len(f.receipts))
	for k, v := range f.receipts {
		oldReceipts[k] = v
	}
	f.begins++
	err := fn(f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil && !errors.Is(err, port.ErrCommitOutcomeUnknown) {
		f.scope, f.rollout, f.events, f.receipts = oldScope, oldRollout, oldEvents, oldReceipts
	} else {
		f.commits++
	}
	return err
}
func (f *monitoringTxFake) operation(name string) error {
	f.log = append(f.log, name)
	if f.fail == name {
		return f.cause
	}
	return nil
}
func (f *monitoringTxFake) LockScope(ctx context.Context, id domain.ScopeID) (port.ScopeSnapshot, error) {
	if err := f.operation("scope lock"); err != nil {
		return port.ScopeSnapshot{}, err
	}
	return f.rolloutTxFake.LockScope(ctx, id)
}
func (f *monitoringTxFake) LockRollout(ctx context.Context, scope domain.ScopeID, id domain.RolloutID) (port.RolloutSnapshot, error) {
	if err := f.operation("rollout lock"); err != nil {
		return port.RolloutSnapshot{}, err
	}
	return f.rolloutTxFake.LockRollout(ctx, scope, id)
}
func (f *monitoringTxFake) ValidateTargets(ctx context.Context, scope domain.ScopeID, ids []domain.RootID) error {
	if err := f.operation("roots lock"); err != nil {
		return err
	}
	return f.rolloutTxFake.ValidateTargets(ctx, scope, ids)
}
func (f *monitoringTxFake) DatabaseTime(context.Context) (time.Time, error) {
	if err := f.operation("DB clock"); err != nil {
		return time.Time{}, err
	}
	return f.now, nil
}
func (f *monitoringTxFake) CompareAndSwapScope(ctx context.Context, old, next port.ScopeSnapshot) error {
	if err := f.operation("scope CAS"); err != nil {
		return err
	}
	return f.rolloutTxFake.CompareAndSwapScope(ctx, old, next)
}
func (f *monitoringTxFake) CompareAndSwapRollout(ctx context.Context, old, next port.RolloutSnapshot) error {
	if err := f.operation("rollout CAS"); err != nil {
		return err
	}
	return f.rolloutTxFake.CompareAndSwapRollout(ctx, old, next)
}
func (f *monitoringTxFake) AppendEvent(ctx context.Context, event domain.Event) error {
	if err := f.operation(event.Type()); err != nil {
		return err
	}
	return f.rolloutTxFake.AppendEvent(ctx, event)
}
func (f *monitoringTxFake) InsertCommandReceipt(ctx context.Context, receipt port.CommandReceipt) error {
	if err := f.operation("receipt"); err != nil {
		return err
	}
	return f.rolloutTxFake.InsertCommandReceipt(ctx, receipt)
}

func newMonitoringFixture(t *testing.T) (*MonitoringService, *monitoringTxFake, MonitoringDecisionRequest) {
	t.Helper()
	base := newRolloutFixture(t)
	if _, err := base.promote(); err != nil {
		t.Fatal(err)
	}
	base.tx.events, base.tx.receipts, base.tx.writes = nil, nil, nil
	base.tx.begins, base.tx.commits = 0, 0
	f := &monitoringTxFake{rolloutTxFake: base.tx, now: base.tx.rollout.Monitoring.StartedAt, cause: errors.New("injected failure")}
	q := MonitoringDecisionRequest{CommandID: "decision", Nonce: "nonce", Scope: f.scope.ScopeID, Rollout: f.rollout.ID, ExpectedScopeEpoch: f.scope.ActivationEpoch, ExpectedSecurityEpoch: f.scope.SecurityEpoch, Gate: domain.CanaryGateInput{RequiredChecks: []domain.CanaryCheckID{"health"}, Checks: []domain.CanaryCheck{{ID: "health", State: domain.CanaryCheckPass}}}}
	return NewMonitoringService(f, nil), f, q
}

func TestMonitoringDecisionEqualClockReplayAndImmutableEvidence(t *testing.T) {
	svc, f, q := newMonitoringFixture(t)
	q.Gate.Checks = nil // validated Gate result HOLD
	first, err := svc.RecordDecision(context.Background(), q)
	if err != nil || first.Monitoring.DecisionRevision != 1 || first.Monitoring.Decision != domain.DecisionHold || len(f.events) != 1 {
		t.Fatal(first, err)
	}
	if first.Monitoring.EvidenceDigest.Validate() != nil {
		t.Fatal("invalid canonical evidence")
	}
	if got := strings.Join(f.log[:4], ","); got != "scope lock,rollout lock,roots lock,DB clock" {
		t.Fatal("lock/clock order", got)
	}
	payload := f.events[0].Payload()
	replay, err := svc.RecordDecision(context.Background(), q)
	if err != nil || !reflect.DeepEqual(replay, first) || len(f.events) != 1 {
		t.Fatal("replay reapplied", err)
	}
	changed := q
	changed.Nonce = "different"
	if _, err := svc.RecordDecision(context.Background(), changed); err == nil || CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
		t.Fatal("conflict not fenced", err)
	}
	q.CommandID, q.ExpectedDecisionRevision = "decision-2", 1
	second, err := svc.RecordDecision(context.Background(), q)
	if err != nil || second.Monitoring.DecisionRevision != 2 || second.Monitoring.DecisionAt != first.Monitoring.DecisionAt || len(f.events) != 2 {
		t.Fatal("equal clock record", second, err)
	}
	if !reflect.DeepEqual(payload, f.events[0].Payload()) || f.events[1].AggregateVersion() != 2 {
		t.Fatal("decision history was changed or reused")
	}
	r := f.receipts[q.CommandID]
	r.Expired = true
	f.receipts[q.CommandID] = r
	if _, err = svc.RecordDecision(context.Background(), q); !errors.Is(err, port.ErrReceiptExpired) || len(f.events) != 2 {
		t.Fatal("expired replay reapplied", err)
	}
}

func TestMonitoringGateEvidenceCanonicalAndOrderIndependent(t *testing.T) {
	a := domain.CanaryGateInput{RequiredChecks: []domain.CanaryCheckID{"b", "a"}, Checks: []domain.CanaryCheck{{ID: "b", State: domain.CanaryCheckPass}, {ID: "a", State: domain.CanaryCheckUnknown}}}
	before := append([]domain.CanaryCheck(nil), a.Checks...)
	b := domain.CanaryGateInput{RequiredChecks: []domain.CanaryCheckID{"a", "b"}, Checks: []domain.CanaryCheck{a.Checks[1], a.Checks[0]}}
	da, err := canonicalGateEvidence(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := canonicalGateEvidence(b)
	if err != nil || da != db || !reflect.DeepEqual(a.Checks, before) {
		t.Fatal("canonical evidence changed with order/mutated input", err)
	}
	b.Checks[0].State = domain.CanaryCheckFail
	dc, _ := canonicalGateEvidence(b)
	if dc == da {
		t.Fatal("evidence ignored changed assertion")
	}
}

func TestMonitoringDecisionBoundariesAndSafeOnlyExits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   domain.CanaryCheckState
		at      time.Duration
		want    domain.RolloutState
		outcome domain.MonitoringOutcome
	}{
		{"early pass", domain.CanaryCheckPass, time.Second, domain.RolloutMonitoring, domain.MonitoringContinue},
		{"fresh boundary pass", domain.CanaryCheckPass, domain.MonitoringActivePeriod, domain.RolloutCompleted, domain.MonitoringComplete},
		{"fresh late pass", domain.CanaryCheckPass, domain.MonitoringActivePeriod + time.Second, domain.RolloutCompleted, domain.MonitoringComplete},
		{"fail", domain.CanaryCheckFail, time.Second, domain.RolloutSafeStopped, domain.MonitoringSafeRollback},
		{"invalid gate abort", domain.CanaryCheckState("invalid"), time.Second, domain.RolloutSafeStopped, domain.MonitoringSafeRollback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, f, q := newMonitoringFixture(t)
			f.now = f.now.Add(tc.at)
			q.Gate.Checks[0].State = tc.state
			out, err := svc.RecordDecision(context.Background(), q)
			if err != nil || out.State != tc.want || out.Outcome != tc.outcome || out.Monitoring.DecisionRevision != 1 {
				t.Fatal(out, err)
			}
			if tc.outcome != domain.MonitoringContinue {
				if f.scope.LiveRolloutID != nil || len(f.events) != 2 || len(f.receipts) != 1 {
					t.Fatal("exit not atomic")
				}
			} else if f.scope.LiveRolloutID == nil {
				t.Fatal("early pass released slot")
			}
			if tc.want == domain.RolloutSafeStopped {
				for _, r := range f.scope.Roots {
					if !r.Policy.SafeBaseline {
						t.Fatal("unsafe exit")
					}
				}
			}
		})
	}
}

func TestMonitoringExpiredHoldCannotBeRevived(t *testing.T) {
	svc, f, q := newMonitoringFixture(t)
	q.Gate.Checks = nil
	if _, err := svc.RecordDecision(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	f.now = f.rollout.Monitoring.HoldDeadline
	q.CommandID = "late-pass"
	q.ExpectedDecisionRevision = 1
	q.Gate.Checks = []domain.CanaryCheck{{ID: "health", State: domain.CanaryCheckPass}}
	out, err := svc.RecordDecision(context.Background(), q)
	if err != nil || out.State != domain.RolloutSafeStopped || out.Monitoring.Decision != domain.DecisionAbort || out.Monitoring.DecisionRevision != 2 {
		t.Fatal(out, err)
	}
}

func TestMonitoringFailuresRollBackDecisionReceiptAndExit(t *testing.T) {
	for _, operation := range []string{"scope lock", "rollout lock", "roots lock", "DB clock", "scope CAS", "rollout CAS", "MonitoringDecisionRecorded", "MonitoringTerminated", "receipt", "commit"} {
		t.Run(operation, func(t *testing.T) {
			svc, f, q := newMonitoringFixture(t)
			q.Gate.Checks[0].State = domain.CanaryCheckFail
			oldScope, oldRollout := f.scope, f.rollout
			f.fail = operation
			if operation == "commit" {
				f.commitErr = f.cause
			}
			if _, err := svc.RecordDecision(context.Background(), q); !errors.Is(err, f.cause) {
				t.Fatal("cause lost", err)
			}
			if !reflect.DeepEqual(f.scope, oldScope) || !reflect.DeepEqual(f.rollout, oldRollout) || len(f.receipts) != 0 || len(f.events) != 0 {
				t.Fatal("partial durable change")
			}
		})
	}
}

func TestMonitoringStaleMalformedAndOverflowDoNotWrite(t *testing.T) {
	for _, change := range []string{"revision", "scope epoch", "security epoch", "roots", "overflow", "clock backwards", "zero DB clock"} {
		t.Run(change, func(t *testing.T) {
			svc, f, q := newMonitoringFixture(t)
			switch change {
			case "revision":
				q.ExpectedDecisionRevision = 1
			case "scope epoch":
				q.ExpectedScopeEpoch++
			case "security epoch":
				q.ExpectedSecurityEpoch++
			case "roots":
				delete(f.scope.Roots, "root-a")
			case "overflow":
				ro, err := domain.RecordMonitoringDecision(rolloutDomain(f.scope, f.rollout), domain.DecisionHold, testDigest(), f.now)
				if err != nil {
					t.Fatal(err)
				}
				f.rollout.Monitoring = ro.Monitoring
				f.rollout.Monitoring.DecisionRevision = math.MaxInt64
				q.ExpectedDecisionRevision = math.MaxInt64
			case "clock backwards":
				f.now = f.now.Add(-time.Second)
			case "zero DB clock":
				f.now = time.Time{}
			}
			if _, err := svc.RecordDecision(context.Background(), q); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if len(f.events) != 0 || len(f.receipts) != 0 || len(f.writes) != 0 {
				t.Fatal("failure wrote state")
			}
		})
	}
}

func TestMonitoringUnknownCommitReconcilesWithoutIncrement(t *testing.T) {
	svc, f, q := newMonitoringFixture(t)
	f.commitErr = errors.Join(port.ErrCommitOutcomeUnknown, f.cause)
	if _, err := svc.RecordDecision(context.Background(), q); !errors.Is(err, port.ErrCommitOutcomeUnknown) {
		t.Fatal(err)
	}
	f.commitErr = nil
	out, err := svc.RecordDecision(context.Background(), q)
	if err != nil || out.Monitoring.DecisionRevision != 1 || len(f.events) != 1 {
		t.Fatal("unknown commit retried mutation", out, err)
	}
}

func TestMonitoringEventCompositeIdentityIsUnambiguous(t *testing.T) {
	f := &eventCaptureTx{}
	for _, result := range []MonitoringResult{{Scope: "a/b", Rollout: "c"}, {Scope: "a", Rollout: "b/c"}} {
		if err := appendMonitoringEvent(context.Background(), f, result, "rollout-decision", "MonitoringDecisionRecorded", 1); err != nil {
			t.Fatal(err)
		}
	}
	if f.events[0].ID() == f.events[1].ID() || f.events[0].AggregateID() == f.events[1].AggregateID() {
		t.Fatal("distinct composite IDs collided")
	}
}

func TestMonitoringNilAndCancelled(t *testing.T) {
	var nilService *MonitoringService
	if _, err := nilService.RecordDecision(context.Background(), MonitoringDecisionRequest{}); err == nil {
		t.Fatal("nil service accepted")
	}
	svc, f, q := newMonitoringFixture(t)
	if _, err := svc.RecordDecision(nil, q); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.RecordDecision(ctx, q); !errors.Is(err, context.Canceled) || f.begins != 0 {
		t.Fatal("cancel ignored", err)
	}
}
