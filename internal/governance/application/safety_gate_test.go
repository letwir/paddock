package application

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type gateTransactor struct {
	snapshot      port.ScopeSnapshot
	lockErr       error
	calls         int
	leaseErr      error
	leaseCalls    int
	inTransaction bool
	order         []string
	binding       domain.AttemptLeaseBinding
}

func TestSafetyGateRequiresFreshLeaseInAuthorityTransaction(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f)
	authorization := gateAuthorization(gateGrant(f.snapshot))
	if err := gate.CheckHighRiskAction(context.Background(), "scope", authorization); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || f.leaseCalls != 1 || f.binding != authorization.Lease || !reflect.DeepEqual(f.order, []string{"authority", "lease"}) {
		t.Fatalf("not composed in order: %+v", f)
	}
	// The same Gate must consult the lease again, not cache the previous success.
	for _, denial := range []error{domain.ErrInvalidLease, domain.ErrDatabaseUnavailable} {
		f.leaseErr = denial
		if err := gate.CheckHighRiskAction(context.Background(), "scope", authorization); !errors.Is(err, denial) {
			t.Fatalf("fresh lease denial: %v", err)
		}
	}
	if f.calls != 3 || f.leaseCalls != 3 {
		t.Fatal("lease validation was cached")
	}
}

func TestSafetyGateRejectsMissingBindingAndStaleGrantBeforeLeaseCheck(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f)
	auth := gateAuthorization(gateGrant(f.snapshot))
	missing := auth
	missing.Lease = domain.AttemptLeaseBinding{}
	if err := gate.CheckHighRiskAction(context.Background(), "scope", missing); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatal(err)
	}
	f.snapshot.Roots["root-a"] = domain.RootAuthority{Policy: auth.Grant.Policy, AuthorizationEpoch: 4}
	if err := gate.CheckHighRiskAction(context.Background(), "scope", auth); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatal(err)
	}
	if f.leaseCalls != 0 {
		t.Fatal("invalid authorization reached lease check")
	}
}

func TestSafetyGateRollbackEpochBoundaryWithActiveLease(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	f.snapshot.ActivationEpoch = 42
	before := gateAuthorization(gateGrant(f.snapshot))
	// Same v1 digest, but a newer Root epoch after one-transaction Rollback.
	f.snapshot.ActivationEpoch = 43
	root := f.snapshot.Roots["root-a"]
	root.AuthorizationEpoch++
	f.snapshot.Roots["root-a"] = root
	gate := NewSafetyGate(f)
	if err := gate.CheckHighRiskAction(context.Background(), "scope", before); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatal(err)
	}
	current := gateAuthorization(gateGrant(f.snapshot))
	if err := gate.CheckHighRiskAction(context.Background(), "scope", current); err != nil {
		t.Fatal(err)
	}
	f.leaseErr = domain.ErrInvalidLease
	if err := gate.CheckHighRiskAction(context.Background(), "scope", current); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatal(err)
	}
	if f.snapshot.SecurityEpoch != 7 {
		t.Fatal("Rollback advanced Security Epoch")
	}
}

func (f *gateTransactor) WithinSafetyGateTransaction(ctx context.Context, fn func(port.SafetyGateTx) error) error {
	f.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	f.inTransaction = true
	defer func() { f.inTransaction = false }()
	return fn(f)
}
func (f *gateTransactor) LockScope(context.Context, domain.ScopeID) (port.ScopeSnapshot, error) {
	f.order = append(f.order, "authority")
	if f.lockErr != nil {
		return port.ScopeSnapshot{}, f.lockErr
	}
	return f.snapshot, nil
}
func (f *gateTransactor) LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (port.RolloutSnapshot, error) {
	return port.RolloutSnapshot{}, errors.New("unexpected rollout lock")
}
func (f *gateTransactor) ValidateTargets(_ context.Context, _ domain.ScopeID, roots []domain.RootID) error {
	if !reflect.DeepEqual(roots, []domain.RootID{"root-a"}) {
		return errors.New("unexpected roots")
	}
	return nil
}
func (f *gateTransactor) ValidateCurrentLease(_ context.Context, scope domain.ScopeID, root domain.RootID, binding domain.AttemptLeaseBinding) error {
	if !f.inTransaction || scope != "scope" || root != "root-a" {
		return errors.New("lease validation outside authority transaction")
	}
	f.leaseCalls++
	f.order = append(f.order, "lease")
	f.binding = binding
	return f.leaseErr
}

func gateAuthorization(grant domain.Grant) domain.HighRiskAuthorization {
	return domain.HighRiskAuthorization{Grant: grant, Lease: domain.AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: "worker", SessionID: "session", LeaseEpoch: 1}}
}

func gateState(mode domain.ScopeMode, epoch domain.Epoch) port.ScopeSnapshot {
	return port.ScopeSnapshot{ScopeID: "scope", ActivationEpoch: 1, SecurityEpoch: epoch, Mode: mode, Roots: map[domain.RootID]domain.RootAuthority{"root-a": {Policy: domain.PolicyBinding{Digest: testDigest()}, AuthorizationEpoch: 3}}}
}
func gateGrant(state port.ScopeSnapshot) domain.Grant {
	root := state.Roots["root-a"]
	return domain.Grant{Root: "root-a", Policy: root.Policy, AuthorizationEpoch: root.AuthorizationEpoch, SecurityEpoch: state.SecurityEpoch}
}

func TestSafetyGateReadsAuthorityFreshForEveryCheck(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f)
	ctx := context.Background()
	grant := gateGrant(f.snapshot)
	if err := gate.CheckNewDispatch(ctx, "scope", "root-a"); err != nil {
		t.Fatal(err)
	}
	if err := gate.CheckNewGrant(ctx, "scope", "root-a"); err != nil {
		t.Fatal(err)
	}
	if err := gate.CheckHighRiskAction(ctx, "scope", gateAuthorization(grant)); err != nil {
		t.Fatal(err)
	}

	// Simulate a committed emergency stop after construction: same gate must
	// observe SAFE_STOPPED and the advanced security epoch on every call.
	f.snapshot = gateState(domain.ScopeSafeStop, 8)
	for name, check := range map[string]func() error{
		"dispatch":              func() error { return gate.CheckNewDispatch(ctx, "scope", "root-a") },
		"grant":                 func() error { return gate.CheckNewGrant(ctx, "scope", "root-a") },
		"stale high-risk grant": func() error { return gate.CheckHighRiskAction(ctx, "scope", gateAuthorization(grant)) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, domain.ErrSafeStopped) {
				t.Fatalf("got %v, want safe-stopped denial", err)
			}
		})
	}
	if f.calls != 6 {
		t.Fatalf("transaction calls = %d, want 6", f.calls)
	}
}

func TestSafetyGateFailsClosedOnDatabaseAndFrozen(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		state   port.ScopeSnapshot
		lockErr error
		want    error
	}{
		{"database unavailable", gateState(domain.ScopeActive, 7), domain.ErrDatabaseUnavailable, domain.ErrDatabaseUnavailable},
		{"frozen", gateState(domain.ScopeFrozen, 7), nil, domain.ErrScopeFrozen},
		{"safe stopped", gateState(domain.ScopeSafeStop, 8), nil, domain.ErrSafeStopped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &gateTransactor{snapshot: tc.state, lockErr: tc.lockErr}
			if err := NewSafetyGate(f).CheckNewDispatch(ctx, "scope", "root-a"); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSafetyGateTransactorErrorFailsClosed(t *testing.T) {
	want := errors.New("database transaction failed")
	gate := NewSafetyGate(&gateTransactor{lockErr: want})
	if err := gate.CheckNewGrant(context.Background(), "scope", "root-a"); !errors.Is(err, want) {
		t.Fatalf("got %v, want transaction error", err)
	}
}
