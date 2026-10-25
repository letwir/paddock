package application

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type gateTransactor struct {
	snapshot port.ScopeSnapshot
	lockErr  error
	calls    int
}

func (f *gateTransactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	f.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(f)
}
func (f *gateTransactor) DatabaseTime(context.Context) (time.Time, error) { return time.Time{}, nil }
func (f *gateTransactor) LockScope(context.Context, domain.ScopeID) (port.ScopeSnapshot, error) {
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
func (*gateTransactor) CompareAndSwapScope(context.Context, port.ScopeSnapshot, port.ScopeSnapshot) error {
	return errors.New("unexpected CAS")
}
func (*gateTransactor) CompareAndSwapRollout(context.Context, port.RolloutSnapshot, port.RolloutSnapshot) error {
	return errors.New("unexpected CAS")
}
func (*gateTransactor) CompareAndSwapSecurityEpoch(context.Context, domain.Epoch, domain.Epoch) error {
	return errors.New("unexpected CAS")
}
func (*gateTransactor) LookupCommandReceipt(context.Context, string) (port.CommandReceipt, bool, error) {
	return port.CommandReceipt{}, false, errors.New("unexpected receipt lookup")
}
func (*gateTransactor) InsertCommandReceipt(context.Context, port.CommandReceipt) error {
	return errors.New("unexpected receipt insert")
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
	if err := gate.CheckHighRiskAction(ctx, "scope", grant); err != nil {
		t.Fatal(err)
	}

	// Simulate a committed emergency stop after construction: same gate must
	// observe SAFE_STOPPED and the advanced security epoch on every call.
	f.snapshot = gateState(domain.ScopeSafeStop, 8)
	for name, check := range map[string]func() error{
		"dispatch":              func() error { return gate.CheckNewDispatch(ctx, "scope", "root-a") },
		"grant":                 func() error { return gate.CheckNewGrant(ctx, "scope", "root-a") },
		"stale high-risk grant": func() error { return gate.CheckHighRiskAction(ctx, "scope", grant) },
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
