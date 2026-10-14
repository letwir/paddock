package port

import (
	"context"
	"errors"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
)

type fakeGovernanceTx struct{ receivers []GovernanceTx }

func (f *fakeGovernanceTx) LockScope(context.Context, domain.ScopeID) (ScopeSnapshot, error) {
	f.receivers = append(f.receivers, f)
	return ScopeSnapshot{}, nil
}
func (f *fakeGovernanceTx) LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (RolloutSnapshot, error) {
	f.receivers = append(f.receivers, f)
	return RolloutSnapshot{}, nil
}
func (f *fakeGovernanceTx) ValidateTargets(context.Context, domain.ScopeID, []domain.RootID) error {
	f.receivers = append(f.receivers, f)
	return nil
}
func (f *fakeGovernanceTx) CompareAndSwapScope(context.Context, ScopeSnapshot, ScopeSnapshot) error {
	f.receivers = append(f.receivers, f)
	return nil
}
func (f *fakeGovernanceTx) CompareAndSwapRollout(context.Context, RolloutSnapshot, RolloutSnapshot) error {
	f.receivers = append(f.receivers, f)
	return nil
}
func (f *fakeGovernanceTx) CompareAndSwapSecurityEpoch(context.Context, domain.Epoch, domain.Epoch) error {
	f.receivers = append(f.receivers, f)
	return nil
}

type fakeTransactor struct{ tx GovernanceTx }

func (f fakeTransactor) WithinTransaction(_ context.Context, fn func(GovernanceTx) error) error {
	return fn(f.tx)
}

var (
	_ GovernanceTx = (*fakeGovernanceTx)(nil)
	_ Transactor   = fakeTransactor{}
)

func TestFakeTransactorSharesTransactionAndPropagatesCallbackError(t *testing.T) {
	tx := &fakeGovernanceTx{}
	transactor := fakeTransactor{tx: tx}
	wantErr := errors.New("callback failed")
	calls := 0

	err := transactor.WithinTransaction(context.Background(), func(got GovernanceTx) error {
		calls++
		if got != tx {
			t.Fatal("callback did not receive the transactor's transaction object")
		}
		if _, err := got.LockScope(context.Background(), "scope"); err != nil {
			return err
		}
		if err := got.ValidateTargets(context.Background(), "scope", []domain.RootID{"root"}); err != nil {
			return err
		}
		return wantErr
	})
	if calls != 1 {
		t.Fatalf("callback called %d times, want 1", calls)
	}
	if len(tx.receivers) != 2 || tx.receivers[0] != tx || tx.receivers[1] != tx {
		t.Fatal("transaction capability was not shared by operations in the callback")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithinTransaction() error = %v, want %v", err, wantErr)
	}
}

func TestStaleWriteSentinelIsStable(t *testing.T) {
	if ErrStaleWrite.Error() == "" {
		t.Fatal("ErrStaleWrite must have a stable description")
	}
}
