package port

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type fakeGovernanceTx struct {
	receivers       []GovernanceTx
	databaseTime    time.Time
	databaseTimeErr error
}

func (f *fakeGovernanceTx) LookupCommandReceipt(context.Context, string) (CommandReceipt, bool, error) {
	return CommandReceipt{}, false, nil
}
func (f *fakeGovernanceTx) InsertCommandReceipt(context.Context, CommandReceipt) error { return nil }
func (f *fakeGovernanceTx) InsertPolicyBundle(context.Context, domain.CanonicalBundle, string, []byte) error {
	return nil
}
func (f *fakeGovernanceTx) AppendEvent(context.Context, domain.Event) error {
	f.receivers = append(f.receivers, f)
	return nil
}

func TestDatabaseTimeDelegatesResultAndError(t *testing.T) {
	want := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	tx := &fakeGovernanceTx{databaseTime: want}
	got, err := tx.DatabaseTime(context.Background())
	if err != nil || !got.Equal(want) {
		t.Fatalf("DatabaseTime() = %v, %v; want %v, nil", got, err, want)
	}
	wantErr := errors.New("database clock unavailable")
	tx.databaseTimeErr = wantErr
	if _, err := tx.DatabaseTime(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("DatabaseTime() error = %v, want %v", err, wantErr)
	}
	if len(tx.receivers) != 2 {
		t.Fatalf("DatabaseTime called %d times, want 2", len(tx.receivers))
	}
}

func (f *fakeGovernanceTx) DatabaseTime(context.Context) (time.Time, error) {
	f.receivers = append(f.receivers, f)
	return f.databaseTime, f.databaseTimeErr
}

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
