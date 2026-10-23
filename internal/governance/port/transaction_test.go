package port

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

func TestRolloutSnapshotCarriesCompleteMonitoringFence(t *testing.T) {
	snapshotType := reflect.TypeOf(RolloutSnapshot{})
	f, ok := snapshotType.FieldByName("Monitoring")
	if !ok || f.Type != reflect.TypeOf(domain.MonitoringWindow{}) {
		t.Fatal("rollout snapshot lost monitoring CAS values")
	}
	r, ok := f.Type.FieldByName("DecisionRevision")
	if !ok || r.Type.Kind() != reflect.Int64 {
		t.Fatal("DecisionRevision must remain int64")
	}
}

type fakeGovernanceTx struct {
	receivers       []GovernanceTx
	databaseTime    time.Time
	databaseTimeErr error
}

func TestTransactionRolledBackPreservesJoinedCause(t *testing.T) {
	cause := errors.New("transaction callback failed")
	err := fmt.Errorf("transaction: %w", errors.Join(ErrTransactionRolledBack, cause))
	if !errors.Is(err, ErrTransactionRolledBack) || !errors.Is(err, cause) {
		t.Fatalf("rollback marker or cause lost: %v", err)
	}
	if ErrTransactionRolledBack.Error() != "governance transaction rolled back" ||
		errors.Is(ErrTransactionRolledBack, ErrCommitOutcomeUnknown) || errors.Is(ErrTransactionRolledBack, ErrStaleWrite) {
		t.Fatal("rollback marker must be stable and distinct from other outcomes")
	}
}

func TestCommitOutcomeUnknownPreservesJoinedCause(t *testing.T) {
	cause := errors.New("commit acknowledgement lost")
	err := fmt.Errorf("commit: %w", errors.Join(ErrCommitOutcomeUnknown, cause))
	if !errors.Is(err, ErrCommitOutcomeUnknown) || !errors.Is(err, cause) {
		t.Fatalf("outcome marker or cause lost: %v", err)
	}
	if ErrCommitOutcomeUnknown.Error() != "governance commit outcome unknown" || errors.Is(ErrCommitOutcomeUnknown, ErrStaleWrite) {
		t.Fatal("commit outcome marker must be stable and distinct from stale write")
	}
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

func TestReceiptExpiryRetainsOriginalTerminalIdentity(t *testing.T) {
	for _, status := range []string{"SUCCEEDED", "REJECTED"} {
		r := CommandReceipt{CommandID: "permanent-id", RequestDigest: domain.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Status: status, Response: []byte("full response")}
		r.Expired, r.Response = true, []byte(ReceiptTombstoneResponse)
		if r.CommandID != "permanent-id" || r.RequestDigest.Validate() != nil || r.Status != status || !r.Expired {
			t.Fatalf("tombstone changed terminal identity: %+v", r)
		}
	}
	if ErrReceiptExpired.Error() != "command receipt response expired" || errors.Is(ErrReceiptExpired, ErrStaleWrite) || errors.Is(ErrReceiptExpired, ErrCommitOutcomeUnknown) {
		t.Fatal("expiry must have a stable distinct sentinel")
	}
}
