package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/port"
)

type fakeBeginner struct {
	tx  transaction
	err error
}

func (f fakeBeginner) Begin(context.Context) (transaction, error) { return f.tx, f.err }

type fakeTransaction struct {
	commitErr   error
	rollbackErr error
	commits     int
	rollbacks   int
}

func (f *fakeTransaction) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (f *fakeTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (f *fakeTransaction) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }
func (f *fakeTransaction) Commit(context.Context) error {
	f.commits++
	return f.commitErr
}
func (f *fakeTransaction) Rollback(context.Context) error {
	f.rollbacks++
	return f.rollbackErr
}

var (
	_ transaction = (*fakeTransaction)(nil)
	_ beginner    = fakeBeginner{}
)

func TestWithinTransactionCommitsOnlyOnNilCallback(t *testing.T) {
	tx := &fakeTransaction{}
	transactor := newTransactor(fakeBeginner{tx: tx})
	if err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commit/rollback = %d/%d, want 1/0", tx.commits, tx.rollbacks)
	}
}

func TestWithinTransactionRollsBackAndPropagatesCallbackError(t *testing.T) {
	tx := &fakeTransaction{}
	transactor := newTransactor(fakeBeginner{tx: tx})
	wantErr := errors.New("callback failed")
	err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want callback error", err)
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("commit/rollback = %d/%d, want 0/1", tx.commits, tx.rollbacks)
	}
}

func TestWithinTransactionPropagatesRollbackFailure(t *testing.T) {
	tx := &fakeTransaction{rollbackErr: errors.New("rollback failed")}
	transactor := newTransactor(fakeBeginner{tx: tx})
	callbackErr := errors.New("callback failed")
	err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return callbackErr })
	if !errors.Is(err, callbackErr) || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("error = %v, want callback and rollback errors", err)
	}
}

func TestWithinTransactionPropagatesUnknownCommitOutcome(t *testing.T) {
	tx := &fakeTransaction{commitErr: errors.New("commit connection lost")}
	transactor := newTransactor(fakeBeginner{tx: tx})
	err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "outcome may be unknown") {
		t.Fatalf("error = %v, want unknown commit outcome", err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commit/rollback = %d/%d, want 1/0 after commit error", tx.commits, tx.rollbacks)
	}
}

func TestWithinTransactionRollsBackWhenContextCancelledAfterCallback(t *testing.T) {
	tx := &fakeTransaction{}
	transactor := newTransactor(fakeBeginner{tx: tx})
	ctx, cancel := context.WithCancel(context.Background())
	err := transactor.WithinTransaction(ctx, func(port.GovernanceTx) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("commit/rollback = %d/%d, want 0/1", tx.commits, tx.rollbacks)
	}
}

func TestWithinTransactionRejectsBeginError(t *testing.T) {
	beginErr := errors.New("begin failed")
	transactor := newTransactor(fakeBeginner{err: beginErr})
	err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return nil })
	if !errors.Is(err, beginErr) {
		t.Fatalf("error = %v, want begin error", err)
	}
}
