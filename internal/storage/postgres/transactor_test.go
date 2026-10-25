package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/port"
)

type fakeBeginner struct {
	tx  transaction
	err error
}

func TestCallbackSQLStateRetryRequiresSuccessfulRollback(t *testing.T) {
	for _, state := range []string{"40001", "40P01", "55P03", "42501"} {
		for _, rollbackErr := range []error{nil, io.EOF, pgx.ErrTxClosed} {
			t.Run(fmt.Sprintf("%s/rollback=%v", state, rollbackErr), func(t *testing.T) {
				cause := &pgconn.PgError{Code: state}
				first, second := &fakeTransaction{rollbackErr: rollbackErr}, &fakeTransaction{}
				pool := &sequenceBeginner{transactions: []transaction{first, second}}
				callbacks := 0
				err := application.Retry(context.Background(), newTransactor(pool), 3, 0, func(port.GovernanceTx) error {
					callbacks++
					if callbacks == 1 {
						return fmt.Errorf("callback: %w", cause)
					}
					return nil
				})
				retried := rollbackErr == nil && (state == "40001" || state == "40P01")
				wantCalls := 1
				if retried {
					wantCalls = 2
					if err != nil || second.commits != 1 {
						t.Fatalf("confirmed rollback retry failed: %v", err)
					}
				} else {
					var got *pgconn.PgError
					if !errors.Is(err, cause) || !errors.As(err, &got) || got != cause ||
						errors.Is(err, port.ErrTransactionRolledBack) != (rollbackErr == nil) ||
						(rollbackErr != nil && !errors.Is(err, rollbackErr)) {
						t.Fatalf("cause or rollback evidence incorrect: %v", err)
					}
				}
				if callbacks != wantCalls || pool.calls != wantCalls || first.rollbacks != 1 || first.commits != 0 ||
					second.rollbacks != 0 || errors.Is(err, port.ErrCommitOutcomeUnknown) {
					t.Fatalf("callbacks=%d transactions=%d want=%d err=%v", callbacks, pool.calls, wantCalls, err)
				}
			})
		}
	}
}

func TestCancellationRollbackFailureDoesNotConfirmRollback(t *testing.T) {
	for _, rollbackErr := range []error{io.EOF, pgx.ErrTxClosed} {
		t.Run(rollbackErr.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tx := &fakeTransaction{rollbackErr: rollbackErr}
			err := newTransactor(fakeBeginner{tx: tx}).WithinTransaction(ctx, func(port.GovernanceTx) error {
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) || !errors.Is(err, rollbackErr) || errors.Is(err, port.ErrTransactionRolledBack) ||
				errors.Is(err, port.ErrCommitOutcomeUnknown) || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("failed rollback incorrectly marked: %v commit/rollback=%d/%d", err, tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestBeginSQLStateDoesNotConfirmRollbackOrRetry(t *testing.T) {
	for _, state := range []string{"40001", "40P01"} {
		t.Run(state, func(t *testing.T) {
			cause := &pgconn.PgError{Code: state}
			callbacks := 0
			err := application.Retry(context.Background(), newTransactor(fakeBeginner{err: cause}), 3, 0, func(port.GovernanceTx) error {
				callbacks++
				return nil
			})
			if !errors.Is(err, cause) || errors.Is(err, port.ErrTransactionRolledBack) || callbacks != 0 {
				t.Fatalf("begin error incorrectly marked: %v callbacks=%d", err, callbacks)
			}
		})
	}
}

func TestCommitFailureClassificationAndRetrySafety(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		unknown   bool
		wantCalls int
	}{
		{"serialization abort", &pgconn.PgError{Code: "40001"}, false, 2},
		{"deadlock abort", fmt.Errorf("server: %w", &pgconn.PgError{Code: "40P01"}), false, 2},
		{"connection lost", io.EOF, true, 1},
		{"cancel during commit", context.Canceled, true, 1},
		{"deadline during commit", context.DeadlineExceeded, true, 1},
		{"unmatched SQLSTATE", &pgconn.PgError{Code: "08006"}, true, 1},
		{"lock unavailable at commit", &pgconn.PgError{Code: "55P03"}, true, 1},
		{"ACL at commit", &pgconn.PgError{Code: "42501"}, true, 1},
		{"closed transaction", pgx.ErrTxClosed, true, 1},
		{"error text not SQLSTATE", errors.New("40001 40P01"), true, 1},
		{"explicit unknown serialization", errors.Join(port.ErrCommitOutcomeUnknown, &pgconn.PgError{Code: "40001"}), true, 1},
		{"explicit unknown deadlock", errors.Join(&pgconn.PgError{Code: "40P01"}, port.ErrCommitOutcomeUnknown), true, 1},
		{"typed unknown serialization", &application.CommandFailure{Kind: application.FailureUnknownCommit, Cause: &pgconn.PgError{Code: "40001"}}, true, 1},
		{"already aborted pgx transaction", pgx.ErrTxCommitRollback, false, 1},
		{"wrapped pgx abort", fmt.Errorf("driver: %w", pgx.ErrTxCommitRollback), false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeTransaction{commitErr: tc.cause}
			transactor := newTransactor(fakeBeginner{tx: tx})
			err := transactor.WithinTransaction(context.Background(), func(port.GovernanceTx) error { return nil })
			if !errors.Is(err, tc.cause) || errors.Is(err, port.ErrCommitOutcomeUnknown) != tc.unknown {
				t.Fatalf("error=%v unknown=%v want=%v", err, errors.Is(err, port.ErrCommitOutcomeUnknown), tc.unknown)
			}
			if errors.Is(err, port.ErrTransactionRolledBack) != !tc.unknown {
				t.Fatalf("rollback marker=%v unknown=%v: %v", errors.Is(err, port.ErrTransactionRolledBack), tc.unknown, err)
			}
			var wantState, gotState *pgconn.PgError
			if errors.As(tc.cause, &wantState) && (!errors.As(err, &gotState) || gotState != wantState) {
				t.Fatal("driver error identity lost")
			}
			if tx.commits != 1 || tx.rollbacks != 0 {
				t.Fatalf("commit/rollback=%d/%d", tx.commits, tx.rollbacks)
			}

			// Exercise the actual transactor + retry composition with fake pgx
			// transactions only. No connection or SQL execution is involved.
			first, second := &fakeTransaction{commitErr: tc.cause}, &fakeTransaction{}
			pool := &sequenceBeginner{transactions: []transaction{first, second}}
			callbacks := 0
			err = application.Retry(context.Background(), newTransactor(pool), 3, 0, func(port.GovernanceTx) error {
				callbacks++
				return nil
			})
			if pool.calls != tc.wantCalls || callbacks != tc.wantCalls || first.rollbacks != 0 || second.rollbacks != 0 {
				t.Fatalf("transactions=%d callbacks=%d want=%d", pool.calls, callbacks, tc.wantCalls)
			}
			if tc.wantCalls == 2 {
				if err != nil || second.commits != 1 {
					t.Fatalf("known abort retry failed: %v", err)
				}
			} else if !errors.Is(err, tc.cause) || errors.Is(err, port.ErrCommitOutcomeUnknown) != tc.unknown || second.commits != 0 {
				t.Fatalf("nonretryable outcome changed: %v", err)
			}
		})
	}
}

type sequenceBeginner struct {
	transactions []transaction
	calls        int
}

func (f *sequenceBeginner) Begin(context.Context) (transaction, error) {
	f.calls++
	if f.calls > len(f.transactions) {
		return nil, errors.New("unexpected extra transaction")
	}
	return f.transactions[f.calls-1], nil
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
	if !errors.Is(err, wantErr) || !errors.Is(err, port.ErrTransactionRolledBack) {
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
	if !errors.Is(err, callbackErr) || !errors.Is(err, tx.rollbackErr) || errors.Is(err, port.ErrTransactionRolledBack) {
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
	if !errors.Is(err, port.ErrCommitOutcomeUnknown) || !errors.Is(err, tx.commitErr) || errors.Is(err, port.ErrTransactionRolledBack) {
		t.Fatalf("outcome marker or cause lost: %v", err)
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
	if !errors.Is(err, context.Canceled) || !errors.Is(err, port.ErrTransactionRolledBack) {
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
	if !errors.Is(err, beginErr) || errors.Is(err, port.ErrTransactionRolledBack) {
		t.Fatalf("error = %v, want begin error", err)
	}
}
