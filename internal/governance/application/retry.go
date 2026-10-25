// Package application contains governance use-case orchestration.
package application

import (
	"context"
	"errors"
	"time"

	"github.com/letwir/paddock/internal/governance/port"
)

// ErrInvalidMaxAttempts is returned when retry is configured with no attempts.
var ErrInvalidMaxAttempts = errors.New("retry maxAttempts must be at least 1")

type sqlStateError interface {
	SQLState() string
}

// Retry runs the entire callback in a fresh transaction for serialization
// failures (SQLSTATE 40001) and deadlocks (40P01) carrying the Transactor's
// ErrTransactionRolledBack marker, up to maxAttempts total attempts.
// The callback must contain repeatable DB-only effects: it must not
// perform external effects. The transactor owns transaction rollback/commit.
// An explicit UNKNOWN_COMMIT is returned unchanged, never retried, regardless
// of wrapped SQLSTATE or concurrent context cancellation.
//
// retryDelay is the fixed delay between retryable failures. A non-positive
// delay retries immediately. The final transaction error is returned unchanged.
func Retry(ctx context.Context, transactor port.Transactor, maxAttempts int, retryDelay time.Duration, callback func(port.GovernanceTx) error) error {
	return retryWithWait(ctx, transactor, maxAttempts, retryDelay, callback, waitContext)
}

func retryWithWait(ctx context.Context, transactor port.Transactor, maxAttempts int, retryDelay time.Duration, callback func(port.GovernanceTx) error, wait func(context.Context, time.Duration) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if maxAttempts < 1 {
		return ErrInvalidMaxAttempts
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := transactor.WithinTransaction(ctx, callback)
		if err == nil {
			return nil
		}
		if unknownCommit(err) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !retryableSQLState(err) || attempt == maxAttempts {
			return err
		}
		if retryDelay > 0 {
			if waitErr := wait(ctx, retryDelay); waitErr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				return waitErr
			}
		}
	}
	return nil
}

func retryableSQLState(err error) bool {
	if unknownCommit(err) || !errors.Is(err, port.ErrTransactionRolledBack) {
		return false
	}
	var stateErr sqlStateError
	if !errors.As(err, &stateErr) {
		return false
	}
	state := stateErr.SQLState()
	return state == "40001" || state == "40P01"
}

func unknownCommit(err error) bool {
	// Check the port contract before inspecting SQLSTATE on any wrapped cause.
	return errors.Is(err, port.ErrCommitOutcomeUnknown)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
