package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/port"
)

// SafetyGateTransactor uses app-only capabilities on one owned transaction.
// Authorization completes before a subsequent external effect; it is not fencing.
type SafetyGateTransactor struct{ pool beginner }

func NewSafetyGateTransactor(pool *pgxpool.Pool) (*SafetyGateTransactor, error) {
	if pool == nil {
		return nil, errors.New("postgres safety gate: nil pool")
	}
	return &SafetyGateTransactor{pool: poolBeginner{pool: pool}}, nil
}

func (t *SafetyGateTransactor) WithinSafetyGateTransaction(ctx context.Context, fn func(port.SafetyGateTx) error) error {
	if t == nil || t.pool == nil {
		return errors.New("postgres safety gate: uninitialized pool")
	}
	if ctx == nil {
		return errors.New("postgres safety gate: nil context")
	}
	if fn == nil {
		return errors.New("postgres safety gate: nil callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin safety gate transaction: %w", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if err := rollback(tx); err != nil {
				panic(errors.Join(fmt.Errorf("safety gate callback panic: %v", recovered), fmt.Errorf("rollback safety gate transaction: %w", err)))
			}
			panic(recovered)
		}
	}()
	err = fn(newSafetyGateTx(tx))
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if rb := rollbackTransaction(tx); rb != nil {
			return errors.Join(err, fmt.Errorf("rollback safety gate transaction: %w", rb))
		}
		return errors.Join(port.ErrTransactionRolledBack, err)
	}
	if err := tx.Commit(ctx); err != nil {
		if !errors.Is(err, port.ErrCommitOutcomeUnknown) && commitKnownAborted(err) {
			return fmt.Errorf("commit safety gate transaction (rolled back): %w", errors.Join(port.ErrTransactionRolledBack, err))
		}
		return fmt.Errorf("commit safety gate transaction (outcome may be unknown): %w", errors.Join(port.ErrCommitOutcomeUnknown, err))
	}
	return nil
}

var _ port.SafetyGateTransactor = (*SafetyGateTransactor)(nil)
