// Package postgres implements governance persistence using pgx Native.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/port"
)

const rollbackTimeout = 5 * time.Second

type transaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

func commitKnownAborted(err error) bool {
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return true
	}
	var stateErr interface{ SQLState() string }
	if !errors.As(err, &stateErr) {
		return false
	}
	return stateErr.SQLState() == "40001" || stateErr.SQLState() == "40P01"
}

type beginner interface {
	Begin(context.Context) (transaction, error)
}

type poolBeginner struct{ pool *pgxpool.Pool }

func (p poolBeginner) Begin(ctx context.Context) (transaction, error) { return p.pool.Begin(ctx) }

// Transactor owns one pgx transaction for one application callback.
type Transactor struct {
	pool      beginner
	safetyAPI bool
}

func NewTransactor(pool *pgxpool.Pool) (*Transactor, error) {
	if pool == nil {
		return nil, errors.New("postgres transactor: nil pool")
	}
	return &Transactor{pool: poolBeginner{pool: pool}}, nil
}

func newTransactor(pool beginner) *Transactor { return &Transactor{pool: pool} }

func (t *Transactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	if t == nil || t.pool == nil {
		return errors.New("postgres transactor: uninitialized pool")
	}
	if ctx == nil {
		return errors.New("postgres transactor: nil context")
	}
	if fn == nil {
		return errors.New("postgres transactor: nil callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin governance transaction: %w", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if rollbackErr := rollback(tx); rollbackErr != nil {
				panic(errors.Join(fmt.Errorf("callback panic: %v", recovered), fmt.Errorf("rollback governance transaction: %w", rollbackErr)))
			}
			panic(recovered)
		}
	}()

	var governanceTx port.GovernanceTx = newGovernanceTx(tx)
	if t.safetyAPI {
		governanceTx = newSafetyGovernanceTx(tx)
	}
	if err := fn(governanceTx); err != nil {
		if rollbackErr := rollbackTransaction(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback governance transaction: %w", rollbackErr))
		}
		return errors.Join(port.ErrTransactionRolledBack, err)
	}
	if err := ctx.Err(); err != nil {
		if rollbackErr := rollbackTransaction(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback cancelled governance transaction: %w", rollbackErr))
		}
		return errors.Join(port.ErrTransactionRolledBack, err)
	}
	if err := tx.Commit(ctx); err != nil {
		// An explicit uncertainty marker always wins over a wrapped SQLSTATE.
		// Server serialization/deadlock errors establish that Commit aborted.
		if !errors.Is(err, port.ErrCommitOutcomeUnknown) && commitKnownAborted(err) {
			return fmt.Errorf("commit governance transaction (rolled back): %w", errors.Join(port.ErrTransactionRolledBack, err))
		}
		return fmt.Errorf("commit governance transaction (outcome may be unknown): %w", errors.Join(port.ErrCommitOutcomeUnknown, err))
	}
	return nil
}

func rollback(tx transaction) error {
	err := rollbackTransaction(tx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Unlike best-effort cleanup, outcome confirmation must not treat ErrTxClosed
// as success: a closed transaction could have committed rather than rolled back.
func rollbackTransaction(tx transaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	return tx.Rollback(ctx)
}
