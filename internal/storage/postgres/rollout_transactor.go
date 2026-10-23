package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/port"
)

// RolloutTransactor binds creation, expected-value CAS, and the existing app-only
// Safety capabilities to one caller transaction. The pool must log in as
// paddock_app, not SET ROLE to it.
type RolloutTransactor struct{ transactor *Transactor }

func NewRolloutTransactor(pool *pgxpool.Pool) (*RolloutTransactor, error) {
	t, err := NewSafetyTransactor(pool)
	if err != nil {
		return nil, err
	}
	return &RolloutTransactor{transactor: t}, nil
}

func (t *RolloutTransactor) WithinRolloutTransaction(ctx context.Context, fn func(port.RolloutTx) error) error {
	if t == nil || t.transactor == nil {
		return errors.New("postgres rollout transactor: uninitialized pool")
	}
	if fn == nil {
		return errors.New("postgres rollout transactor: nil callback")
	}
	// Delegate transaction ownership, cancellation, panic rollback and unknown
	// commit outcomes to the existing lifecycle; never open a nested transaction.
	return t.transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		safety, ok := tx.(*safetyGovernanceTx)
		if !ok {
			return errors.New("postgres rollout transactor: app-only adapter required")
		}
		return fn(&rolloutGovernanceTx{safetyGovernanceTx: safety})
	})
}

var _ port.RolloutTransactor = (*RolloutTransactor)(nil)

// Monitoring, Safety HoldExtend and Reaper use the same full-snapshot adapter
// as StartCanary/Promote, not the base-only Safety adapter.
func (t *RolloutTransactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	if fn == nil {
		return errors.New("postgres rollout transactor: nil callback")
	}
	return t.WithinRolloutTransaction(ctx, func(tx port.RolloutTx) error { return fn(tx) })
}

var _ port.Transactor = (*RolloutTransactor)(nil)
