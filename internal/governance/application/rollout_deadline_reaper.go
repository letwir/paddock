package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// RolloutDeadlineReaper is Coordinator-local. Local ticks only wake a sweep;
// all eligibility/expiry decisions use the locked row and transaction DB clock.
// One sweep is bounded by BatchSize and a separate timeout for listing and each
// candidate transaction. No goroutines, open transactions across ticks, or
// automatic retry of unknown commits. Downtime delays processing until recovery.
type RolloutDeadlineReaper struct {
	tx       port.Transactor
	store    port.RolloutDeadlineStore
	lkg      LKGVerifier
	interval time.Duration
	timeout  time.Duration
	batch    int
}

func NewRolloutDeadlineReaper(tx port.Transactor, store port.RolloutDeadlineStore, lkg LKGVerifier, interval, transactionTimeout time.Duration, batch int) (*RolloutDeadlineReaper, error) {
	if tx == nil || store == nil || interval <= 0 || transactionTimeout <= 0 {
		return nil, errors.New("invalid rollout deadline reaper configuration")
	}
	if err := port.ValidateRolloutDeadlineBatch(batch); err != nil {
		return nil, err
	}
	return &RolloutDeadlineReaper{tx: tx, store: store, lkg: lkg, interval: interval, timeout: transactionTimeout, batch: batch}, nil
}

// Sweep returns the number of committed terminal exits. A concurrent winner or
// changed extension/Decision snapshot is a no-op. Operational/CAS/commit failures
// are propagated, with no claim that their attempted changes committed.
func (r *RolloutDeadlineReaper) Sweep(ctx context.Context) (int, error) {
	if r == nil || r.tx == nil || r.store == nil || ctx == nil {
		return 0, errors.New("rollout deadline reaper/context is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	listCtx, cancel := context.WithTimeout(ctx, r.timeout)
	candidates, err := r.store.ListRolloutDeadlines(listCtx, r.batch)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("list rollout deadlines: %w", err)
	}
	if len(candidates) > r.batch {
		return 0, errors.New("rollout deadline store exceeded batch bound")
	}
	processed := 0
	for _, hint := range candidates {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		if hint.Scope.Validate() != nil || hint.Rollout.Validate() != nil || hint.Monitoring.Validate() != nil {
			return processed, errors.New("malformed rollout deadline candidate")
		}
		txCtx, cancel := context.WithTimeout(ctx, r.timeout)
		changed := false
		err := r.tx.WithinTransaction(txCtx, func(tx port.GovernanceTx) error {
			changed = false
			sn, old, ro, err := lockMonitoring(txCtx, tx, hint.Scope, hint.Rollout)
			if errors.Is(err, port.ErrStaleWrite) {
				return nil // another Coordinator released the slot or changed state
			}
			if err != nil {
				return err
			}
			if old.Monitoring != hint.Monitoring {
				return nil // includes an extension without a revision increment
			}
			now, err := tx.DatabaseTime(txCtx)
			if err != nil {
				return err
			}
			next, outcome, err := domain.EvaluateMonitoring(ro, now)
			if err != nil || outcome == domain.MonitoringContinue {
				return err
			}
			if _, err = persistMonitoring(txCtx, tx, r.lkg, sn, old, next, outcome, ""); err != nil {
				return err
			}
			changed = true
			return nil
		})
		cancel()
		if err != nil {
			return processed, fmt.Errorf("reap rollout %s/%s: %w", hint.Scope, hint.Rollout, err)
		}
		if changed {
			processed++
		}
	}
	return processed, nil
}

// Run stops and reports the first operational failure rather than hiding it or
// retrying an uncertain commit. The Coordinator owns restart/observability.
func (r *RolloutDeadlineReaper) Run(ctx context.Context) error {
	if r == nil || ctx == nil || r.interval <= 0 {
		return errors.New("rollout deadline reaper/context is not initialized")
	}
	if _, err := r.Sweep(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := r.Sweep(ctx); err != nil {
				return err
			}
		}
	}
}
