package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SafetyGate performs a local, transaction-backed authority check. It is not a
// deployed network Gateway. Callers must invoke it immediately before admission
// or action; a race remains between this check and an external side effect
// unless that effect is protected by an execution-fencing design.
type SafetyGate struct {
	transactor port.Transactor
}

func NewSafetyGate(transactor port.Transactor) *SafetyGate {
	return &SafetyGate{transactor: transactor}
}

// CheckNewDispatch checks fresh authority before creating a dispatch.
func (g *SafetyGate) CheckNewDispatch(ctx context.Context, scopeID domain.ScopeID, root domain.RootID) error {
	return g.check(ctx, scopeID, func(state domain.AuthorityState) error {
		if _, err := domain.EffectivePolicy(state, root); err != nil {
			return fmt.Errorf("new dispatch denied: %w", err)
		}
		return nil
	})
}

// CheckNewGrant checks fresh authority before issuing a grant.
func (g *SafetyGate) CheckNewGrant(ctx context.Context, scopeID domain.ScopeID, root domain.RootID) error {
	return g.check(ctx, scopeID, func(state domain.AuthorityState) error {
		if _, err := domain.EffectivePolicy(state, root); err != nil {
			return fmt.Errorf("new grant denied: %w", err)
		}
		return nil
	})
}

// CheckHighRiskAction verifies a grant against fresh Root policy and epochs.
func (g *SafetyGate) CheckHighRiskAction(ctx context.Context, scopeID domain.ScopeID, grant domain.Grant) error {
	return g.check(ctx, scopeID, func(state domain.AuthorityState) error {
		if err := domain.Authorize(state, grant); err != nil {
			return fmt.Errorf("high-risk action denied: %w", err)
		}
		return nil
	})
}

func (g *SafetyGate) check(ctx context.Context, scopeID domain.ScopeID, authorize func(domain.AuthorityState) error) error {
	if g == nil || g.transactor == nil {
		return errors.New("safety gate is not initialized")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return g.transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		snapshot, err := lockAuthority(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		return authorize(snapshotAuthority(snapshot))
	})
}
