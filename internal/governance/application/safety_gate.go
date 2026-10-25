package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SafetyGate performs a local, transaction-backed authority check. It is not a
// deployed network Gateway. Callers must invoke it immediately before admission
// or action; a race remains between this check and an external side effect
// unless that effect is protected by an execution-fencing design.
type SafetyGate struct {
	transactor port.SafetyGateTransactor
	audience   string
}

func NewSafetyGate(transactor port.SafetyGateTransactor, audience string) *SafetyGate {
	return &SafetyGate{transactor: transactor, audience: audience}
}

// CheckNewDispatch checks fresh authority before creating a dispatch.
func (g *SafetyGate) CheckNewDispatch(ctx context.Context, scopeID domain.ScopeID, root domain.RootID) error {
	return g.check(ctx, scopeID, func(_ port.SafetyGateTx, state domain.AuthorityState) error {
		if _, err := domain.EffectivePolicy(state, root); err != nil {
			return fmt.Errorf("new dispatch denied: %w", err)
		}
		return nil
	})
}

// CheckNewGrant checks fresh authority before issuing a grant.
func (g *SafetyGate) CheckNewGrant(ctx context.Context, scopeID domain.ScopeID, root domain.RootID) error {
	return g.check(ctx, scopeID, func(_ port.SafetyGateTx, state domain.AuthorityState) error {
		if _, err := domain.EffectivePolicy(state, root); err != nil {
			return fmt.Errorf("new grant denied: %w", err)
		}
		return nil
	})
}

// CheckHighRiskAction checks Root/Security authority, current Lease, Credential
// status/key proof, and trusted current Issuer context in one
// short transaction. It neither executes nor fences a subsequent external action.
// request is trusted actual-command context, not a Worker claim. This check
// does not execute a mutation: effects retain the M04-S02 Receipt contract.
func (g *SafetyGate) CheckHighRiskAction(ctx context.Context, scopeID domain.ScopeID, authorization domain.HighRiskAuthorization, request domain.CredentialRequest) error {
	return g.check(ctx, scopeID, func(tx port.SafetyGateTx, state domain.AuthorityState) error {
		if err := domain.Authorize(state, authorization.Grant); err != nil {
			return fmt.Errorf("high-risk action denied: %w", err)
		}
		if err := authorization.Lease.Validate(); err != nil {
			return fmt.Errorf("high-risk action denied: %w", err)
		}
		if err := tx.ValidateCurrentLease(ctx, scopeID, authorization.Grant.Root, authorization.Lease); err != nil {
			return fmt.Errorf("high-risk action lease validation: %w", err)
		}
		if g.audience == "" || authorization.Credential.Validate() != nil || request.Validate() != nil {
			return domain.ErrWorkerCredential
		}
		credential, key, err := tx.LockWorkerCredential(ctx, authorization.Credential.ID)
		if err != nil {
			return fmt.Errorf("high-risk credential lookup: %w", err)
		}
		issuer, err := tx.LockCurrentCredentialIssuer(ctx, credential.Issuer.IssuerID)
		if err != nil {
			return fmt.Errorf("high-risk issuer context: %w", err)
		}
		if err := domain.VerifyWorkerCredential(credential, key, scopeID, authorization, request, g.audience, issuer); err != nil {
			return err
		}
		// Credential/Issuer locks may have waited for revocation or deployment.
		// Keep the established lock order, but sample DB time again now that
		// all locks are held: a Lease that expired during that wait must deny.
		if err := tx.ValidateCurrentLease(ctx, scopeID, authorization.Grant.Root, authorization.Lease); err != nil {
			return fmt.Errorf("high-risk action final lease validation: %w", err)
		}
		return nil
	})
}

func (g *SafetyGate) check(ctx context.Context, scopeID domain.ScopeID, authorize func(port.SafetyGateTx, domain.AuthorityState) error) error {
	if g == nil || g.transactor == nil {
		return errors.New("safety gate is not initialized")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return g.transactor.WithinSafetyGateTransaction(ctx, func(tx port.SafetyGateTx) error {
		snapshot, err := lockGateAuthority(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		return authorize(tx, snapshotAuthority(snapshot))
	})
}

// Keep the same authority-lock/validation order as SafetyService while exposing
// no mutation, receipt, or event capability to a gate callback.
func lockGateAuthority(ctx context.Context, tx port.SafetyGateTx, scopeID domain.ScopeID) (port.ScopeSnapshot, error) {
	if tx == nil {
		return port.ScopeSnapshot{}, errors.New("nil safety gate transaction")
	}
	if err := scopeID.Validate(); err != nil {
		return port.ScopeSnapshot{}, err
	}
	snapshot, err := tx.LockScope(ctx, scopeID)
	if err != nil {
		return port.ScopeSnapshot{}, err
	}
	if snapshot.ScopeID != scopeID {
		return port.ScopeSnapshot{}, errors.New("malformed scope snapshot: identity mismatch")
	}
	if snapshot.LiveRolloutID != nil {
		rollout, err := tx.LockRollout(ctx, scopeID, *snapshot.LiveRolloutID)
		if err != nil {
			return port.ScopeSnapshot{}, err
		}
		if rollout.ID != *snapshot.LiveRolloutID || rollout.Scope != scopeID {
			return port.ScopeSnapshot{}, errors.New("malformed rollout snapshot: identity mismatch")
		}
	}
	if err := snapshotAuthority(snapshot).Validate(); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("malformed authority snapshot: %w", err)
	}
	ids := make([]domain.RootID, 0, len(snapshot.Roots))
	for id := range snapshot.Roots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return port.ScopeSnapshot{}, errors.New("malformed authority snapshot: no Roots")
	}
	if err := tx.ValidateTargets(ctx, scopeID, ids); err != nil {
		return port.ScopeSnapshot{}, err
	}
	return snapshot, nil
}
