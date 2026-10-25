package postgres

import (
	"context"
	"fmt"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type safetyGateTx struct{ *safetyGovernanceTx }

func (t *safetyGateTx) LockWorkerCredential(ctx context.Context, id string) (domain.WorkerCredential, []byte, error) {
	return lockWorkerCredential(ctx, t.tx, id)
}

func (t *safetyGateTx) LockCurrentCredentialIssuer(ctx context.Context, id string) (domain.CredentialIssuerContext, error) {
	return lockCurrentCredentialIssuer(ctx, t.tx, id)
}

func newSafetyGateTx(tx transaction) *safetyGateTx {
	return &safetyGateTx{safetyGovernanceTx: newSafetyGovernanceTx(tx)}
}

func (t *safetyGateTx) ValidateCurrentLease(ctx context.Context, scope domain.ScopeID, root domain.RootID, b domain.AttemptLeaseBinding) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := root.Validate(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	var valid bool
	err := t.tx.QueryRow(ctx, `SELECT raw.safety_validate_current_lease($1,$2,$3,$4,$5,$6,$7)`, string(scope), string(root), string(b.WorkOrderID), string(b.AttemptID), string(b.WorkerID), string(b.SessionID), int64(b.LeaseEpoch)).Scan(&valid)
	if err != nil {
		// Do not include opaque session identities or query arguments in context.
		return fmt.Errorf("validate SafetyGate current lease: %w", err)
	}
	if !valid {
		return domain.ErrInvalidLease
	}
	return nil
}

var _ port.SafetyGateTx = (*safetyGateTx)(nil)
