package port

import (
	"context"
	"github.com/letwir/paddock/internal/governance/domain"
)

// SafetyGateTx exposes only fresh authority/credential locks and lease validation.
// Implementations must run every method on the same short transaction; no
// external action is made atomic by this authorization boundary.
type SafetyGateTx interface {
	LockScope(context.Context, domain.ScopeID) (ScopeSnapshot, error)
	LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (RolloutSnapshot, error)
	ValidateTargets(context.Context, domain.ScopeID, []domain.RootID) error
	ValidateCurrentLease(context.Context, domain.ScopeID, domain.RootID, domain.AttemptLeaseBinding) error
	LockWorkerCredential(context.Context, string) (domain.WorkerCredential, []byte, error)
	// LockCurrentCredentialIssuer reads the shared registry and holds its row
	// against deployment updates/deletion until this same transaction ends.
	LockCurrentCredentialIssuer(context.Context, string) (domain.CredentialIssuerContext, error)
}

type SafetyGateTransactor interface {
	WithinSafetyGateTransaction(context.Context, func(SafetyGateTx) error) error
}
