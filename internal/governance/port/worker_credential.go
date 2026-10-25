package port

import (
	"context"
	"github.com/letwir/paddock/internal/governance/domain"
)

// WorkerCredentialStore is private to the trusted Coordinator, not an ingress
// or Worker capability. Issuance must check the persisted enrollment binding
// and compare the supplied Issuer context with the locked current DB registry.
type WorkerCredentialStore interface {
	IssueWorkerCredential(context.Context, domain.WorkerCredential) error
	RevokeWorkerCredential(context.Context, string) error
}

// CredentialIssuerProvider supplies trusted Coordinator context for issuance
// only. It is not a Gate freshness source: the SQL issue capability compares
// it with the locked current registry, and SafetyGate reads that registry in
// its own transaction. Never derive this context from Worker claims.
type CredentialIssuerProvider interface {
	CurrentCredentialIssuer(context.Context, string) (domain.CredentialIssuerContext, error)
}
