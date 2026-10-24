package port

import (
	"context"

	"github.com/letwir/paddock/internal/governance/domain"
)

// WorkerEnrollmentStore is a trusted Coordinator capability, never an external
// enrollment endpoint. Implementations persist the exact immutable challenge,
// return only unused tickets, and atomically compare/consume that ticket and
// insert a Q0 Worker. A unique public-key fingerprint spans all Coordinators.
// Proof failure never calls ConsumeEnrollment; transaction failure leaves the
// ticket unused. No Scope membership, Trust promotion, or Authority is granted.
type WorkerEnrollmentStore interface {
	CreateEnrollmentChallenge(context.Context, domain.EnrollmentChallenge) error
	ReadEnrollmentChallenge(context.Context, string) (domain.EnrollmentChallenge, error)
	ConsumeEnrollment(context.Context, domain.VerifiedWorkerEnrollment, domain.WorkerID) (domain.QuarantinedWorker, error)
}
