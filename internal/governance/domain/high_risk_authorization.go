package domain

import (
	"errors"
	"fmt"
)

// These identities belong to the authorization contract, not a Scheduler model.
type AttemptID string
type WorkerID string
type SessionID string
type LeaseEpoch int64

var ErrInvalidLease = errors.New("current attempt/lease authorization denied")

// AttemptLeaseBinding identifies exactly one execution generation. It does not
// assert liveness: that must be checked against the current database lease.
type AttemptLeaseBinding struct {
	WorkOrderID WorkOrderID
	AttemptID   AttemptID
	WorkerID    WorkerID
	SessionID   SessionID
	LeaseEpoch  LeaseEpoch
}

func (b AttemptLeaseBinding) Validate() error {
	for _, id := range []string{string(b.WorkOrderID), string(b.AttemptID), string(b.WorkerID), string(b.SessionID)} {
		if err := validateID(id); err != nil {
			return fmt.Errorf("invalid attempt/lease identity: %w", ErrInvalidLease)
		}
	}
	if b.LeaseEpoch <= 0 {
		return ErrInvalidLease
	}
	return nil
}

// HighRiskAuthorization composes a reusable Root Grant with an operation's
// execution binding. Neither value alone authorizes a high-risk action.
type HighRiskAuthorization struct {
	Grant Grant
	Lease AttemptLeaseBinding
}
