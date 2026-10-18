package port

import (
	"context"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

// MaxOutboxClaimBatch bounds one database claim transaction.
const MaxOutboxClaimBatch = 100

// OutboxClaim is one Event leased for delivery. ClaimToken fences Ack/Retry
// calls from a dispatcher whose claim has since been replaced.
type OutboxClaim struct {
	Event          domain.Event
	ClaimToken     string
	AttemptCount   int32
	LeaseExpiresAt time.Time
}

// OutboxRetryDisposition is the persisted result of retrying a claimed Event.
type OutboxRetryDisposition string

const (
	OutboxRetryScheduled OutboxRetryDisposition = "RETRY_SCHEDULED"
	OutboxDeadLettered   OutboxRetryDisposition = "DEAD_LETTERED"
	OutboxClaimStale     OutboxRetryDisposition = "STALE_CLAIM"
)

// OutboxStore grants only transactional claim/ack/retry capabilities. Concrete
// implementations must publish outside the database transaction and enforce claim fencing.
type OutboxStore interface {
	Claim(ctx context.Context, limit int) ([]OutboxClaim, error)
	Ack(ctx context.Context, eventID, claimToken string) (bool, error)
	Retry(ctx context.Context, eventID, claimToken, sanitizedErrorCode string) (OutboxRetryDisposition, error)
}

// OutboxNotificationListener waits for a best-effort PostgreSQL wake-up hint.
// Callers must continue durable Polling after timeout, disconnect, or error.
type OutboxNotificationListener interface {
	Wait(ctx context.Context) error
	Close(ctx context.Context) error
}

// OutboxNotifier subscribes to wake-up hints; notifications are never delivery
// records and may be coalesced or missed while disconnected.
type OutboxNotifier interface {
	Listen(ctx context.Context) (OutboxNotificationListener, error)
}
