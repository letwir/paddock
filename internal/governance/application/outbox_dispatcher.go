package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

const maxOutboxClaimBatch = port.MaxOutboxClaimBatch
const outboxDeliveryFailureCode = "EVENT_DELIVERY_FAILED"

var ErrOutboxDispatcherNotInitialized = errors.New("outbox dispatcher is not initialized")

// EventPublisher is the local application boundary for dispatch. No Broker or
// concrete network client is selected by this interface. Delivery is at-least-once:
// a successful publish followed by an Ack failure/lease expiry may publish again,
// so a concrete consumer/effect boundary must deduplicate by Event ID.
type EventPublisher interface {
	Publish(context.Context, domain.Event) error
}

// OutboxDispatchReport summarizes one durable claim batch.
type OutboxDispatchReport struct {
	Claimed      int
	Acknowledged int
	Retried      int
	DeadLettered int
	StaleClaims  int
}

// OutboxDispatcher claims durable Events, publishes outside DB transactions,
// and token-fences the subsequent Ack or Retry.
type OutboxDispatcher struct {
	store      port.OutboxStore
	notifier   port.OutboxNotifier
	publisher  EventPublisher
	claimLimit int
}

func NewOutboxDispatcher(store port.OutboxStore, notifier port.OutboxNotifier, publisher EventPublisher, claimLimit int) (*OutboxDispatcher, error) {
	if store == nil || notifier == nil || publisher == nil {
		return nil, ErrOutboxDispatcherNotInitialized
	}
	if claimLimit < 1 || claimLimit > maxOutboxClaimBatch {
		return nil, fmt.Errorf("outbox claim limit must be between 1 and %d", maxOutboxClaimBatch)
	}
	return &OutboxDispatcher{store: store, notifier: notifier, publisher: publisher, claimLimit: claimLimit}, nil
}

// DispatchOnce polls one bounded durable batch and applies Event effects outside
// DB transactions. Notification delivery never substitutes for Polling.
func (d *OutboxDispatcher) DispatchOnce(ctx context.Context) (OutboxDispatchReport, error) {
	if d == nil || d.store == nil || d.publisher == nil || d.claimLimit < 1 || d.claimLimit > maxOutboxClaimBatch {
		return OutboxDispatchReport{}, ErrOutboxDispatcherNotInitialized
	}
	if ctx == nil {
		return OutboxDispatchReport{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return OutboxDispatchReport{}, err
	}

	claims, err := d.store.Claim(ctx, d.claimLimit)
	if err != nil {
		return OutboxDispatchReport{}, fmt.Errorf("claim Outbox Events: %w", err)
	}
	report := OutboxDispatchReport{Claimed: len(claims)}
	for _, claim := range claims {
		if err := claim.Event.Validate(); err != nil {
			return report, fmt.Errorf("claim returned invalid Event %q: %w", claim.Event.ID(), err)
		}
		if claim.ClaimToken == "" || claim.AttemptCount < 1 || claim.LeaseExpiresAt.IsZero() {
			return report, fmt.Errorf("claim returned incomplete lease for Event %q", claim.Event.ID())
		}

		if err := d.publisher.Publish(ctx, claim.Event.Clone()); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return report, ctxErr
			}
			disposition, retryErr := d.store.Retry(ctx, claim.Event.ID(), claim.ClaimToken, outboxDeliveryFailureCode)
			if retryErr != nil {
				return report, fmt.Errorf("record Outbox delivery failure for Event %q: %w", claim.Event.ID(), retryErr)
			}
			switch disposition {
			case port.OutboxRetryScheduled:
				report.Retried++
			case port.OutboxDeadLettered:
				report.DeadLettered++
			case port.OutboxClaimStale:
				report.StaleClaims++
			default:
				return report, fmt.Errorf("unexpected Outbox Retry disposition %q", disposition)
			}
			continue
		}

		acknowledged, err := d.store.Ack(ctx, claim.Event.ID(), claim.ClaimToken)
		if err != nil {
			return report, fmt.Errorf("ack Outbox Event %q: %w", claim.Event.ID(), err)
		}
		if !acknowledged {
			report.StaleClaims++
			continue
		}
		report.Acknowledged++
	}
	return report, nil
}

// Run registers LISTEN first, then polls the durable Outbox before waiting for a
// wake-up. Timeout/disconnect always returns to Polling; notification payloads
// are ignored and never interpreted as delivery records.
func (d *OutboxDispatcher) Run(ctx context.Context, pollInterval time.Duration) error {
	if d == nil || d.store == nil || d.notifier == nil || d.publisher == nil || d.claimLimit < 1 || d.claimLimit > maxOutboxClaimBatch {
		return ErrOutboxDispatcherNotInitialized
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	if pollInterval <= 0 {
		return errors.New("outbox poll interval must be positive")
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		listener, listenErr := d.notifier.Listen(ctx)
		if listenErr != nil || listener == nil {
			if listener != nil {
				if closeErr := closeOutboxListener(listener); closeErr != nil {
					return fmt.Errorf("close listener returned with failed Listen: %w", closeErr)
				}
			}
			if _, err := d.DispatchOnce(ctx); err != nil {
				return err
			}
			if err := waitForOutboxPoll(ctx, pollInterval); err != nil {
				return err
			}
			continue
		}

		reconnect := false
		for !reconnect {
			report, err := d.DispatchOnce(ctx)
			if err != nil {
				if closeErr := closeOutboxListener(listener); closeErr != nil {
					return errors.Join(err, fmt.Errorf("close listener after dispatch failure: %w", closeErr))
				}
				return err
			}
			if report.Claimed > 0 {
				continue
			}

			waitCtx, cancel := context.WithTimeout(ctx, pollInterval)
			waitErr := listener.Wait(waitCtx)
			cancel()
			closeErr := closeOutboxListener(listener)
			if ctxErr := ctx.Err(); ctxErr != nil {
				if closeErr != nil {
					return errors.Join(ctxErr, fmt.Errorf("close listener after cancellation: %w", closeErr))
				}
				return ctxErr
			}
			if closeErr != nil {
				return fmt.Errorf("close listener after notification wait: %w", closeErr)
			}
			if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) {
				reconnect = true
				continue
			}
			// A notification or polling timeout both lead to another durable poll.
			listener, listenErr = d.notifier.Listen(ctx)
			if listenErr != nil || listener == nil {
				if listener != nil {
					if closeErr := closeOutboxListener(listener); closeErr != nil {
						return fmt.Errorf("close listener returned with failed reconnect Listen: %w", closeErr)
					}
				}
				reconnect = true
			}
		}
	}
}

func closeOutboxListener(listener port.OutboxNotificationListener) error {
	if listener == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return listener.Close(ctx)
}

func waitForOutboxPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
