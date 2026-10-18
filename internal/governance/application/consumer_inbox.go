package application

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

var ErrConsumerInboxNotInitialized = errors.New("consumer Inbox processor is not initialized")

// ConsumerInboxProcessor applies a local database consumer effect at most once
// per (consumer, Event ID). The store owns the atomic Inbox/effect transaction.
type ConsumerInboxProcessor struct {
	store port.ConsumerInboxStore
}

func NewConsumerInboxProcessor(store port.ConsumerInboxStore) (*ConsumerInboxProcessor, error) {
	if store == nil {
		return nil, ErrConsumerInboxNotInitialized
	}
	return &ConsumerInboxProcessor{store: store}, nil
}

// Process handles one at-least-once Event delivery. It returns applied=false
// for a duplicate; this does not imply exactly-once behavior for external APIs.
func (p *ConsumerInboxProcessor) Process(ctx context.Context, consumerID string, event domain.Event) (applied bool, err error) {
	if p == nil || p.store == nil {
		return false, ErrConsumerInboxNotInitialized
	}
	if ctx == nil {
		return false, errors.New("consumer Inbox: nil context")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if consumerID == "" || strings.TrimSpace(consumerID) != consumerID {
		return false, fmt.Errorf("consumer Inbox: invalid consumer ID")
	}
	if err := event.Validate(); err != nil {
		return false, fmt.Errorf("consumer Inbox: invalid Event: %w", err)
	}
	applied, err = p.store.ApplyEventOnce(ctx, consumerID, event.ID())
	if err != nil {
		return false, fmt.Errorf("consumer Inbox: apply Event %q for consumer %q: %w", event.ID(), consumerID, err)
	}
	return applied, nil
}
