package application

import (
	"context"
	"errors"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
)

type consumerInboxStoreFake struct {
	consumerID string
	eventID    string
	applied    bool
	err        error
	calls      int
}

func (f *consumerInboxStoreFake) ApplyEventOnce(_ context.Context, consumerID, eventID string) (bool, error) {
	f.calls++
	f.consumerID, f.eventID = consumerID, eventID
	return f.applied, f.err
}

func validConsumerInboxEvent(t *testing.T) domain.Event {
	t.Helper()
	event, err := domain.NewEvent("event-1", "scope", "scope-1", 1, "ScopeChanged", "event/1", []byte(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestConsumerInboxProcessorAppliesAndDeduplicatesDeliveries(t *testing.T) {
	store := &consumerInboxStoreFake{applied: true}
	processor, err := NewConsumerInboxProcessor(store)
	if err != nil {
		t.Fatal(err)
	}
	event := validConsumerInboxEvent(t)
	applied, err := processor.Process(context.Background(), "projection-v1", event)
	if err != nil || !applied {
		t.Fatalf("first Process() = (%t, %v), want (true, nil)", applied, err)
	}
	store.applied = false
	applied, err = processor.Process(context.Background(), "projection-v1", event)
	if err != nil || applied {
		t.Fatalf("duplicate Process() = (%t, %v), want (false, nil)", applied, err)
	}
	if store.calls != 2 || store.consumerID != "projection-v1" || store.eventID != event.ID() {
		t.Fatalf("store call state = calls:%d consumer:%q event:%q", store.calls, store.consumerID, store.eventID)
	}
}

func TestConsumerInboxProcessorRejectsInvalidInputWithoutStoreCall(t *testing.T) {
	store := &consumerInboxStoreFake{}
	processor, err := NewConsumerInboxProcessor(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := domain.NewEvent("event-2", "scope", "scope-1", 1, "ScopeChanged", "event/1", nil); err == nil {
		t.Fatal("NewEvent accepted a nil payload")
	}
	validEvent := validConsumerInboxEvent(t)
	for _, tc := range []struct {
		name       string
		consumerID string
		event      domain.Event
	}{
		{name: "empty consumer", consumerID: "", event: validEvent},
		{name: "untrimmed consumer", consumerID: " projection-v1", event: validEvent},
		{name: "invalid zero Event", consumerID: "projection-v1", event: domain.Event{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if applied, err := processor.Process(context.Background(), tc.consumerID, tc.event); err == nil || applied {
				t.Fatalf("Process() = (%t, %v), want false and validation error", applied, err)
			}
		})
	}
	if store.calls != 0 {
		t.Fatalf("invalid input reached store %d times", store.calls)
	}
}

func TestConsumerInboxProcessorPropagatesStoreFailure(t *testing.T) {
	wantErr := errors.New("database transaction failed")
	store := &consumerInboxStoreFake{err: wantErr}
	processor, err := NewConsumerInboxProcessor(store)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := processor.Process(context.Background(), "projection-v1", validConsumerInboxEvent(t))
	if !errors.Is(err, wantErr) || applied {
		t.Fatalf("Process() = (%t, %v), want false and wrapped store error", applied, err)
	}
}
