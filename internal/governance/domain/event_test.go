package domain

import "testing"

func validEvent() Event {
	e, err := NewEvent("event-1", "rollout", "rollout-1", 1, "rollout.started", "1", []byte(`opaque`))
	if err != nil {
		panic(err)
	}
	return e
}

func TestEventValidate(t *testing.T) {
	if err := validEvent().Validate(); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
}

func TestEventValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{"missing event ID", func(e *Event) { e.id = "" }},
		{"untrimmed event ID", func(e *Event) { e.id = " event-1" }},
		{"missing aggregate kind", func(e *Event) { e.aggregateKind = "" }},
		{"untrimmed aggregate kind", func(e *Event) { e.aggregateKind = "rollout " }},
		{"missing aggregate ID", func(e *Event) { e.aggregateID = "" }},
		{"untrimmed aggregate ID", func(e *Event) { e.aggregateID = " rollout-1" }},
		{"missing event type", func(e *Event) { e.eventType = "" }},
		{"untrimmed event type", func(e *Event) { e.eventType = "rollout.started " }},
		{"missing schema version", func(e *Event) { e.schemaVersion = "" }},
		{"untrimmed schema version", func(e *Event) { e.schemaVersion = " 1" }},
		{"missing payload", func(e *Event) { e.payload = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvent()
			tt.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEventValidateAggregateVersion(t *testing.T) {
	for _, version := range []int64{0, -1} {
		e := validEvent()
		e.aggregateVersion = version
		if err := e.Validate(); err == nil {
			t.Errorf("version %d accepted", version)
		}
	}
}

func TestEventEnvelopeAccessorsAndClone(t *testing.T) {
	input := []byte("payload")
	e, err := NewEvent("event-1", "rollout", "rollout-1", 1, "started", "1", input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	assertEnvelope := func(got Event) {
		t.Helper()
		if got.ID() != "event-1" || got.AggregateKind() != "rollout" || got.AggregateID() != "rollout-1" ||
			got.AggregateVersion() != 1 || got.Type() != "started" || got.SchemaVersion() != "1" {
			t.Fatalf("unexpected envelope accessor values: %#v", got)
		}
		if payload := got.Payload(); string(payload) != "payload" {
			t.Fatalf("unexpected payload: %q", payload)
		}
	}
	assertEnvelope(e)

	returned := e.Payload()
	returned[0] = 'Z'
	clone := e.Clone()
	clone.payload[0] = 'Y'
	clone.id = "clone-only"
	clone.aggregateKind = "clone-only"
	clone.aggregateID = "clone-only"
	clone.aggregateVersion = 2
	clone.eventType = "clone-only"
	clone.schemaVersion = "clone-only"

	assertEnvelope(e)
	if clone.ID() != "clone-only" || string(clone.Payload()) != "Yayload" {
		t.Fatalf("clone mutation did not remain independent: ID=%q payload=%q", clone.ID(), clone.Payload())
	}
}

func TestEventAllowsOpaqueEmptyPayload(t *testing.T) {
	e, err := NewEvent("event-1", "rollout", "rollout-1", 1, "started", "1", []byte{})
	if err != nil {
		t.Fatalf("non-nil empty opaque payload rejected: %v", err)
	}
	if payload := e.Payload(); payload == nil || len(payload) != 0 {
		t.Fatalf("expected present empty payload, got %#v", payload)
	}
}
