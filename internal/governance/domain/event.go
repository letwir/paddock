package domain

import (
	"fmt"
	"strings"
)

// Event is a database- and transport-independent, immutable event envelope.
// Payload is opaque bytes: this contract does not prescribe JSON or any
// serialization. A non-nil zero-length payload is present and valid; nil means
// absent. All fields are private and exposed only through read-only accessors.
type Event struct {
	id               string
	aggregateKind    string
	aggregateID      string
	aggregateVersion int64
	eventType        string
	schemaVersion    string
	payload          []byte
}

// NewEvent constructs a validated Event and retains independent copies of its
// data. Empty, non-nil payloads are allowed because the payload contract is
// opaque bytes rather than JSON; nil denotes missing payload.
func NewEvent(id, aggregateKind, aggregateID string, aggregateVersion int64, eventType, schemaVersion string, payload []byte) (Event, error) {
	event := Event{
		id: id, aggregateKind: aggregateKind, aggregateID: aggregateID,
		aggregateVersion: aggregateVersion, eventType: eventType,
		schemaVersion: schemaVersion, payload: cloneBytes(payload),
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

// ID returns the event identifier.
func (e Event) ID() string { return e.id }

// AggregateKind returns the kind of aggregate that produced the event.
func (e Event) AggregateKind() string { return e.aggregateKind }

// AggregateID returns the identifier of the aggregate that produced the event.
func (e Event) AggregateID() string { return e.aggregateID }

// AggregateVersion returns the aggregate's version for this event.
func (e Event) AggregateVersion() int64 { return e.aggregateVersion }

// Type returns the event type.
func (e Event) Type() string { return e.eventType }

// SchemaVersion returns the event schema version.
func (e Event) SchemaVersion() string { return e.schemaVersion }

// Payload returns a defensive copy of the opaque payload bytes.
func (e Event) Payload() []byte { return cloneBytes(e.payload) }

// Validate checks required envelope fields without interpreting payload bytes.
func (e Event) Validate() error {
	for name, value := range map[string]string{
		"event ID":       e.id,
		"aggregate kind": e.aggregateKind,
		"aggregate ID":   e.aggregateID,
		"event type":     e.eventType,
		"schema version": e.schemaVersion,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("invalid %s: must be non-empty and trimmed", name)
		}
	}
	if e.aggregateVersion <= 0 {
		return fmt.Errorf("aggregate version must be positive")
	}
	if e.payload == nil {
		return fmt.Errorf("event payload is missing")
	}
	return nil
}

// Clone returns an independent envelope with an independently owned payload.
func (e Event) Clone() Event {
	e.payload = cloneBytes(e.payload)
	return e
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	return append([]byte{}, src...)
}
