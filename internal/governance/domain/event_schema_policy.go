package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const eventSchemaPrefix = "event/"

var (
	ErrInvalidEventSchemaVersion   = errors.New("invalid Event schema version")
	ErrInvalidSupportedSchemaMajor = errors.New("invalid supported Event schema major")
	ErrQuarantineIdentityConflict  = errors.New("compatibility quarantine identity conflict")
	ErrDifferentQuarantineKey      = errors.New("compatibility quarantine key mismatch")
)

// EventSchemaVersion is the versioned Event envelope major. The accepted wire
// form is event/<positive decimal major>; current event/1 is major 1.
type EventSchemaVersion struct {
	major uint64
}

func ParseEventSchemaVersion(value string) (EventSchemaVersion, error) {
	if !strings.HasPrefix(value, eventSchemaPrefix) || strings.TrimSpace(value) != value {
		return EventSchemaVersion{}, fmt.Errorf("%w: expected %s<positive-major>", ErrInvalidEventSchemaVersion, eventSchemaPrefix)
	}
	majorText := strings.TrimPrefix(value, eventSchemaPrefix)
	if majorText == "" {
		return EventSchemaVersion{}, fmt.Errorf("%w: major is empty", ErrInvalidEventSchemaVersion)
	}
	if len(majorText) > 1 && majorText[0] == '0' {
		return EventSchemaVersion{}, fmt.Errorf("%w: major must use canonical decimal form", ErrInvalidEventSchemaVersion)
	}
	for _, r := range majorText {
		if r < '0' || r > '9' {
			return EventSchemaVersion{}, fmt.Errorf("%w: major must be unsigned decimal", ErrInvalidEventSchemaVersion)
		}
	}
	major, err := strconv.ParseUint(majorText, 10, 64)
	if err != nil || major == 0 {
		return EventSchemaVersion{}, fmt.Errorf("%w: major must be positive", ErrInvalidEventSchemaVersion)
	}
	return EventSchemaVersion{major: major}, nil
}

func (v EventSchemaVersion) Major() uint64 { return v.major }

func (v EventSchemaVersion) String() string {
	if v.major == 0 {
		return ""
	}
	return eventSchemaPrefix + strconv.FormatUint(v.major, 10)
}

type EventSchemaCompatibility string

const (
	EventSchemaSupportedMajor EventSchemaCompatibility = "SUPPORTED_MAJOR"
	EventSchemaUnknownMajor   EventSchemaCompatibility = "UNKNOWN_MAJOR"
)

// CheckEventSchemaCompatibility accepts only explicitly supported majors.
// Unknown majors are a fail-closed compatibility outcome, not a parse error;
// callers must quarantine them without Inbox or business-effect mutation.
func CheckEventSchemaCompatibility(value string, supportedMajors []uint64) (EventSchemaVersion, EventSchemaCompatibility, error) {
	version, err := ParseEventSchemaVersion(value)
	if err != nil {
		return EventSchemaVersion{}, "", err
	}
	for _, supported := range supportedMajors {
		if supported == 0 {
			return EventSchemaVersion{}, "", ErrInvalidSupportedSchemaMajor
		}
	}
	for _, supported := range supportedMajors {
		if supported == version.major {
			return version, EventSchemaSupportedMajor, nil
		}
	}
	return version, EventSchemaUnknownMajor, nil
}

const CompatibilityQuarantineUnsupportedMajor = "UNSUPPORTED_SCHEMA_MAJOR"

// CompatibilityQuarantine is payload-free audit metadata. The source Event is
// retained separately in the immutable Event store and addressed by EventID.
type CompatibilityQuarantine struct {
	consumerID    string
	eventID       string
	schema        EventSchemaVersion
	errorCode     string
	quarantinedAt time.Time
}

func NewCompatibilityQuarantine(consumerID, eventID, schemaVersion, errorCode string, quarantinedAt time.Time) (CompatibilityQuarantine, error) {
	if consumerID == "" || strings.TrimSpace(consumerID) != consumerID || eventID == "" || strings.TrimSpace(eventID) != eventID {
		return CompatibilityQuarantine{}, errors.New("compatibility quarantine requires non-empty trimmed consumer and Event IDs")
	}
	if errorCode != CompatibilityQuarantineUnsupportedMajor {
		return CompatibilityQuarantine{}, fmt.Errorf("unsupported compatibility quarantine error code %q", errorCode)
	}
	if quarantinedAt.IsZero() {
		return CompatibilityQuarantine{}, errors.New("compatibility quarantine time is required")
	}
	version, err := ParseEventSchemaVersion(schemaVersion)
	if err != nil {
		return CompatibilityQuarantine{}, err
	}
	return CompatibilityQuarantine{
		consumerID: consumerID, eventID: eventID, schema: version,
		errorCode: errorCode, quarantinedAt: quarantinedAt,
	}, nil
}

func (q CompatibilityQuarantine) ConsumerID() string                { return q.consumerID }
func (q CompatibilityQuarantine) EventID() string                   { return q.eventID }
func (q CompatibilityQuarantine) SchemaVersion() EventSchemaVersion { return q.schema }
func (q CompatibilityQuarantine) ErrorCode() string                 { return q.errorCode }
func (q CompatibilityQuarantine) QuarantinedAt() time.Time          { return q.quarantinedAt }
func (q CompatibilityQuarantine) RetentionDeadline() time.Time {
	if q.quarantinedAt.IsZero() {
		return time.Time{}
	}
	return q.quarantinedAt.Add(TerminalAuditRetention)
}

// PreserveFirstCompatibilityQuarantine models ON CONFLICT DO NOTHING for the
// unique (consumer_id,event_id) key. Duplicate deliveries never extend the
// replay anchor; conflicting immutable Event metadata fails closed.
func PreserveFirstCompatibilityQuarantine(existing *CompatibilityQuarantine, proposed CompatibilityQuarantine) (CompatibilityQuarantine, bool, error) {
	if existing == nil {
		return proposed, true, nil
	}
	if existing.consumerID != proposed.consumerID || existing.eventID != proposed.eventID {
		return CompatibilityQuarantine{}, false, ErrDifferentQuarantineKey
	}
	if existing.schema != proposed.schema || existing.errorCode != proposed.errorCode {
		return CompatibilityQuarantine{}, false, ErrQuarantineIdentityConflict
	}
	return *existing, false, nil
}

const (
	PublishedOutboxRetention = 7 * 24 * time.Hour
	OrdinaryEventRetention   = 90 * 24 * time.Hour
	ProcessedInboxRetention  = 90 * 24 * time.Hour
	TerminalAuditRetention   = 365 * 24 * time.Hour
	ConsumerReplayWindow     = 30 * 24 * time.Hour
)

// OutboxRetentionDeadline returns no deadline for pending work. Published rows
// use the short retention; terminal DLQ rows retain their audit record longer.
func OutboxRetentionDeadline(publishedAt, deadLetteredAt *time.Time) (time.Time, bool, error) {
	if publishedAt != nil && deadLetteredAt != nil {
		return time.Time{}, false, errors.New("Outbox row cannot be both published and dead-lettered")
	}
	if publishedAt == nil && deadLetteredAt == nil {
		return time.Time{}, false, nil
	}
	if publishedAt != nil {
		if publishedAt.IsZero() {
			return time.Time{}, false, errors.New("published_at is zero")
		}
		return publishedAt.Add(PublishedOutboxRetention), true, nil
	}
	if deadLetteredAt.IsZero() {
		return time.Time{}, false, errors.New("dead_lettered_at is zero")
	}
	return deadLetteredAt.Add(TerminalAuditRetention), true, nil
}

// SourceEventRetentionDeadline pins Events with pending Outbox work forever
// and extends source retention from each terminal-DLQ/quarantine audit anchor.
func SourceEventRetentionDeadline(createdAt time.Time, outboxPending bool, deadLetteredAt, quarantinedAt *time.Time) (time.Time, bool, error) {
	if createdAt.IsZero() {
		return time.Time{}, false, errors.New("Event created_at is required")
	}
	if outboxPending {
		return time.Time{}, false, nil
	}
	deadline := createdAt.Add(OrdinaryEventRetention)
	for _, anchor := range []*time.Time{deadLetteredAt, quarantinedAt} {
		if anchor == nil {
			continue
		}
		if anchor.IsZero() {
			return time.Time{}, false, errors.New("Event audit timestamp is zero")
		}
		candidate := anchor.Add(TerminalAuditRetention)
		if candidate.After(deadline) {
			deadline = candidate
		}
	}
	return deadline, true, nil
}

// ProcessedInboxRetentionDeadline retains unprocessed markers and any marker
// whose source Outbox/replay window still permits another delivery.
func ProcessedInboxRetentionDeadline(processedAt *time.Time, outboxPending, replayWindowOpen bool) (time.Time, bool) {
	if processedAt == nil || processedAt.IsZero() || outboxPending || replayWindowOpen {
		return time.Time{}, false
	}
	return processedAt.Add(ProcessedInboxRetention), true
}

func ReplayAuditRetentionDeadline(requestedAt time.Time) (time.Time, bool) {
	if requestedAt.IsZero() {
		return time.Time{}, false
	}
	return requestedAt.Add(TerminalAuditRetention), true
}

func RetentionExpired(deadline, now time.Time) bool {
	return !deadline.IsZero() && !now.IsZero() && !now.Before(deadline)
}

type ConsumerReplaySource string

const (
	ReplaySourceTerminalOutboxDLQ ConsumerReplaySource = "TERMINAL_OUTBOX_DLQ"
	ReplaySourceCompatibility     ConsumerReplaySource = "COMPATIBILITY_QUARANTINE"
)

type ConsumerReplayDenial string

const (
	ReplayDeniedInvalidSource ConsumerReplayDenial = "INVALID_SOURCE"
	ReplayDeniedInvalidTime   ConsumerReplayDenial = "INVALID_TIME"
	ReplayDeniedEventExpired  ConsumerReplayDenial = "SOURCE_EVENT_EXPIRED"
	ReplayDeniedUnsupported   ConsumerReplayDenial = "UNSUPPORTED_SCHEMA_MAJOR"
	ReplayDeniedOutsideWindow ConsumerReplayDenial = "REPLAY_WINDOW_CLOSED"
)

type ConsumerReplayOutcome string

const (
	ReplayOutcomeApplied   ConsumerReplayOutcome = "APPLIED"
	ReplayOutcomeDuplicate ConsumerReplayOutcome = "DUPLICATE"
	ReplayOutcomeDenied    ConsumerReplayOutcome = "DENIED"
)

const TrustedReplayServicePrincipal = "paddock_app"

// ConsumerReplayAudit is a payload-free audit value. Principal records only the
// trusted database service identity; it deliberately carries no human identity.
type ConsumerReplayAudit struct {
	requestID   string
	consumerID  string
	eventID     string
	schema      EventSchemaVersion
	source      ConsumerReplaySource
	requestedAt time.Time
	outcome     ConsumerReplayOutcome
	principal   string
}

func NewConsumerReplayAudit(requestID, consumerID, eventID, schemaVersion string, source ConsumerReplaySource, requestedAt time.Time, outcome ConsumerReplayOutcome, sessionUser string) (ConsumerReplayAudit, error) {
	for field, value := range map[string]string{
		"replay request ID": requestID,
		"consumer ID":       consumerID,
		"Event ID":          eventID,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return ConsumerReplayAudit{}, fmt.Errorf("invalid %s", field)
		}
	}
	version, err := ParseEventSchemaVersion(schemaVersion)
	if err != nil {
		return ConsumerReplayAudit{}, err
	}
	if source != ReplaySourceTerminalOutboxDLQ && source != ReplaySourceCompatibility {
		return ConsumerReplayAudit{}, fmt.Errorf("invalid replay source %q", source)
	}
	if requestedAt.IsZero() {
		return ConsumerReplayAudit{}, errors.New("consumer replay audit requires database request time")
	}
	if outcome != ReplayOutcomeApplied && outcome != ReplayOutcomeDuplicate && outcome != ReplayOutcomeDenied {
		return ConsumerReplayAudit{}, fmt.Errorf("invalid consumer replay outcome %q", outcome)
	}
	if sessionUser != TrustedReplayServicePrincipal {
		return ConsumerReplayAudit{}, errors.New("consumer replay audit requires trusted paddock_app service principal")
	}
	return ConsumerReplayAudit{
		requestID: requestID, consumerID: consumerID, eventID: eventID,
		schema: version, source: source, requestedAt: requestedAt,
		outcome: outcome, principal: sessionUser,
	}, nil
}

func (a ConsumerReplayAudit) RequestID() string                 { return a.requestID }
func (a ConsumerReplayAudit) ConsumerID() string                { return a.consumerID }
func (a ConsumerReplayAudit) EventID() string                   { return a.eventID }
func (a ConsumerReplayAudit) SchemaVersion() EventSchemaVersion { return a.schema }
func (a ConsumerReplayAudit) Source() ConsumerReplaySource      { return a.source }
func (a ConsumerReplayAudit) RequestedAt() time.Time            { return a.requestedAt }
func (a ConsumerReplayAudit) Outcome() ConsumerReplayOutcome    { return a.outcome }
func (a ConsumerReplayAudit) Principal() string                 { return a.principal }

// ConsumerReplayAllowed applies the strict D-019/D-020 boundary. Support is
// checked at request execution time; replay at the exact 30-day deadline is
// denied. `sourceEventRetained` comes from the replay source read capability.
func ConsumerReplayAllowed(source ConsumerReplaySource, anchor, now time.Time, sourceEventRetained, consumerSupportsMajor bool) (bool, ConsumerReplayDenial) {
	if source != ReplaySourceTerminalOutboxDLQ && source != ReplaySourceCompatibility {
		return false, ReplayDeniedInvalidSource
	}
	if anchor.IsZero() || now.IsZero() || now.Before(anchor) {
		return false, ReplayDeniedInvalidTime
	}
	if !sourceEventRetained {
		return false, ReplayDeniedEventExpired
	}
	if !consumerSupportsMajor {
		return false, ReplayDeniedUnsupported
	}
	if !now.Before(anchor.Add(ConsumerReplayWindow)) {
		return false, ReplayDeniedOutsideWindow
	}
	return true, ""
}
