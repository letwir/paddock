package domain

import (
	"errors"
	"testing"
	"time"
)

func policyTime(day int) time.Time {
	return time.Date(2026, time.January, day, 12, 0, 0, 0, time.UTC)
}

func TestParseEventSchemaVersionPositiveMajor(t *testing.T) {
	for _, tc := range []struct {
		input string
		major uint64
		want  string
	}{
		{input: "event/1", major: 1, want: "event/1"},
		{input: "event/27", major: 27, want: "event/27"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			version, err := ParseEventSchemaVersion(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if version.Major() != tc.major || version.String() != tc.want {
				t.Fatalf("ParseEventSchemaVersion(%q) = major %d / %q", tc.input, version.Major(), version.String())
			}
		})
	}
}

func TestParseEventSchemaVersionFailsClosed(t *testing.T) {
	for _, input := range []string{"", "1", "event/", "event/0", "event/01", "event/001", "event/-1", "event/+1", "event/1.0", "event/1x", " event/1", "event/1 ", "event/18446744073709551616"} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseEventSchemaVersion(input); !errors.Is(err, ErrInvalidEventSchemaVersion) {
				t.Fatalf("ParseEventSchemaVersion(%q) error = %v, want ErrInvalidEventSchemaVersion", input, err)
			}
		})
	}
}

func TestCheckEventSchemaCompatibilityRejectsUnknownMajorWithoutCoercion(t *testing.T) {
	version, compatibility, err := CheckEventSchemaCompatibility("event/1", []uint64{1})
	if err != nil || compatibility != EventSchemaSupportedMajor || version.Major() != 1 {
		t.Fatalf("known major result = (%d,%q,%v)", version.Major(), compatibility, err)
	}
	version, compatibility, err = CheckEventSchemaCompatibility("event/2", []uint64{1})
	if err != nil || compatibility != EventSchemaUnknownMajor || version.Major() != 2 {
		t.Fatalf("unknown major result = (%d,%q,%v), want unknown major 2", version.Major(), compatibility, err)
	}
	if _, _, err := CheckEventSchemaCompatibility("event/1", []uint64{1, 0}); !errors.Is(err, ErrInvalidSupportedSchemaMajor) {
		t.Fatalf("trailing zero supported major error = %v, want ErrInvalidSupportedSchemaMajor", err)
	}
}

func TestCompatibilityQuarantinePreservesFirstTimestampAndIdentity(t *testing.T) {
	firstAt := policyTime(1)
	duplicateAt := firstAt.Add(12 * time.Hour)
	first, err := NewCompatibilityQuarantine("consumer-A", "event-1", "event/2", CompatibilityQuarantineUnsupportedMajor, firstAt)
	if err != nil {
		t.Fatal(err)
	}
	if !first.RetentionDeadline().Equal(firstAt.Add(TerminalAuditRetention)) {
		t.Fatalf("quarantine retention deadline=%v", first.RetentionDeadline())
	}
	duplicate, err := NewCompatibilityQuarantine("consumer-A", "event-1", "event/2", CompatibilityQuarantineUnsupportedMajor, duplicateAt)
	if err != nil {
		t.Fatal(err)
	}
	kept, inserted, err := PreserveFirstCompatibilityQuarantine(&first, duplicate)
	if err != nil || inserted || !kept.QuarantinedAt().Equal(firstAt) {
		t.Fatalf("duplicate quarantine = (%v,%t,%v), want first timestamp preserved", kept.QuarantinedAt(), inserted, err)
	}
	otherConsumer, _ := NewCompatibilityQuarantine("consumer-B", "event-1", "event/2", CompatibilityQuarantineUnsupportedMajor, duplicateAt)
	if _, _, err := PreserveFirstCompatibilityQuarantine(&first, otherConsumer); !errors.Is(err, ErrDifferentQuarantineKey) {
		t.Fatalf("different consumer error = %v, want ErrDifferentQuarantineKey", err)
	}
	changedVersion, _ := NewCompatibilityQuarantine("consumer-A", "event-1", "event/3", CompatibilityQuarantineUnsupportedMajor, duplicateAt)
	if _, _, err := PreserveFirstCompatibilityQuarantine(&first, changedVersion); !errors.Is(err, ErrQuarantineIdentityConflict) {
		t.Fatalf("changed version error = %v, want ErrQuarantineIdentityConflict", err)
	}
}

func TestRetentionDurationsMatchD019(t *testing.T) {
	if PublishedOutboxRetention != 7*24*time.Hour || OrdinaryEventRetention != 90*24*time.Hour || ProcessedInboxRetention != 90*24*time.Hour || TerminalAuditRetention != 365*24*time.Hour || ConsumerReplayWindow != 30*24*time.Hour {
		t.Fatalf("retention constants changed: outbox=%s event=%s inbox=%s audit=%s replay=%s", PublishedOutboxRetention, OrdinaryEventRetention, ProcessedInboxRetention, TerminalAuditRetention, ConsumerReplayWindow)
	}
}

func TestOutboxRetentionDeadlinesAndPendingNeverExpires(t *testing.T) {
	publishedAt := policyTime(1)
	deadline, exists, err := OutboxRetentionDeadline(&publishedAt, nil)
	if err != nil || !exists || !deadline.Equal(publishedAt.Add(PublishedOutboxRetention)) {
		t.Fatalf("published Outbox deadline = (%v,%t,%v)", deadline, exists, err)
	}
	if RetentionExpired(deadline, deadline.Add(-time.Nanosecond)) || !RetentionExpired(deadline, deadline) {
		t.Fatal("published Outbox expiry boundary must be exclusive-before and expired-at-deadline")
	}
	deadAt := policyTime(2)
	deadline, exists, err = OutboxRetentionDeadline(nil, &deadAt)
	if err != nil || !exists || !deadline.Equal(deadAt.Add(TerminalAuditRetention)) {
		t.Fatalf("terminal Outbox deadline = (%v,%t,%v)", deadline, exists, err)
	}
	if _, exists, err := OutboxRetentionDeadline(nil, nil); err != nil || exists {
		t.Fatalf("pending Outbox has deadline = (%t,%v), want none", exists, err)
	}
	if _, _, err := OutboxRetentionDeadline(&publishedAt, &deadAt); err == nil {
		t.Fatal("incompatible published+DLQ state was accepted")
	}
}

func TestSourceEventRetentionPinsPendingAndUsesLatestAuditAnchor(t *testing.T) {
	createdAt := policyTime(1)
	ordinary, eligible, err := SourceEventRetentionDeadline(createdAt, false, nil, nil)
	if err != nil || !eligible || !ordinary.Equal(createdAt.Add(OrdinaryEventRetention)) {
		t.Fatalf("ordinary Event deadline = (%v,%t,%v)", ordinary, eligible, err)
	}
	if _, eligible, err := SourceEventRetentionDeadline(createdAt, true, nil, nil); err != nil || eligible {
		t.Fatalf("pending Event retention eligible=%t err=%v, want pinned", eligible, err)
	}
	dlqAt := createdAt.Add(10 * 24 * time.Hour)
	quarantinedAt := createdAt.Add(20 * 24 * time.Hour)
	deadline, eligible, err := SourceEventRetentionDeadline(createdAt, false, &dlqAt, &quarantinedAt)
	if err != nil || !eligible || !deadline.Equal(quarantinedAt.Add(TerminalAuditRetention)) {
		t.Fatalf("audited Event deadline = (%v,%t,%v), want latest 365d anchor", deadline, eligible, err)
	}
	zero := time.Time{}
	if _, eligible, err := SourceEventRetentionDeadline(createdAt, false, &zero, nil); err == nil || eligible {
		t.Fatal("zero terminal timestamp did not fail closed")
	}
}

func TestProcessedInboxRetentionWaitsForPendingOutboxAndReplay(t *testing.T) {
	processedAt := policyTime(1)
	deadline, eligible := ProcessedInboxRetentionDeadline(&processedAt, false, false)
	if !eligible || !deadline.Equal(processedAt.Add(ProcessedInboxRetention)) {
		t.Fatalf("processed Inbox deadline = (%v,%t)", deadline, eligible)
	}
	if _, eligible := ProcessedInboxRetentionDeadline(nil, false, false); eligible {
		t.Fatal("unprocessed Inbox row became expiry-eligible")
	}
	if _, eligible := ProcessedInboxRetentionDeadline(&processedAt, true, false); eligible {
		t.Fatal("pending Outbox failed to pin Inbox")
	}
	if _, eligible := ProcessedInboxRetentionDeadline(&processedAt, false, true); eligible {
		t.Fatal("open replay window failed to pin Inbox")
	}
}

func TestConsumerReplayWindowStrictBoundariesAndGuards(t *testing.T) {
	anchor := policyTime(1)
	for _, source := range []ConsumerReplaySource{ReplaySourceTerminalOutboxDLQ, ReplaySourceCompatibility} {
		t.Run(string(source), func(t *testing.T) {
			if ok, denial := ConsumerReplayAllowed(source, anchor, anchor.Add(-time.Nanosecond), true, true); ok || denial != ReplayDeniedInvalidTime {
				t.Fatalf("pre-anchor replay = (%t,%q)", ok, denial)
			}
			if ok, denial := ConsumerReplayAllowed(source, anchor, anchor, true, true); !ok || denial != "" {
				t.Fatalf("anchor replay = (%t,%q), want allowed", ok, denial)
			}
			boundary := anchor.Add(ConsumerReplayWindow)
			if ok, denial := ConsumerReplayAllowed(source, anchor, boundary.Add(-time.Nanosecond), true, true); !ok || denial != "" {
				t.Fatalf("pre-boundary replay = (%t,%q), want allowed", ok, denial)
			}
			if ok, denial := ConsumerReplayAllowed(source, anchor, boundary, true, true); ok || denial != ReplayDeniedOutsideWindow {
				t.Fatalf("exact-boundary replay = (%t,%q), want denied", ok, denial)
			}
			if ok, denial := ConsumerReplayAllowed(source, anchor, anchor, false, true); ok || denial != ReplayDeniedEventExpired {
				t.Fatalf("missing Event replay = (%t,%q), want denied", ok, denial)
			}
			if ok, denial := ConsumerReplayAllowed(source, anchor, anchor, true, false); ok || denial != ReplayDeniedUnsupported {
				t.Fatalf("unsupported schema replay = (%t,%q), want denied", ok, denial)
			}
		})
	}
	if ok, denial := ConsumerReplayAllowed("UNKNOWN", anchor, anchor, true, true); ok || denial != ReplayDeniedInvalidSource {
		t.Fatalf("invalid replay source = (%t,%q), want denied", ok, denial)
	}
}

func TestReplayAuditRetentionDeadline(t *testing.T) {
	requestedAt := policyTime(1)
	deadline, exists := ReplayAuditRetentionDeadline(requestedAt)
	if !exists || !deadline.Equal(requestedAt.Add(TerminalAuditRetention)) {
		t.Fatalf("Replay audit deadline = (%v,%t)", deadline, exists)
	}
	if _, exists := ReplayAuditRetentionDeadline(time.Time{}); exists {
		t.Fatal("zero replay request time received a retention deadline")
	}
}

func TestConsumerReplayAuditRequiresTrustedServiceAndPayloadFreeIdentity(t *testing.T) {
	requestedAt := policyTime(5)
	audit, err := NewConsumerReplayAudit("replay-1", "consumer-1", "event-1", "event/2", ReplaySourceCompatibility, requestedAt, ReplayOutcomeDenied, TrustedReplayServicePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if audit.RequestID() != "replay-1" || audit.ConsumerID() != "consumer-1" || audit.EventID() != "event-1" || audit.SchemaVersion().Major() != 2 || audit.Source() != ReplaySourceCompatibility || !audit.RequestedAt().Equal(requestedAt) || audit.Outcome() != ReplayOutcomeDenied || audit.Principal() != TrustedReplayServicePrincipal {
		t.Fatalf("replay audit fields did not round-trip: %+v", audit)
	}
	if _, err := NewConsumerReplayAudit("replay-2", "consumer-1", "event-1", "event/2", ReplaySourceCompatibility, requestedAt, ReplayOutcomeApplied, "human:operator"); err == nil {
		t.Fatal("replay audit accepted a non-service principal")
	}
	if _, err := NewConsumerReplayAudit("replay-3", "consumer-1", "event-1", "event/2", ReplaySourceCompatibility, requestedAt, ConsumerReplayOutcome("raw-payload"), TrustedReplayServicePrincipal); err == nil {
		t.Fatal("replay audit accepted a raw/unbounded outcome")
	}
}
