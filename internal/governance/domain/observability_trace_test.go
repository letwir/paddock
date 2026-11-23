package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestTraceRecordLineageAndCredentialLeakPrevention(t *testing.T) {
	rec, err := NewTraceRecord(TraceRecord{
		TraceID:         "trace-001",
		CorrelationID:   "corr-001",
		RootID:          "root-a",
		WorkOrderID:     "wo-10",
		AttemptID:       "att-2",
		RolloutID:       "rollout-4",
		PolicyReleaseID: "rel-42",
		CommandID:       "cmd-9",
		EventID:         "evt-9",
		ReceiptID:       "rcpt-9",
		Component:       "coordinator",
		Action:          "promote",
		Outcome:         "SUCCEEDED",
		Attributes:      map[string]string{"scope_epoch": "42"},
	})
	if err != nil {
		t.Fatalf("valid trace rejected: %v", err)
	}
	b, err := rec.MarshalSafeJSON()
	if err != nil {
		t.Fatalf("marshal safe JSON: %v", err)
	}
	for _, want := range []string{"trace-001", "corr-001", "root-a", "wo-10", "att-2", "rollout-4", "rel-42", "rcpt-9"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing lineage field %q in %s", want, b)
		}
	}

	leaks := []map[string]string{
		{"PADDOCK_DB_URL": "postgres://user:pass@localhost:5432/paddock_test"},
		{"note": "postgres://app:secret@db/paddock"},
		{"note": "sslpassword=SYNTHETIC_PASS"},
		{"note": "dbname=paddock host=db"},
		{"auth_header": "Bearer super-secret-jwt"},
		{"signing_key": "deadbeef"},
		{"payload": "-----BEGIN PRIVATE KEY-----"},
		{"token": "ghp_123456"},
		{"ghp_SYNTHETIC_KEY": "normal_value"},
	}
	for _, attrs := range leaks {
		_, err := NewTraceRecord(TraceRecord{
			TraceID:       "trace-leak",
			CorrelationID: "corr-leak",
			RootID:        "root-a",
			Component:     "gateway",
			Action:        "authorize",
			Outcome:       "DENIED",
			Attributes:    attrs,
		})
		if !errors.Is(err, ErrTraceCredentialLeak) {
			t.Fatalf("credential leak not rejected for %v: %v", attrs, err)
		}
		if strings.Contains(err.Error(), "ghp_SYNTHETIC_KEY") || strings.Contains(err.Error(), "PADDOCK_DB_URL") {
			t.Fatalf("error echoed unsafe key: %v", err)
		}
		redacted := RedactTraceAttributes(attrs)
		for k, v := range redacted {
			if strings.Contains(k, "ghp_") || v != "[REDACTED]" {
				t.Fatalf("attribute %q=%q not safely redacted", k, v)
			}
		}
	}
}
