package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var ErrTraceCredentialLeak = errors.New("trace record contains sensitive credential material")

const TraceSchemaVersion = "paddock.trace/1"

// TraceRecord links correlation/trace IDs across Root, WorkOrder, Attempt,
// Rollout, PolicyRelease, Command, Event, and Receipt without exposing secrets.
type TraceRecord struct {
	SchemaVersion   string            `json:"schema_version"`
	TraceID         string            `json:"trace_id"`
	CorrelationID   string            `json:"correlation_id"`
	RootID          RootID            `json:"root_id,omitempty"`
	WorkOrderID     WorkOrderID       `json:"work_order_id,omitempty"`
	AttemptID       string            `json:"attempt_id,omitempty"`
	RolloutID       RolloutID         `json:"rollout_id,omitempty"`
	PolicyReleaseID string            `json:"policy_release_id,omitempty"`
	CommandID       string            `json:"command_id,omitempty"`
	EventID         string            `json:"event_id,omitempty"`
	ReceiptID       string            `json:"receipt_id,omitempty"`
	Component       string            `json:"component"`
	Action          string            `json:"action"`
	Outcome         string            `json:"outcome"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

var sensitiveKeyTokens = []string{
	"password", "passwd", "pwd", "secret", "token", "private_key", "privkey",
	"dsn", "db_url", "paddock_db_url", "authorization", "api_key", "apikey",
	"credential", "cookie", "session_key", "signing_key",
}

var sensitiveValuePrefixes = []string{
	"postgres://", "postgresql://", "bearer ", "-----begin ",
	"aiza", "sk-", "ghp_", "gho_", "xoxb-", "xoxp-",
}

var (
	keyValueSecretPattern  = regexp.MustCompile(`(?i)[a-z0-9_]*(password|passwd|pwd|secret|token|key|credential|dsn|connection_string)[a-z0-9_]*\s*=`)
	keyValueDSNHostPattern = regexp.MustCompile(`(?i)\bhost\s*=`)
	keyValueDSNOtherParam  = regexp.MustCompile(`(?i)\b(user|dbname|port|sslmode|sslpassword|sslcert|sslkey)\s*=`)
)

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))
	for _, tok := range sensitiveKeyTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return isSensitiveValue(k)
}

func isSensitiveValue(v string) bool {
	lower := strings.ToLower(strings.TrimSpace(v))
	for _, pref := range sensitiveValuePrefixes {
		if strings.Contains(lower, pref) {
			return true
		}
	}
	return keyValueSecretPattern.MatchString(v) ||
		(keyValueDSNHostPattern.MatchString(v) && keyValueDSNOtherParam.MatchString(v))
}

// NewTraceRecord validates lineage identifiers and fails closed if any field
// or attribute contains credential or secret material, without echoing keys.
func NewTraceRecord(r TraceRecord) (TraceRecord, error) {
	if r.SchemaVersion == "" {
		r.SchemaVersion = TraceSchemaVersion
	}
	if r.SchemaVersion != TraceSchemaVersion ||
		validateID(r.TraceID) != nil ||
		validateID(r.CorrelationID) != nil ||
		validateID(r.Component) != nil ||
		validateID(r.Action) != nil ||
		validateID(r.Outcome) != nil {
		return TraceRecord{}, fmt.Errorf("%w: invalid trace header", ErrInvalidCanonicalInput)
	}
	if r.RootID == "" && r.WorkOrderID == "" && r.AttemptID == "" &&
		r.RolloutID == "" && r.PolicyReleaseID == "" && r.CommandID == "" && r.ReceiptID == "" {
		return TraceRecord{}, fmt.Errorf("%w: trace must link at least one entity", ErrInvalidCanonicalInput)
	}
	for _, opt := range []string{
		string(r.RootID), string(r.WorkOrderID), r.AttemptID,
		string(r.RolloutID), r.PolicyReleaseID, r.CommandID, r.EventID, r.ReceiptID,
	} {
		if opt != "" {
			if validateID(opt) != nil || isSensitiveValue(opt) {
				return TraceRecord{}, ErrTraceCredentialLeak
			}
		}
	}
	cloned := make(map[string]string, len(r.Attributes))
	for k, v := range r.Attributes {
		if validateID(k) != nil {
			return TraceRecord{}, fmt.Errorf("%w: invalid attribute key", ErrInvalidCanonicalInput)
		}
		if isSensitiveKey(k) || isSensitiveValue(v) {
			return TraceRecord{}, fmt.Errorf("%w: sensitive attribute rejected", ErrTraceCredentialLeak)
		}
		cloned[k] = v
	}
	r.Attributes = cloned
	return r, nil
}

// RedactTraceAttributes returns a deterministic, credential-free copy of attrs,
// replacing both unsafe attribute keys and unsafe attribute values.
func RedactTraceAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(attrs))
	redactedKeyIdx := 0
	for _, k := range keys {
		v := attrs[k]
		if isSensitiveValue(k) {
			redactedKeyIdx++
			out[fmt.Sprintf("redacted_key_%d", redactedKeyIdx)] = "[REDACTED]"
			continue
		}
		if isSensitiveKey(k) || isSensitiveValue(v) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// MarshalSafeJSON serializes a validated TraceRecord and verifies no sensitive
// credential pattern escaped into the serialized JSON bytes.
func (r TraceRecord) MarshalSafeJSON() ([]byte, error) {
	if _, err := NewTraceRecord(r); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if isSensitiveValue(string(b)) {
		return nil, ErrTraceCredentialLeak
	}
	return b, nil
}
