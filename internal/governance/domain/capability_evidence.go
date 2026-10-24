package domain

import (
	"errors"
	"strings"
	"time"
)

var ErrCapabilityEvidence = errors.New("invalid capability probe evidence")

// CapabilityRequirement is an exact name/value requirement, not a capability taxonomy.
type CapabilityRequirement struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// WorkerCapabilityClaim is untrusted metadata, never dispatch evidence.
type WorkerCapabilityClaim struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CapabilityEvidenceSource string

const CoordinatorObservedProbe CapabilityEvidenceSource = "coordinator_observed_probe"

// ProbeProvenance records the Coordinator-controlled observation's subject and source.
// These identifiers are not authentication or a cryptographic attestation. Only
// trusted Coordinator code may construct/adapt these records for dispatch.
type ProbeProvenance struct {
	Source        CapabilityEvidenceSource `json:"source"`
	CoordinatorID string                   `json:"coordinator_id"`
	ProbeID       string                   `json:"probe_id"`
	WorkerID      string                   `json:"worker_id"`
	SessionID     string                   `json:"session_id"`
}

type CoordinatorProbeEvidence struct {
	Name       string          `json:"name"`
	Value      string          `json:"value"`
	Provenance ProbeProvenance `json:"provenance"`
	ObservedAt time.Time       `json:"observed_at"`
	ValidUntil time.Time       `json:"valid_until"`
}

// HardwareAttestation is an unverified statement, deliberately not Probe Evidence.
// No verifier, hardware proof, trust promotion or production semantics are implied.
type HardwareAttestation struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Attester  string `json:"attester"`
	Statement string `json:"statement"`
}

type CapabilityProbeRequest struct {
	WorkerID     string
	SessionID    string
	Requirements []CapabilityRequirement
}

func capabilityText(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

func capabilityTime(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	_, err := t.MarshalJSON()
	return err == nil
}

func (r CapabilityProbeRequest) Validate() error {
	if !capabilityText(r.WorkerID) || !capabilityText(r.SessionID) {
		return ErrCapabilityEvidence
	}
	seen := make(map[string]bool, len(r.Requirements))
	for _, c := range r.Requirements {
		if !capabilityText(c.Name) || !capabilityText(c.Value) || seen[c.Name] {
			return ErrCapabilityEvidence
		}
		seen[c.Name] = true
	}
	return nil
}

// ValidateFor uses a trusted Coordinator's evaluatedAt, never a Worker clock.
// No TTL is chosen: the supplied interval must contain evaluatedAt, excluding
// its upper boundary. Claims and attestations cannot be passed as this type.
func (e CoordinatorProbeEvidence) ValidateFor(workerID, sessionID string, evaluatedAt time.Time) error {
	p := e.Provenance
	if !capabilityText(e.Name) || !capabilityText(e.Value) ||
		p.Source != CoordinatorObservedProbe || !capabilityText(p.CoordinatorID) || !capabilityText(p.ProbeID) ||
		!capabilityText(p.WorkerID) || !capabilityText(p.SessionID) || p.WorkerID != workerID || p.SessionID != sessionID ||
		!capabilityTime(e.ObservedAt) || !capabilityTime(e.ValidUntil) || !capabilityTime(evaluatedAt) ||
		!e.ObservedAt.Before(e.ValidUntil) || e.ObservedAt.After(evaluatedAt) || !evaluatedAt.Before(e.ValidUntil) {
		return ErrCapabilityEvidence
	}
	return nil
}

// ValidateCapabilityObservations requires an exact set. Duplicate, missing and
// extra evidence fail closed, including evidence for an unconstrained request.
func ValidateCapabilityObservations(r CapabilityProbeRequest, evidence []CoordinatorProbeEvidence, evaluatedAt time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !capabilityTime(evaluatedAt) || len(r.Requirements) != len(evidence) {
		return ErrCapabilityEvidence
	}
	have := make(map[string]string, len(evidence))
	for _, e := range evidence {
		if err := e.ValidateFor(r.WorkerID, r.SessionID, evaluatedAt); err != nil {
			return err
		}
		if _, exists := have[e.Name]; exists {
			return ErrCapabilityEvidence
		}
		have[e.Name] = e.Value
	}
	for _, r := range r.Requirements {
		if have[r.Name] != r.Value {
			return ErrCapabilityEvidence
		}
	}
	return nil
}
