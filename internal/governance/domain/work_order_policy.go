package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/letwir/paddock/internal/canonical"
)

// WorkOrderPolicy keeps the two D-005 axes independent. ExternalActions is an
// explicit allowlist; an empty list grants no online external action.
type WorkOrderPolicy struct {
	Mode            OfflinePolicy     `json:"mode"`
	Checkpoint      Checkpointability `json:"checkpointability"`
	ExternalActions []string          `json:"external_actions"`
	LowRiskActions  []string          `json:"low_risk_actions"`
}

// sortActionsJCS orders the semantically-set allowlist by the UTF-16 code
// units required by RFC 8785 (rather than Go's UTF-8 byte/string order).
func sortActionsJCS(actions []string) {
	sort.Slice(actions, func(i, j int) bool {
		left, right := utf16.Encode([]rune(actions[i])), utf16.Encode([]rune(actions[j]))
		for k := 0; k < len(left) && k < len(right); k++ {
			if left[k] != right[k] {
				return left[k] < right[k]
			}
		}
		return len(left) < len(right)
	})
}

var ErrInvalidWorkOrderPolicy = errors.New("invalid WorkOrder policy")

// Validate rejects implicit/wildcard authority and duplicate or malformed IDs.
func (p WorkOrderPolicy) Validate() error {
	if (p.Mode != OnlineRequired && p.Mode != OfflineCompute) ||
		(p.Checkpoint != Checkpointable && p.Checkpoint != NotCheckpointable) {
		return ErrInvalidWorkOrderPolicy
	}
	seen := make(map[string]struct{}, len(p.ExternalActions))
	for _, action := range p.ExternalActions {
		if err := validateID(action); err != nil || !utf8.ValidString(action) || action == "*" || action == "%" {
			return ErrInvalidWorkOrderPolicy
		}
		if _, ok := seen[action]; ok {
			return ErrInvalidWorkOrderPolicy
		}
		seen[action] = struct{}{}
	}
	lowSeen := make(map[string]struct{}, len(p.LowRiskActions))
	external := make(map[string]struct{}, len(p.ExternalActions))
	for _, action := range p.ExternalActions {
		external[action] = struct{}{}
	}
	for _, action := range p.LowRiskActions {
		if err := validateID(action); err != nil || !utf8.ValidString(action) || action == "*" || action == "%" {
			return ErrInvalidWorkOrderPolicy
		}
		if _, ok := lowSeen[action]; ok {
			return ErrInvalidWorkOrderPolicy
		}
		lowSeen[action] = struct{}{}
		if _, ok := external[action]; !ok {
			return ErrInvalidWorkOrderPolicy
		}
	}
	return nil
}

// CanonicalBytes returns RFC 8785 bytes of the complete persisted policy.
func (p WorkOrderPolicy) CanonicalBytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	actions := append([]string(nil), p.ExternalActions...)
	sortActionsJCS(actions)
	// The low-risk classification is part of the signed policy schema. Keep an
	// empty set explicit in canonical JSON rather than encoding nil as null.
	low := make([]string, len(p.LowRiskActions))
	copy(low, p.LowRiskActions)
	sortActionsJCS(low)
	encoded, err := json.Marshal(WorkOrderPolicy{Mode: p.Mode, Checkpoint: p.Checkpoint, ExternalActions: actions, LowRiskActions: low})
	if err != nil {
		return nil, err
	}
	return canonical.NewJCSCodec().CanonicalizeJSON(encoded)
}

// Digest is lowercase SHA-256 over the RFC 8785 canonical policy bytes.
func (p WorkOrderPolicy) Digest() (string, error) {
	data, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
