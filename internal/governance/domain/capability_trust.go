package domain

import (
	"errors"
	"fmt"
)

// ErrWorkerCapabilityTrust identifies an invalid worker-bound capability trust
// profile or update request.
var ErrWorkerCapabilityTrust = errors.New("invalid worker capability trust profile")

// CapabilityTrustTier is a per-capability trust stage. It is separate from the
// enrollment-level QuarantinedWorker tier.
type CapabilityTrustTier string

const (
	CapabilityTrustQ0 CapabilityTrustTier = "Q0"
	CapabilityTrustQ1 CapabilityTrustTier = "Q1"
	CapabilityTrustQ2 CapabilityTrustTier = "Q2"
	CapabilityTrustQ3 CapabilityTrustTier = "Q3"
)

// CapabilityTrustEntry assigns one capability name to one trust stage.
type CapabilityTrustEntry struct {
	Capability string
	Tier       CapabilityTrustTier
}

// WorkerCapabilityTrustProfile is an immutable per-capability trust-stage
// snapshot bound to one enrolled WorkerID. It stores no permissions or Authority.
// Missing capabilities have the conservative per-capability default Q0.
type WorkerCapabilityTrustProfile struct {
	workerID WorkerID
	tiers    map[string]CapabilityTrustTier
}

func validCapabilityTrustTier(tier CapabilityTrustTier) bool {
	switch tier {
	case CapabilityTrustQ0, CapabilityTrustQ1, CapabilityTrustQ2, CapabilityTrustQ3:
		return true
	default:
		return false
	}
}

// NewWorkerCapabilityTrustProfile validates and copies entries. An empty entry
// list is valid for an enrolled worker and reads as Q0 for every capability.
// Capability names follow the same trimmed non-empty contract as CapabilityRequirement.
func NewWorkerCapabilityTrustProfile(workerID WorkerID, entries []CapabilityTrustEntry) (WorkerCapabilityTrustProfile, error) {
	if ValidateEnrollmentWorkerID(workerID) != nil {
		return WorkerCapabilityTrustProfile{}, fmt.Errorf("%w: invalid enrolled WorkerID", ErrWorkerCapabilityTrust)
	}
	tiers := make(map[string]CapabilityTrustTier, len(entries))
	for _, entry := range entries {
		if !capabilityText(entry.Capability) || !validCapabilityTrustTier(entry.Tier) {
			return WorkerCapabilityTrustProfile{}, fmt.Errorf("%w: malformed capability or tier", ErrWorkerCapabilityTrust)
		}
		if _, exists := tiers[entry.Capability]; exists {
			return WorkerCapabilityTrustProfile{}, fmt.Errorf("%w: duplicate capability", ErrWorkerCapabilityTrust)
		}
		tiers[entry.Capability] = entry.Tier
	}
	return WorkerCapabilityTrustProfile{workerID: workerID, tiers: tiers}, nil
}

func (p WorkerCapabilityTrustProfile) validate() error {
	if ValidateEnrollmentWorkerID(p.workerID) != nil {
		return fmt.Errorf("%w: invalid profile WorkerID", ErrWorkerCapabilityTrust)
	}
	for capability, tier := range p.tiers {
		if !capabilityText(capability) || !validCapabilityTrustTier(tier) {
			return fmt.Errorf("%w: malformed stored capability or tier", ErrWorkerCapabilityTrust)
		}
	}
	return nil
}

// WorkerID returns the enrollment-level opaque identity to which this profile is
// bound. It is not a real-world identity or proof of Trust.
func (p WorkerCapabilityTrustProfile) WorkerID() WorkerID { return p.workerID }

// Tier returns the tier for an existing capability, or Q0 if it is absent.
func (p WorkerCapabilityTrustProfile) Tier(capability string) (CapabilityTrustTier, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if !capabilityText(capability) {
		return "", fmt.Errorf("%w: malformed capability name", ErrWorkerCapabilityTrust)
	}
	if tier, exists := p.tiers[capability]; exists {
		return tier, nil
	}
	return CapabilityTrustQ0, nil
}

// WithTier returns a new profile with exactly one capability changed. The target
// tier must come from the trusted evaluator; this value model does not validate
// evidence, select promotion thresholds, or grant Scope/Authority. Setting Q0
// removes the explicit entry because an absent capability already means Q0.
func (p WorkerCapabilityTrustProfile) WithTier(capability string, tier CapabilityTrustTier) (WorkerCapabilityTrustProfile, error) {
	if err := p.validate(); err != nil {
		return WorkerCapabilityTrustProfile{}, err
	}
	if !capabilityText(capability) || !validCapabilityTrustTier(tier) {
		return WorkerCapabilityTrustProfile{}, fmt.Errorf("%w: malformed capability or target tier", ErrWorkerCapabilityTrust)
	}
	updated := p.clone()
	if tier == CapabilityTrustQ0 {
		delete(updated.tiers, capability)
	} else {
		updated.tiers[capability] = tier
	}
	return updated, nil
}

// OnConnectivityInterruption returns an equivalent profile. Connectivity loss
// is unavailable evidence, not an Integrity violation, and cannot change Trust.
func (p WorkerCapabilityTrustProfile) OnConnectivityInterruption(capability string) (WorkerCapabilityTrustProfile, error) {
	if err := p.validate(); err != nil {
		return WorkerCapabilityTrustProfile{}, err
	}
	if !capabilityText(capability) {
		return WorkerCapabilityTrustProfile{}, fmt.Errorf("%w: malformed capability name", ErrWorkerCapabilityTrust)
	}
	return p.clone(), nil
}

func (p WorkerCapabilityTrustProfile) clone() WorkerCapabilityTrustProfile {
	tiers := make(map[string]CapabilityTrustTier, len(p.tiers))
	for capability, tier := range p.tiers {
		tiers[capability] = tier
	}
	return WorkerCapabilityTrustProfile{workerID: p.workerID, tiers: tiers}
}
