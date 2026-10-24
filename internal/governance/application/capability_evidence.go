package application

import (
	"context"
	"fmt"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// CapabilityEvidenceService adapts a trusted Coordinator probe to the Domain
// contract. It neither authenticates Workers nor forms Trust or verifies hardware.
type CapabilityEvidenceService struct {
	probe port.CapabilityProbe
}

var _ port.CapabilityProbe = (*CapabilityEvidenceService)(nil)

func NewCapabilityEvidenceService(probe port.CapabilityProbe) *CapabilityEvidenceService {
	return &CapabilityEvidenceService{probe: probe}
}

// Observe returns a detached, validated snapshot. evaluatedAt is supplied by the
// trusted Coordinator; expiry policy and TTL selection remain outside this seam.
func (s *CapabilityEvidenceService) Observe(ctx context.Context, r domain.CapabilityProbeRequest, evaluatedAt time.Time) ([]domain.CoordinatorProbeEvidence, error) {
	if ctx == nil || s == nil || s.probe == nil {
		return nil, domain.ErrCapabilityEvidence
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.Requirements = append([]domain.CapabilityRequirement(nil), r.Requirements...)
	if err := r.Validate(); err != nil {
		return nil, err
	}
	// Validate the evaluation clock even before calling the observation port.
	if evaluatedAt.IsZero() {
		return nil, domain.ErrCapabilityEvidence
	}
	if _, err := evaluatedAt.MarshalJSON(); err != nil {
		return nil, domain.ErrCapabilityEvidence
	}
	probeRequest := r
	probeRequest.Requirements = append([]domain.CapabilityRequirement(nil), r.Requirements...)
	observations, err := s.probe.Observe(ctx, probeRequest, evaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("observe capabilities for worker %q: %w", r.WorkerID, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observations = append([]domain.CoordinatorProbeEvidence(nil), observations...)
	if err := domain.ValidateCapabilityObservations(r, observations, evaluatedAt); err != nil {
		return nil, fmt.Errorf("validate capabilities for worker %q: %w", r.WorkerID, err)
	}
	return observations, nil
}
