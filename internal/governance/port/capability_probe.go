package port

import (
	"context"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

// CapabilityProbe is controlled by the Coordinator, not supplied by a Worker.
// Implementations observe only the requested worker/session capabilities and
// supply observation intervals; this port selects no TTL or probing mechanism.
// Claims and unverified hardware attestations must not be adapted into results.
// Implementations must honor context cancellation. No external probe is provided.
// evaluatedAt comes from the trusted Coordinator, never from Worker input.
type CapabilityProbe interface {
	Observe(context.Context, domain.CapabilityProbeRequest, time.Time) ([]domain.CoordinatorProbeEvidence, error)
}
