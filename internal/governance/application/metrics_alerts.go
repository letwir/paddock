package application

import (
	"fmt"
	"sort"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type AlertSeverity string

const (
	AlertWarning  AlertSeverity = "WARNING"
	AlertCritical AlertSeverity = "CRITICAL"
)

type AlertCode string

const (
	AlertCanaryFailureSpike AlertCode = "CANARY_FAILURE_SPIKE"
	AlertCanaryHoldExpired  AlertCode = "CANARY_HOLD_EXPIRED"
	AlertScopeSafeStopped   AlertCode = "SCOPE_SAFE_STOPPED"
	AlertOutboxDeliveryLag  AlertCode = "OUTBOX_DELIVERY_LAG"
	AlertOutboxDLQPresent   AlertCode = "OUTBOX_DLQ_PRESENT"
	AlertLeaseExpired       AlertCode = "LEASE_EXPIRATIONS_DETECTED"
)

// GovernanceMetricSnapshot captures point-in-time Rollout, Outbox, and Lease counts.
type GovernanceMetricSnapshot struct {
	Scope               domain.ScopeID
	CanaryFailureRateBP int
	HoldExpiredCount    int
	SafeStopped         bool
	PendingOutboxCount  int
	MaxOutboxAge        time.Duration
	OutboxDLQCount      int
	ActiveLeaseCount    int
	ExpiredLeaseCount   int
}

type AlertThresholds struct {
	MaxCanaryFailureRateBP int
	MaxOutboxAge           time.Duration
	MaxPendingOutbox       int
	MaxExpiredLeases       int
}

type GovernanceAlert struct {
	Code     AlertCode
	Severity AlertSeverity
	Scope    domain.ScopeID
	Message  string
}

// EvaluateGovernanceMetrics deterministically evaluates Canary anomalies,
// Outbox delivery stalls/DLQ, and Lease expirations against AlertThresholds.
func EvaluateGovernanceMetrics(snap GovernanceMetricSnapshot, th AlertThresholds) []GovernanceAlert {
	var alerts []GovernanceAlert
	if snap.SafeStopped {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertScopeSafeStopped,
			Severity: AlertCritical,
			Scope:    snap.Scope,
			Message:  "scope entered SAFE_STOPPED baseline",
		})
	}
	if snap.CanaryFailureRateBP > th.MaxCanaryFailureRateBP {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertCanaryFailureSpike,
			Severity: AlertCritical,
			Scope:    snap.Scope,
			Message:  fmt.Sprintf("canary failure rate %dbp exceeds %dbp", snap.CanaryFailureRateBP, th.MaxCanaryFailureRateBP),
		})
	}
	if snap.HoldExpiredCount > 0 {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertCanaryHoldExpired,
			Severity: AlertWarning,
			Scope:    snap.Scope,
			Message:  fmt.Sprintf("%d monitoring HOLD episode(s) expired", snap.HoldExpiredCount),
		})
	}
	if (th.MaxOutboxAge > 0 && snap.MaxOutboxAge > th.MaxOutboxAge) ||
		(th.MaxPendingOutbox > 0 && snap.PendingOutboxCount > th.MaxPendingOutbox) {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertOutboxDeliveryLag,
			Severity: AlertWarning,
			Scope:    snap.Scope,
			Message:  fmt.Sprintf("outbox lag age=%s pending=%d", snap.MaxOutboxAge, snap.PendingOutboxCount),
		})
	}
	if snap.OutboxDLQCount > 0 {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertOutboxDLQPresent,
			Severity: AlertCritical,
			Scope:    snap.Scope,
			Message:  fmt.Sprintf("%d terminal DLQ outbox event(s)", snap.OutboxDLQCount),
		})
	}
	if snap.ExpiredLeaseCount > th.MaxExpiredLeases {
		alerts = append(alerts, GovernanceAlert{
			Code:     AlertLeaseExpired,
			Severity: AlertWarning,
			Scope:    snap.Scope,
			Message:  fmt.Sprintf("%d expired lease(s) detected", snap.ExpiredLeaseCount),
		})
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Code < alerts[j].Code })
	return alerts
}
