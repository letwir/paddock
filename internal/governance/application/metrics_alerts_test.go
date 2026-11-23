package application

import (
	"testing"
	"time"
)

func TestEvaluateGovernanceMetricsFaultInjection(t *testing.T) {
	th := AlertThresholds{
		MaxCanaryFailureRateBP: 500,
		MaxOutboxAge:           30 * time.Second,
		MaxPendingOutbox:       50,
		MaxExpiredLeases:       0,
	}

	healthy := EvaluateGovernanceMetrics(GovernanceMetricSnapshot{
		Scope:               "scope-a",
		CanaryFailureRateBP: 100,
		PendingOutboxCount:  5,
		MaxOutboxAge:        2 * time.Second,
		ActiveLeaseCount:    3,
	}, th)
	if len(healthy) != 0 {
		t.Fatalf("expected 0 alerts on healthy snapshot, got %+v", healthy)
	}

	// Equality boundaries must not alert.
	atBoundary := EvaluateGovernanceMetrics(GovernanceMetricSnapshot{
		Scope:               "scope-a",
		CanaryFailureRateBP: 500,
		PendingOutboxCount:  50,
		MaxOutboxAge:        30 * time.Second,
		ExpiredLeaseCount:   0,
	}, th)
	if len(atBoundary) != 0 {
		t.Fatalf("expected 0 alerts at exact threshold equality, got %+v", atBoundary)
	}

	// Isolated single-fault cases for every alert code.
	isolated := []struct {
		name     string
		snap     GovernanceMetricSnapshot
		wantCode AlertCode
		wantSev  AlertSeverity
	}{
		{
			name:     "safe stopped",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", SafeStopped: true},
			wantCode: AlertScopeSafeStopped,
			wantSev:  AlertCritical,
		},
		{
			name:     "canary failure spike",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", CanaryFailureRateBP: 501},
			wantCode: AlertCanaryFailureSpike,
			wantSev:  AlertCritical,
		},
		{
			name:     "canary hold expired",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", HoldExpiredCount: 1},
			wantCode: AlertCanaryHoldExpired,
			wantSev:  AlertWarning,
		},
		{
			name:     "outbox age only",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", PendingOutboxCount: 1, MaxOutboxAge: 31 * time.Second},
			wantCode: AlertOutboxDeliveryLag,
			wantSev:  AlertWarning,
		},
		{
			name:     "outbox pending only",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", PendingOutboxCount: 51, MaxOutboxAge: 1 * time.Second},
			wantCode: AlertOutboxDeliveryLag,
			wantSev:  AlertWarning,
		},
		{
			name:     "outbox dlq present",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", OutboxDLQCount: 1},
			wantCode: AlertOutboxDLQPresent,
			wantSev:  AlertCritical,
		},
		{
			name:     "lease expired",
			snap:     GovernanceMetricSnapshot{Scope: "scope-a", ExpiredLeaseCount: 1},
			wantCode: AlertLeaseExpired,
			wantSev:  AlertWarning,
		},
	}
	for _, tc := range isolated {
		t.Run(tc.name, func(t *testing.T) {
			alerts := EvaluateGovernanceMetrics(tc.snap, th)
			if len(alerts) != 1 || alerts[0].Code != tc.wantCode || alerts[0].Severity != tc.wantSev {
				t.Fatalf("unexpected alert for %s: %+v", tc.name, alerts)
			}
		})
	}

	// Combined fault snapshot triggers all 6 distinct alert codes.
	fault := EvaluateGovernanceMetrics(GovernanceMetricSnapshot{
		Scope:               "scope-a",
		CanaryFailureRateBP: 1500,
		HoldExpiredCount:    1,
		SafeStopped:         true,
		PendingOutboxCount:  120,
		MaxOutboxAge:        2 * time.Minute,
		OutboxDLQCount:      2,
		ExpiredLeaseCount:   3,
	}, th)
	if len(fault) != 6 {
		t.Fatalf("expected all 6 fault alerts, got %d: %+v", len(fault), fault)
	}
}
