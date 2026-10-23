package domain

import (
	"errors"
	"math"
	"time"
)

const (
	MonitoringActivePeriod = 7 * 24 * time.Hour
	MonitoringHoldBudget   = 24 * time.Hour
	MonitoringExtendedCap  = 2 * MonitoringHoldBudget
)

var ErrInvalidMonitoring = errors.New("invalid monitoring transition")

// MonitoringWindow is a value snapshot. HoldUsed counts CLOSED hold episodes;
// an open episode additionally consumes dbNow-HoldSince. ObservationDeadline is
// shifted only when an episode closes. No Domain function reads a clock.
// The zero value represents monitoring not yet initialized (legacy Promote).
// Application must initialize in the promotion transaction before exposing it.
type MonitoringWindow struct {
	StartedAt           time.Time
	LastObservedAt      time.Time
	ObservationDeadline time.Time
	HoldSince           time.Time
	HoldDeadline        time.Time
	HoldUsed            time.Duration
	HoldBudget          time.Duration
	ExtensionUsed       bool
	ExtensionCommandID  string
	ExtensionNonce      string
	Decision            MonitoringDecision
	DecisionAt          time.Time
	EvidenceDigest      Digest
	// DecisionRevision starts at zero and advances once per new Decision record,
	// including equal-clock re-records and expiry ABORTs, never for HOLD_EXTEND.
	DecisionRevision int64
}

func monitoringTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999
}

// Validate checks stored invariants, not freshness; freshness needs dbNow.
func (m MonitoringWindow) Validate() error {
	if !monitoringTime(m.StartedAt) || !monitoringTime(m.LastObservedAt) || !monitoringTime(m.ObservationDeadline) || m.LastObservedAt.Before(m.StartedAt) {
		return ErrInvalidMonitoring
	}
	cap := MonitoringHoldBudget
	if m.ExtensionUsed {
		cap = MonitoringExtendedCap
		if validateID(m.ExtensionCommandID) != nil || validateID(m.ExtensionNonce) != nil {
			return ErrInvalidMonitoring
		}
	} else if m.ExtensionCommandID != "" || m.ExtensionNonce != "" {
		return ErrInvalidMonitoring
	}
	if m.HoldBudget != cap || m.HoldUsed < 0 || m.HoldUsed > cap || !m.ObservationDeadline.Equal(m.StartedAt.Add(MonitoringActivePeriod+m.HoldUsed)) {
		return ErrInvalidMonitoring
	}
	if m.Decision == "" {
		if !m.DecisionAt.IsZero() || m.EvidenceDigest != "" || m.DecisionRevision != 0 {
			return ErrInvalidMonitoring
		}
	} else if m.DecisionRevision < 1 || m.Decision.Validate() != nil || !monitoringTime(m.DecisionAt) || m.DecisionAt.Before(m.StartedAt) || m.DecisionAt.After(m.LastObservedAt) || (m.EvidenceDigest.Validate() != nil && !(m.Decision == DecisionAbort && m.EvidenceDigest == "")) {
		return ErrInvalidMonitoring
	}
	if m.Decision == DecisionHold {
		if !monitoringTime(m.HoldSince) || !monitoringTime(m.HoldDeadline) || m.HoldSince.Before(m.StartedAt) || m.HoldSince.After(m.DecisionAt) || m.HoldSince.After(m.LastObservedAt) || m.HoldUsed == cap || !m.HoldDeadline.Equal(m.HoldSince.Add(cap-m.HoldUsed)) || !m.LastObservedAt.Before(m.HoldDeadline) {
			return ErrInvalidMonitoring
		}
	} else if !m.HoldSince.IsZero() || !m.HoldDeadline.IsZero() {
		return ErrInvalidMonitoring
	}
	return nil
}

// StartMonitoring initializes a freshly promoted rollout using a DB-clock
// observation supplied by Application. Re-initialization cannot reset budgets.
func StartMonitoring(r PolicyRollout, dbNow time.Time) (PolicyRollout, error) {
	dbNow = dbNow.Round(0).UTC()
	if r.Validate() != nil || r.State != RolloutMonitoring || r.Monitoring != (MonitoringWindow{}) || !monitoringTime(dbNow) {
		return r, ErrInvalidMonitoring
	}
	out := r
	out.Monitoring = MonitoringWindow{StartedAt: dbNow, LastObservedAt: dbNow, ObservationDeadline: dbNow.Add(MonitoringActivePeriod), HoldBudget: MonitoringHoldBudget}
	if out.Validate() != nil {
		return r, ErrInvalidMonitoring
	}
	return out, nil
}

func monitoringInput(r PolicyRollout, dbNow time.Time) error {
	if r.Validate() != nil || r.State != RolloutMonitoring || r.Monitoring.Validate() != nil || !monitoringTime(dbNow) || dbNow.Before(r.Monitoring.LastObservedAt) {
		return ErrInvalidMonitoring
	}
	return nil
}

func (m MonitoringWindow) expired(dbNow time.Time) bool {
	if m.Decision == DecisionHold {
		return !dbNow.Before(m.HoldDeadline)
	}
	return dbNow.After(m.ObservationDeadline)
}

// closeHold accounts exactly for the elapsed episode, once. Expiry callers
// close at HoldDeadline, not at a late Reaper observation beyond the cap.
func (m *MonitoringWindow) closeHold(at time.Time) {
	if !m.HoldSince.IsZero() {
		held := at.Sub(m.HoldSince)
		m.HoldUsed += held
		m.ObservationDeadline = m.ObservationDeadline.Add(held)
		m.HoldSince, m.HoldDeadline = time.Time{}, time.Time{}
	}
}

// RecordMonitoringDecision accepts a validated Gate result and canonical evidence
// digest. FAIL/ABORT are sticky and classified for safe-only rollback; they can
// never be superseded by an ordinary PASS. Expired updates are rejected; use
// EvaluateMonitoring to durably classify expiry as ABORT. Equal database wall-clock
// readings are valid; callers fence decision ordering with their transaction/CAS,
// not clock monotonicity.
func RecordMonitoringDecision(r PolicyRollout, decision MonitoringDecision, evidence Digest, dbNow time.Time) (PolicyRollout, error) {
	dbNow = dbNow.Round(0).UTC()
	if monitoringInput(r, dbNow) != nil || r.Monitoring.DecisionRevision == math.MaxInt64 || decision.Validate() != nil || evidence.Validate() != nil || (r.Monitoring.Decision == DecisionHold && r.Monitoring.expired(dbNow)) || r.Monitoring.Decision == DecisionFail || r.Monitoring.Decision == DecisionAbort {
		return r, ErrInvalidMonitoring
	}
	out := r
	m := &out.Monitoring
	if decision != DecisionHold {
		m.closeHold(dbNow)
	} else if m.Decision != DecisionHold {
		if m.HoldUsed >= m.HoldBudget {
			return r, ErrInvalidMonitoring
		}
		m.HoldSince = dbNow
		m.HoldDeadline = dbNow.Add(m.HoldBudget - m.HoldUsed)
	}
	m.Decision, m.DecisionAt, m.EvidenceDigest, m.LastObservedAt = decision, dbNow, evidence, dbNow
	m.DecisionRevision++
	if out.Validate() != nil {
		return r, ErrInvalidMonitoring
	}
	return out, nil
}

type MonitoringOutcome string

const (
	MonitoringContinue     MonitoringOutcome = "CONTINUE"
	MonitoringComplete     MonitoringOutcome = "COMPLETE"
	MonitoringSafeRollback MonitoringOutcome = "SAFE_ONLY_ROLLBACK"
)

// EvaluateMonitoring is a pure Reaper/command classification. Application must
// persist the returned snapshot and perform SAFE_ONLY_ROLLBACK immediately via
// the preauthorized safety path, never Candidate approval. It does not perform
// rollback, I/O, or claim liveness while the Coordinator/DB is unavailable.
func EvaluateMonitoring(r PolicyRollout, dbNow time.Time) (PolicyRollout, MonitoringOutcome, error) {
	dbNow = dbNow.Round(0).UTC()
	if monitoringInput(r, dbNow) != nil {
		return r, "", ErrInvalidMonitoring
	}
	out := r
	m := &out.Monitoring
	if m.Decision == DecisionFail || m.Decision == DecisionAbort {
		return out, MonitoringSafeRollback, nil
	}
	if m.Decision == DecisionHold {
		if dbNow.Before(m.HoldDeadline) {
			return out, MonitoringContinue, nil
		}
		m.closeHold(m.HoldDeadline)
	} else {
		if dbNow.Before(m.ObservationDeadline) {
			return out, MonitoringContinue, nil
		}
		if m.Decision == DecisionPass && !m.DecisionAt.Before(m.ObservationDeadline) {
			m.LastObservedAt = dbNow
			out.State = RolloutCompleted
			if out.Validate() != nil {
				return r, "", ErrInvalidMonitoring
			}
			return out, MonitoringComplete, nil
		}
	}
	if m.DecisionRevision == math.MaxInt64 {
		return r, "", ErrInvalidMonitoring
	}
	m.Decision, m.DecisionAt, m.LastObservedAt = DecisionAbort, dbNow, dbNow
	m.DecisionRevision++
	if out.Validate() != nil {
		return r, "", ErrInvalidMonitoring
	}
	return out, MonitoringSafeRollback, nil
}
