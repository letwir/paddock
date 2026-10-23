package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// RolloutDeadlineStore returns hints only. The transaction adapter re-locks and
// compares the entire window before any action; listing never claims a row.
type RolloutDeadlineStore struct{ pool deadlineQuerier }
type deadlineQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func NewRolloutDeadlineStore(pool *pgxpool.Pool) (*RolloutDeadlineStore, error) {
	if pool == nil {
		return nil, errors.New("postgres rollout deadline store: nil pool")
	}
	return &RolloutDeadlineStore{pool: pool}, nil
}

func (s *RolloutDeadlineStore) ListRolloutDeadlines(ctx context.Context, limit int) ([]port.RolloutDeadlineCandidate, error) {
	if err := port.ValidateRolloutDeadlineBatch(limit); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("list rollout deadlines: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil {
		return nil, errors.New("list rollout deadlines: uninitialized pool")
	}
	rows, err := s.pool.Query(ctx, `SELECT * FROM raw.safety_list_rollout_deadlines($1)`, limit)
	if err != nil {
		return nil, fmt.Errorf("list rollout deadlines: %w", err)
	}
	defer rows.Close()
	out := make([]port.RolloutDeadlineCandidate, 0, limit)
	for rows.Next() {
		if len(out) == limit {
			return nil, errors.New("list rollout deadlines: database exceeded batch bound")
		}
		var c port.RolloutDeadlineCandidate
		wire := monitoringRow{}
		dest := append([]any{&c.Scope, &c.Rollout}, wire.dest()...)
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan rollout deadline: %w", err)
		}
		c.Monitoring, err = wire.window()
		if err != nil || c.Scope.Validate() != nil || c.Rollout.Validate() != nil || c.Monitoring.Validate() != nil {
			return nil, fmt.Errorf("invalid rollout deadline %q/%q: %w", c.Scope, c.Rollout, errors.Join(domain.ErrInvalidMonitoring, err))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rollout deadlines: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// INTERVAL is a three-part value. A duration is not a calendar interval:
// reject months/days, NULL, negative values and overflow rather than normalize
// using a caller timezone or silently truncate sub-microsecond values.
func durationInterval(d time.Duration) (pgtype.Interval, error) {
	if d < 0 || d%time.Microsecond != 0 {
		return pgtype.Interval{}, domain.ErrInvalidMonitoring
	}
	return pgtype.Interval{Microseconds: int64(d / time.Microsecond), Valid: true}, nil
}
func intervalDuration(i pgtype.Interval) (time.Duration, error) {
	if !i.Valid || i.Months != 0 || i.Days != 0 || i.Microseconds < 0 || i.Microseconds > math.MaxInt64/int64(time.Microsecond) {
		return 0, domain.ErrInvalidMonitoring
	}
	return time.Duration(i.Microseconds) * time.Microsecond, nil
}

// Column order is shared by the locked reader and deadline-list SQL APIs.
type monitoringRow struct {
	started, observed, observation, since, deadline pgtype.Timestamptz
	used, budget                                    pgtype.Interval
	extension                                       bool
	command, nonce, decision                        string
	decisionAt                                      pgtype.Timestamptz
	evidence                                        string
	revision                                        int64
}

func (r *monitoringRow) dest() []any {
	return []any{&r.started, &r.observed, &r.observation, &r.since, &r.deadline, &r.used, &r.budget, &r.extension, &r.command, &r.nonce, &r.decision, &r.decisionAt, &r.evidence, &r.revision}
}
func (r *monitoringRow) window() (domain.MonitoringWindow, error) {
	var times [6]time.Time
	for n, v := range []pgtype.Timestamptz{r.started, r.observed, r.observation, r.since, r.deadline, r.decisionAt} {
		if v.Valid {
			if v.InfinityModifier != pgtype.Finite || v.Time.IsZero() || v.Time.Year() < 1 || v.Time.Year() > 9999 || v.Time.Nanosecond()%1000 != 0 {
				return domain.MonitoringWindow{}, domain.ErrInvalidMonitoring
			}
			times[n] = v.Time.UTC()
		}
	}
	used, err := intervalDuration(r.used)
	if err != nil {
		return domain.MonitoringWindow{}, err
	}
	budget, err := intervalDuration(r.budget)
	if err != nil {
		return domain.MonitoringWindow{}, err
	}
	m := domain.MonitoringWindow{StartedAt: times[0], LastObservedAt: times[1], ObservationDeadline: times[2], HoldSince: times[3], HoldDeadline: times[4], HoldUsed: used, HoldBudget: budget, ExtensionUsed: r.extension, ExtensionCommandID: r.command, ExtensionNonce: r.nonce, Decision: domain.MonitoringDecision(r.decision), DecisionAt: times[5], EvidenceDigest: domain.Digest(r.evidence), DecisionRevision: r.revision}
	if m != (domain.MonitoringWindow{}) {
		if err := m.Validate(); err != nil {
			return domain.MonitoringWindow{}, err
		}
	}
	return m, nil
}
func validatePersistentRollout(s port.RolloutSnapshot) error {
	if err := validateRolloutSnapshot(s); err != nil {
		return err
	}
	if s.BaseActivationEpoch > math.MaxInt64 || s.BaseSecurityEpoch > math.MaxInt64 || s.LastActivationEpoch > math.MaxInt64 || s.LastActivationEpoch < s.BaseActivationEpoch || len(s.Targets) == 0 || (s.TargetRoot == nil && s.State != domain.RolloutShadow) {
		return domain.ErrInvalidRollout
	}
	if s.TargetRoot != nil {
		if _, ok := s.Targets[*s.TargetRoot]; !ok {
			return domain.ErrInvalidRollout
		}
	}
	for _, t := range s.Targets {
		if t.BaseRootEpoch > math.MaxInt64 {
			return domain.ErrInvalidRollout
		}
	}
	m := s.Monitoring
	if m == (domain.MonitoringWindow{}) {
		if s.State == domain.RolloutMonitoring || s.State == domain.RolloutCompleted || (s.RollbackFrom != nil && *s.RollbackFrom == domain.RolloutMonitoring) {
			return domain.ErrInvalidMonitoring
		}
		return nil
	}
	if s.State == domain.RolloutCanary || s.State == domain.RolloutShadow {
		return domain.ErrInvalidMonitoring
	}
	if err := m.Validate(); err != nil {
		return err
	}
	for _, t := range []time.Time{m.StartedAt, m.LastObservedAt, m.ObservationDeadline, m.HoldSince, m.HoldDeadline, m.DecisionAt} {
		if !t.IsZero() && (t.Year() < 1 || t.Year() > 9999 || t.Nanosecond()%1000 != 0) {
			return domain.ErrInvalidMonitoring
		}
	}
	if _, err := durationInterval(m.HoldUsed); err != nil {
		return err
	}
	if _, err := durationInterval(m.HoldBudget); err != nil {
		return err
	}
	if s.State == domain.RolloutCompleted && (m.Decision != domain.DecisionPass || m.DecisionAt.Before(m.ObservationDeadline) || m.LastObservedAt.Before(m.ObservationDeadline)) {
		return domain.ErrInvalidMonitoring
	}
	return nil
}
func monitoringTimeValue(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// JSON is only the typed API transport. PostgreSQL parses timestamps/INTERVALs
// into the table's exact types before comparing; no textual timestamp equality.
func persistentRolloutJSON(s port.RolloutSnapshot) (string, error) {
	if err := validatePersistentRollout(s); err != nil {
		return "", err
	}
	m := s.Monitoring
	used, err := durationInterval(m.HoldUsed)
	if err != nil {
		return "", err
	}
	budget, err := durationInterval(m.HoldBudget)
	if err != nil {
		return "", err
	}
	targets := make([]map[string]any, 0, len(s.Targets))
	for _, id := range sortedTargetIDs(s.Targets) {
		t := s.Targets[id]
		targets = append(targets, map[string]any{"root_id": string(id), "baseline_bundle_digest": nullablePolicyDigest(t.Baseline), "candidate_bundle_digest": string(t.Candidate.Digest), "base_root_epoch": t.BaseRootEpoch})
	}
	v := map[string]any{
		"rollout_id": string(s.ID), "scope_id": string(s.Scope), "state": string(s.State), "target_root_id": nullableRootID(s.TargetRoot), "base_activation_epoch": s.BaseActivationEpoch, "last_activation_epoch": s.LastActivationEpoch, "base_security_epoch": s.BaseSecurityEpoch, "rollback_from": nullableRolloutState(s.RollbackFrom), "targets": targets,
		"monitoring_started_at": monitoringTimeValue(m.StartedAt), "monitoring_last_observed_at": monitoringTimeValue(m.LastObservedAt), "observation_deadline": monitoringTimeValue(m.ObservationDeadline), "hold_since": monitoringTimeValue(m.HoldSince), "hold_deadline": monitoringTimeValue(m.HoldDeadline),
		"hold_used": fmt.Sprintf("%d microseconds", used.Microseconds), "hold_budget": fmt.Sprintf("%d microseconds", budget.Microseconds), "extension_used": m.ExtensionUsed, "extension_command_id": m.ExtensionCommandID, "extension_nonce": m.ExtensionNonce, "monitoring_decision": string(m.Decision), "decision_at": monitoringTimeValue(m.DecisionAt), "evidence_digest": string(m.EvidenceDigest), "decision_revision": m.DecisionRevision,
	}
	b, err := json.Marshal(v)
	return string(b), err
}

var _ port.RolloutDeadlineStore = (*RolloutDeadlineStore)(nil)
