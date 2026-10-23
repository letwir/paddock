package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// rolloutGovernanceTx inherits only the app-only Safety overrides for authority
// access. Rollout CAS must NOT fall through to governanceTx's direct table DML.
type rolloutGovernanceTx struct{ *safetyGovernanceTx }

// The base Safety API owns the Scope -> Rollout locks and target loading. Read
// monitoring under those same locks; never cache a partially loaded snapshot.
func (g *rolloutGovernanceTx) LockRollout(ctx context.Context, scope domain.ScopeID, id domain.RolloutID) (port.RolloutSnapshot, error) {
	if _, ok := g.lockedScopes[scope]; !ok {
		return port.RolloutSnapshot{}, ErrScopeNotLocked
	}
	key := rolloutKey{scope: scope, rollout: id}
	if s, ok := g.lockedRollouts[key]; ok {
		if err := validatePersistentRollout(s); err != nil {
			return port.RolloutSnapshot{}, err
		}
		return cloneRollout(s), nil
	}
	s, err := g.safetyGovernanceTx.LockRollout(ctx, scope, id)
	if err != nil {
		return port.RolloutSnapshot{}, err
	}
	delete(g.lockedRollouts, key)
	wire := monitoringRow{}
	err = g.tx.QueryRow(ctx, `SELECT * FROM raw.safety_rollout_monitoring($1, $2)`, string(scope), string(id)).Scan(wire.dest()...)
	if err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("read Rollout %q monitoring: %w", id, err)
	}
	s.Monitoring, err = wire.window()
	if err == nil {
		err = validatePersistentRollout(s)
	}
	if err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("validate Rollout %q monitoring: %w", id, err)
	}
	g.lockedRollouts[key] = cloneRollout(s)
	return s, nil
}

// rolloutCreateTarget deliberately uses json (not jsonb) at the SQL boundary.
// Every object always includes all five keys, including a null safe baseline.
type rolloutCreateTarget struct {
	RootID          string       `json:"root_id"`
	Target          bool         `json:"target"`
	BaselineDigest  any          `json:"baseline_digest"`
	CandidateDigest string       `json:"candidate_digest"`
	BaseRootEpoch   domain.Epoch `json:"base_root_epoch"`
}

func (g *rolloutGovernanceTx) CreateRollout(ctx context.Context, snapshot port.RolloutSnapshot) error {
	if err := validatePersistentRollout(snapshot); err != nil {
		return fmt.Errorf("create rollout: %w", err)
	}
	locked, ok := g.lockedScopes[snapshot.Scope]
	if !ok {
		return ErrScopeNotLocked
	}
	if !g.validatedScopes[snapshot.Scope] {
		return ErrTargetsNotLocked
	}
	last, err := snapshot.BaseActivationEpoch.Next()
	if err != nil {
		return fmt.Errorf("create rollout epoch: %w", err)
	}
	// The five-argument create API represents precisely a new StartCanary, not
	// arbitrary insertion of historical or terminal Rollouts.
	if snapshot.State != domain.RolloutCanary || snapshot.TargetRoot == nil || snapshot.RollbackFrom != nil ||
		snapshot.LastActivationEpoch != last || snapshot.BaseActivationEpoch != locked.ActivationEpoch ||
		snapshot.BaseSecurityEpoch != locked.SecurityEpoch || locked.Mode != domain.ScopeActive || locked.LiveRolloutID != nil ||
		len(snapshot.Targets) == 0 || len(snapshot.Targets) != len(locked.Roots) {
		return port.ErrStaleWrite
	}
	if _, ok := snapshot.Targets[*snapshot.TargetRoot]; !ok {
		return port.ErrStaleWrite
	}
	targets := make([]rolloutCreateTarget, 0, len(snapshot.Targets))
	for _, id := range sortedTargetIDs(snapshot.Targets) {
		target := snapshot.Targets[id]
		root, exists := locked.Roots[id]
		if !exists || target.BaseRootEpoch != root.AuthorizationEpoch || target.Baseline != root.Policy {
			return port.ErrStaleWrite
		}
		targets = append(targets, rolloutCreateTarget{RootID: string(id), Target: id == *snapshot.TargetRoot,
			BaselineDigest: nullablePolicyDigest(target.Baseline), CandidateDigest: string(target.Candidate.Digest), BaseRootEpoch: target.BaseRootEpoch})
	}
	payload, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("encode rollout targets: %w", err)
	}
	_, err = g.tx.Exec(ctx, `SELECT raw.safety_create_rollout($1, $2, $3, $4, $5::json)`,
		string(snapshot.ID), string(snapshot.Scope), snapshot.BaseActivationEpoch, snapshot.BaseSecurityEpoch, string(payload))
	if err != nil {
		return fmt.Errorf("create rollout %q: %w", snapshot.ID, err)
	}
	g.lockedRollouts[rolloutKey{scope: snapshot.Scope, rollout: snapshot.ID}] = cloneRollout(snapshot)
	return nil
}

func (g *rolloutGovernanceTx) CompareAndSwapRollout(ctx context.Context, expected, next port.RolloutSnapshot) error {
	key := rolloutKey{scope: expected.Scope, rollout: expected.ID}
	locked, ok := g.lockedRollouts[key]
	if !ok || !reflect.DeepEqual(locked, expected) {
		return port.ErrStaleWrite
	}
	if expected.ID != next.ID || expected.Scope != next.Scope || expected.BaseActivationEpoch != next.BaseActivationEpoch ||
		expected.BaseSecurityEpoch != next.BaseSecurityEpoch || !sameTargetIDs(expected.Targets, next.Targets) {
		return port.ErrStaleWrite
	}
	if err := validatePersistentRollout(expected); err != nil {
		return err
	}
	if err := validatePersistentRollout(next); err != nil {
		return err
	}
	if next.LastActivationEpoch < expected.LastActivationEpoch {
		return port.ErrStaleWrite
	}
	var updated bool
	oldPayload, err := persistentRolloutJSON(expected)
	if err != nil {
		return fmt.Errorf("encode expected Rollout: %w", err)
	}
	newPayload, err := persistentRolloutJSON(next)
	if err != nil {
		return fmt.Errorf("encode next Rollout: %w", err)
	}
	err = g.tx.QueryRow(ctx, `SELECT raw.safety_cas_rollout($1::jsonb, $2::jsonb)`, oldPayload, newPayload).Scan(&updated)
	if err != nil {
		return fmt.Errorf("CAS Rollout %q: %w", expected.ID, err)
	}
	if !updated {
		return port.ErrStaleWrite
	}
	for _, id := range sortedTargetIDs(expected.Targets) {
		oldTarget, newTarget := expected.Targets[id], next.Targets[id]
		err := g.tx.QueryRow(ctx, `SELECT raw.safety_cas_rollout_target($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			nullablePolicyDigest(newTarget.Baseline), nullablePolicyDigest(newTarget.Candidate), newTarget.BaseRootEpoch,
			string(expected.ID), string(expected.Scope), string(id), nullablePolicyDigest(oldTarget.Baseline),
			string(oldTarget.Candidate.Digest), oldTarget.BaseRootEpoch).Scan(&updated)
		if err != nil {
			return fmt.Errorf("CAS rollout target Root %q: %w", id, err)
		}
		if !updated {
			return port.ErrStaleWrite
		}
	}
	g.lockedRollouts[key] = cloneRollout(next)
	return nil
}

var _ port.RolloutTx = (*rolloutGovernanceTx)(nil)
