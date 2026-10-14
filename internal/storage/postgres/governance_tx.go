package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

var (
	ErrScopeNotLocked   = errors.New("scope must be locked before governance operation")
	ErrScopeNotFound    = errors.New("scope not found")
	ErrRolloutNotFound  = errors.New("rollout not found in scope")
	ErrInvalidSnapshot  = errors.New("invalid governance snapshot")
	ErrTargetsNotLocked = errors.New("all same-scope Roots must be locked before Scope CAS")
	ErrRolloutNotLocked = errors.New("live Rollout must be locked before Scope CAS")
)

type rolloutKey struct {
	scope   domain.ScopeID
	rollout domain.RolloutID
}

func (g *governanceTx) DatabaseTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	if err := g.tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("read PostgreSQL database time: %w", err)
	}
	return now, nil
}

type governanceTx struct {
	tx              transaction
	lockedScopes    map[domain.ScopeID]port.ScopeSnapshot
	lockedRollouts  map[rolloutKey]port.RolloutSnapshot
	validatedScopes map[domain.ScopeID]bool
}

func newGovernanceTx(tx transaction) *governanceTx {
	return &governanceTx{
		tx: tx, lockedScopes: make(map[domain.ScopeID]port.ScopeSnapshot),
		lockedRollouts:  make(map[rolloutKey]port.RolloutSnapshot),
		validatedScopes: make(map[domain.ScopeID]bool),
	}
}

func (g *governanceTx) LockScope(ctx context.Context, id domain.ScopeID) (port.ScopeSnapshot, error) {
	if err := id.Validate(); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope: %w", err)
	}
	if snapshot, ok := g.lockedScopes[id]; ok {
		return cloneScope(snapshot), nil
	}

	var snapshot port.ScopeSnapshot
	var mode string
	var baseline, live pgtype.Text
	err := g.tx.QueryRow(ctx, `
SELECT scope_id, activation_epoch, mode, baseline_bundle_digest, live_rollout_id
FROM raw.policy_scopes
WHERE scope_id = $1
FOR UPDATE`, string(id)).Scan(&snapshot.ScopeID, &snapshot.ActivationEpoch, &mode, &baseline, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.ScopeSnapshot{}, ErrScopeNotFound
	}
	if err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q: %w", id, err)
	}
	snapshot.Mode = domain.ScopeMode(mode)
	if err := snapshot.Mode.Validate(); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q mode: %w", id, err)
	}
	if baseline.Valid {
		digest := domain.Digest(baseline.String)
		if err := digest.Validate(); err != nil {
			return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q baseline: %w", id, err)
		}
		snapshot.BaselineBundle = &digest
	}
	if live.Valid {
		rolloutID := domain.RolloutID(live.String)
		if err := rolloutID.Validate(); err != nil {
			return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q live rollout: %w", id, err)
		}
		snapshot.LiveRolloutID = &rolloutID
	}

	// A shared lock makes the snapshot stable against Emergency Stop's exclusive
	// singleton epoch update without serializing independent Scope transactions.
	if err := g.tx.QueryRow(ctx, `
SELECT security_epoch
FROM raw.security_generation
WHERE singleton_id = true
FOR SHARE`).Scan(&snapshot.SecurityEpoch); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("read/lock global security epoch: %w", err)
	}

	snapshot.Roots = make(map[domain.RootID]domain.RootAuthority)
	rows, err := g.tx.Query(ctx, `
SELECT root_id, authorization_epoch, effective_bundle_digest, safe_baseline
FROM raw.roots
WHERE scope_id = $1
ORDER BY root_id`, string(id))
	if err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("read roots for scope %q: %w", id, err)
	}
	for rows.Next() {
		var rootID string
		var epoch domain.Epoch
		var digest pgtype.Text
		var safeBaseline bool
		if err := rows.Scan(&rootID, &epoch, &digest, &safeBaseline); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("scan root for scope %q: %w", id, err)
		}
		id := domain.RootID(rootID)
		if err := id.Validate(); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("invalid root identifier: %w", err)
		}
		binding := domain.PolicyBinding{SafeBaseline: safeBaseline}
		if digest.Valid {
			binding.Digest = domain.Digest(digest.String)
		}
		if err := binding.Validate(); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("root %q policy binding: %w", id, err)
		}
		snapshot.Roots[id] = domain.RootAuthority{Policy: binding, AuthorizationEpoch: epoch}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return port.ScopeSnapshot{}, fmt.Errorf("iterate roots for scope %q: %w", id, err)
	}
	rows.Close()
	if len(snapshot.Roots) == 0 {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q: %w", id, domain.ErrRootNotFound)
	}

	g.lockedScopes[id] = cloneScope(snapshot)
	return cloneScope(snapshot), nil
}

func (g *governanceTx) LockRollout(ctx context.Context, scopeID domain.ScopeID, rolloutID domain.RolloutID) (port.RolloutSnapshot, error) {
	if _, ok := g.lockedScopes[scopeID]; !ok {
		return port.RolloutSnapshot{}, ErrScopeNotLocked
	}
	if err := rolloutID.Validate(); err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("lock rollout: %w", err)
	}
	key := rolloutKey{scope: scopeID, rollout: rolloutID}
	if snapshot, ok := g.lockedRollouts[key]; ok {
		return cloneRollout(snapshot), nil
	}
	if g.validatedScopes[scopeID] {
		return port.RolloutSnapshot{}, errors.New("lock order violation: rollout must be locked before target Roots")
	}

	var snapshot port.RolloutSnapshot
	var state string
	var target, rollbackFrom pgtype.Text
	err := g.tx.QueryRow(ctx, `
SELECT rollout_id, scope_id, state, target_root_id, base_activation_epoch,
       last_activation_epoch, base_security_epoch, rollback_from
FROM raw.policy_rollouts
WHERE scope_id = $1 AND rollout_id = $2
FOR UPDATE`, string(scopeID), string(rolloutID)).Scan(
		&snapshot.ID, &snapshot.Scope, &state, &target, &snapshot.BaseActivationEpoch,
		&snapshot.LastActivationEpoch, &snapshot.BaseSecurityEpoch, &rollbackFrom)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.RolloutSnapshot{}, ErrRolloutNotFound
	}
	if err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("lock rollout %q: %w", rolloutID, err)
	}
	snapshot.State = domain.RolloutState(state)
	if err := snapshot.State.Validate(); err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("rollout %q state: %w", rolloutID, err)
	}
	if snapshot.ID != rolloutID || snapshot.Scope != scopeID {
		return port.RolloutSnapshot{}, fmt.Errorf("rollout %q returned mismatched identity", rolloutID)
	}
	if target.Valid {
		rootID := domain.RootID(target.String)
		if err := rootID.Validate(); err != nil {
			return port.RolloutSnapshot{}, fmt.Errorf("rollout %q target root: %w", rolloutID, err)
		}
		snapshot.TargetRoot = &rootID
	}
	if rollbackFrom.Valid {
		state := domain.RolloutState(rollbackFrom.String)
		if err := state.Validate(); err != nil {
			return port.RolloutSnapshot{}, fmt.Errorf("rollout %q rollback origin: %w", rolloutID, err)
		}
		snapshot.RollbackFrom = &state
	}

	snapshot.Targets = make(map[domain.RootID]port.RolloutTargetSnapshot)
	rows, err := g.tx.Query(ctx, `
SELECT root_id, baseline_bundle_digest, candidate_bundle_digest, base_root_epoch
FROM raw.rollout_targets
WHERE scope_id = $1 AND rollout_id = $2
ORDER BY root_id
FOR UPDATE`, string(scopeID), string(rolloutID))
	if err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("lock targets for rollout %q: %w", rolloutID, err)
	}
	for rows.Next() {
		var rootString string
		var baseline, candidate pgtype.Text
		var epoch domain.Epoch
		if err := rows.Scan(&rootString, &baseline, &candidate, &epoch); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("scan target for rollout %q: %w", rolloutID, err)
		}
		rootID := domain.RootID(rootString)
		if err := rootID.Validate(); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("invalid target root: %w", err)
		}
		baseBinding := domain.PolicyBinding{SafeBaseline: !baseline.Valid}
		if baseline.Valid {
			baseBinding.Digest = domain.Digest(baseline.String)
		}
		candidateDigest := domain.Digest(candidate.String)
		candidateBinding := domain.PolicyBinding{Digest: candidateDigest}
		if err := baseBinding.Validate(); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("target %q baseline: %w", rootID, err)
		}
		if err := candidateBinding.Validate(); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("target %q candidate: %w", rootID, err)
		}
		snapshot.Targets[rootID] = port.RolloutTargetSnapshot{Baseline: baseBinding, Candidate: candidateBinding, BaseRootEpoch: epoch}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return port.RolloutSnapshot{}, fmt.Errorf("iterate targets for rollout %q: %w", rolloutID, err)
	}
	rows.Close()
	if len(snapshot.Targets) == 0 {
		return port.RolloutSnapshot{}, fmt.Errorf("rollout %q has no targets", rolloutID)
	}

	g.lockedRollouts[key] = cloneRollout(snapshot)
	return cloneRollout(snapshot), nil
}

func (g *governanceTx) ValidateTargets(ctx context.Context, scopeID domain.ScopeID, targets []domain.RootID) error {
	if _, ok := g.lockedScopes[scopeID]; !ok {
		return ErrScopeNotLocked
	}
	if len(targets) == 0 {
		return errors.New("validate targets: at least one Root is required")
	}
	seen := make(map[domain.RootID]struct{}, len(targets))
	for _, id := range targets {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("validate target Root: %w", err)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate target Root %q", id)
		}
		seen[id] = struct{}{}
	}
	rows, err := g.tx.Query(ctx, `
SELECT root_id
FROM raw.roots
WHERE scope_id = $1
ORDER BY root_id
FOR UPDATE`, string(scopeID))
	if err != nil {
		return fmt.Errorf("validate targets for scope %q: %w", scopeID, err)
	}
	found := make(map[domain.RootID]struct{}, len(targets))
	for rows.Next() {
		var rawID string
		if err := rows.Scan(&rawID); err != nil {
			rows.Close()
			return fmt.Errorf("scan validated target: %w", err)
		}
		found[domain.RootID(rawID)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate validated targets: %w", err)
	}
	rows.Close()
	for id := range seen {
		if _, ok := found[id]; !ok {
			return fmt.Errorf("Root %q does not belong to Scope %q", id, scopeID)
		}
	}
	if len(found) == 0 {
		return fmt.Errorf("one or more Roots do not belong to Scope %q", scopeID)
	}
	g.validatedScopes[scopeID] = true
	return nil
}

func (g *governanceTx) CompareAndSwapScope(ctx context.Context, expected, next port.ScopeSnapshot) error {
	if !g.validatedScopes[expected.ScopeID] {
		return ErrTargetsNotLocked
	}
	if expected.LiveRolloutID != nil {
		key := rolloutKey{scope: expected.ScopeID, rollout: *expected.LiveRolloutID}
		if _, ok := g.lockedRollouts[key]; !ok {
			return ErrRolloutNotLocked
		}
	}
	locked, ok := g.lockedScopes[expected.ScopeID]
	if !ok || !reflect.DeepEqual(locked, expected) {
		return port.ErrStaleWrite
	}
	if expected.ScopeID != next.ScopeID || expected.SecurityEpoch != next.SecurityEpoch {
		return fmt.Errorf("scope CAS cannot change identity or global Security Epoch")
	}
	if err := validateScopeSnapshot(next); err != nil {
		return err
	}
	if next.ActivationEpoch < expected.ActivationEpoch || !sameRootIDs(expected.Roots, next.Roots) {
		return port.ErrStaleWrite
	}
	command, err := g.tx.Exec(ctx, `
UPDATE raw.policy_scopes
SET activation_epoch = $1, mode = $2, baseline_bundle_digest = $3,
    live_rollout_id = $4, updated_at = clock_timestamp()
WHERE scope_id = $5 AND activation_epoch = $6 AND mode = $7
  AND baseline_bundle_digest IS NOT DISTINCT FROM $8
  AND live_rollout_id IS NOT DISTINCT FROM $9
  AND EXISTS (SELECT 1 FROM raw.security_generation
              WHERE singleton_id = true AND security_epoch = $10)`,
		next.ActivationEpoch, string(next.Mode), nullableDigest(next.BaselineBundle), nullableRolloutID(next.LiveRolloutID),
		string(expected.ScopeID), expected.ActivationEpoch, string(expected.Mode), nullableDigest(expected.BaselineBundle),
		nullableRolloutID(expected.LiveRolloutID), expected.SecurityEpoch)
	if err != nil {
		return fmt.Errorf("CAS Scope %q: %w", expected.ScopeID, err)
	}
	if command.RowsAffected() != 1 {
		return port.ErrStaleWrite
	}

	for _, rootID := range sortedRootIDs(expected.Roots) {
		oldRoot, newRoot := expected.Roots[rootID], next.Roots[rootID]
		if newRoot.AuthorizationEpoch < oldRoot.AuthorizationEpoch {
			return port.ErrStaleWrite
		}
		command, err := g.tx.Exec(ctx, `
UPDATE raw.roots
SET authorization_epoch = $1, effective_bundle_digest = $2,
    safe_baseline = $3, updated_at = clock_timestamp()
WHERE root_id = $4 AND scope_id = $5 AND authorization_epoch = $6
  AND effective_bundle_digest IS NOT DISTINCT FROM $7 AND safe_baseline = $8`,
			newRoot.AuthorizationEpoch, nullablePolicyDigest(newRoot.Policy), newRoot.Policy.SafeBaseline,
			string(rootID), string(expected.ScopeID), oldRoot.AuthorizationEpoch,
			nullablePolicyDigest(oldRoot.Policy), oldRoot.Policy.SafeBaseline)
		if err != nil {
			return fmt.Errorf("CAS Root %q in Scope %q: %w", rootID, expected.ScopeID, err)
		}
		if command.RowsAffected() != 1 {
			return port.ErrStaleWrite
		}
	}
	g.lockedScopes[next.ScopeID] = cloneScope(next)
	return nil
}

func (g *governanceTx) CompareAndSwapRollout(ctx context.Context, expected, next port.RolloutSnapshot) error {
	key := rolloutKey{scope: expected.Scope, rollout: expected.ID}
	locked, ok := g.lockedRollouts[key]
	if !ok || !reflect.DeepEqual(locked, expected) {
		return port.ErrStaleWrite
	}
	if expected.ID != next.ID || expected.Scope != next.Scope || expected.BaseActivationEpoch != next.BaseActivationEpoch ||
		expected.BaseSecurityEpoch != next.BaseSecurityEpoch || !sameTargetIDs(expected.Targets, next.Targets) {
		return port.ErrStaleWrite
	}
	if err := validateRolloutSnapshot(next); err != nil {
		return err
	}
	if next.LastActivationEpoch < expected.LastActivationEpoch {
		return port.ErrStaleWrite
	}
	command, err := g.tx.Exec(ctx, `
UPDATE raw.policy_rollouts
SET state = $1, target_root_id = $2, last_activation_epoch = $3,
    rollback_from = $4, updated_at = clock_timestamp()
WHERE rollout_id = $5 AND scope_id = $6 AND state = $7
  AND base_activation_epoch = $8 AND last_activation_epoch = $9
  AND base_security_epoch = $10 AND target_root_id IS NOT DISTINCT FROM $11
  AND rollback_from IS NOT DISTINCT FROM $12`,
		string(next.State), nullableRootID(next.TargetRoot), next.LastActivationEpoch,
		nullableRolloutState(next.RollbackFrom), string(expected.ID), string(expected.Scope),
		string(expected.State), expected.BaseActivationEpoch, expected.LastActivationEpoch,
		expected.BaseSecurityEpoch, nullableRootID(expected.TargetRoot), nullableRolloutState(expected.RollbackFrom))
	if err != nil {
		return fmt.Errorf("CAS Rollout %q: %w", expected.ID, err)
	}
	if command.RowsAffected() != 1 {
		return port.ErrStaleWrite
	}
	for _, rootID := range sortedTargetIDs(expected.Targets) {
		oldTarget, newTarget := expected.Targets[rootID], next.Targets[rootID]
		command, err := g.tx.Exec(ctx, `
UPDATE raw.rollout_targets
SET baseline_bundle_digest = $1, candidate_bundle_digest = $2, base_root_epoch = $3, updated_at = clock_timestamp()
WHERE rollout_id = $4 AND scope_id = $5 AND root_id = $6
  AND baseline_bundle_digest IS NOT DISTINCT FROM $7
  AND candidate_bundle_digest = $8 AND base_root_epoch = $9`,
			nullablePolicyDigest(newTarget.Baseline), nullablePolicyDigest(newTarget.Candidate), newTarget.BaseRootEpoch,
			string(expected.ID), string(expected.Scope), string(rootID), nullablePolicyDigest(oldTarget.Baseline),
			string(oldTarget.Candidate.Digest), oldTarget.BaseRootEpoch)
		if err != nil {
			return fmt.Errorf("CAS rollout target Root %q: %w", rootID, err)
		}
		if command.RowsAffected() != 1 {
			return port.ErrStaleWrite
		}
	}
	g.lockedRollouts[key] = cloneRollout(next)
	return nil
}

func (g *governanceTx) CompareAndSwapSecurityEpoch(ctx context.Context, expected, next domain.Epoch) error {
	want, err := expected.Next()
	if err != nil {
		return fmt.Errorf("advance Security Epoch: %w", err)
	}
	if next != want {
		return errors.New("Security Epoch must advance exactly once")
	}
	command, err := g.tx.Exec(ctx, `
UPDATE raw.security_generation
SET security_epoch = $1, updated_at = clock_timestamp()
WHERE singleton_id = true AND security_epoch = $2`, next, expected)
	if err != nil {
		return fmt.Errorf("CAS global Security Epoch: %w", err)
	}
	if command.RowsAffected() != 1 {
		return port.ErrStaleWrite
	}
	return nil
}

func validateScopeSnapshot(snapshot port.ScopeSnapshot) error {
	if err := snapshot.ScopeID.Validate(); err != nil {
		return err
	}
	if err := snapshot.Mode.Validate(); err != nil {
		return err
	}
	if snapshot.BaselineBundle != nil {
		if err := snapshot.BaselineBundle.Validate(); err != nil {
			return err
		}
	}
	if snapshot.LiveRolloutID != nil {
		if err := snapshot.LiveRolloutID.Validate(); err != nil {
			return err
		}
	}
	for id, root := range snapshot.Roots {
		if err := id.Validate(); err != nil {
			return err
		}
		if err := root.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateRolloutSnapshot(snapshot port.RolloutSnapshot) error {
	if err := snapshot.ID.Validate(); err != nil {
		return err
	}
	if err := snapshot.Scope.Validate(); err != nil {
		return err
	}
	if err := snapshot.State.Validate(); err != nil {
		return err
	}
	if snapshot.TargetRoot != nil {
		if err := snapshot.TargetRoot.Validate(); err != nil {
			return err
		}
	}
	if snapshot.State == domain.RolloutRollingBack {
		if snapshot.RollbackFrom == nil || (*snapshot.RollbackFrom != domain.RolloutCanary && *snapshot.RollbackFrom != domain.RolloutMonitoring) {
			return fmt.Errorf("ROLLING_BACK rollout requires a valid rollback origin")
		}
	} else if snapshot.RollbackFrom != nil {
		return fmt.Errorf("non-rollback rollout must not have rollback origin")
	}
	for id, target := range snapshot.Targets {
		if err := id.Validate(); err != nil {
			return err
		}
		if err := target.Baseline.Validate(); err != nil {
			return err
		}
		if err := target.Candidate.Validate(); err != nil || target.Candidate.SafeBaseline {
			return fmt.Errorf("invalid rollout candidate for Root %q", id)
		}
	}
	return nil
}

func nullableDigest(d *domain.Digest) any {
	if d == nil {
		return nil
	}
	return string(*d)
}
func nullablePolicyDigest(p domain.PolicyBinding) any {
	if p.SafeBaseline {
		return nil
	}
	return string(p.Digest)
}
func nullableRolloutID(id *domain.RolloutID) any {
	if id == nil {
		return nil
	}
	return string(*id)
}
func nullableRootID(id *domain.RootID) any {
	if id == nil {
		return nil
	}
	return string(*id)
}
func nullableRolloutState(state *domain.RolloutState) any {
	if state == nil {
		return nil
	}
	return string(*state)
}
func sameRootIDs(a, b map[domain.RootID]domain.RootAuthority) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}
func sameTargetIDs(a, b map[domain.RootID]port.RolloutTargetSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}
func sortedRootIDs(m map[domain.RootID]domain.RootAuthority) []domain.RootID {
	ids := make([]domain.RootID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
func sortedTargetIDs(m map[domain.RootID]port.RolloutTargetSnapshot) []domain.RootID {
	ids := make([]domain.RootID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
func cloneScope(snapshot port.ScopeSnapshot) port.ScopeSnapshot {
	out := snapshot
	if snapshot.BaselineBundle != nil {
		value := *snapshot.BaselineBundle
		out.BaselineBundle = &value
	}
	if snapshot.LiveRolloutID != nil {
		value := *snapshot.LiveRolloutID
		out.LiveRolloutID = &value
	}
	out.Roots = make(map[domain.RootID]domain.RootAuthority, len(snapshot.Roots))
	for id, root := range snapshot.Roots {
		out.Roots[id] = root
	}
	return out
}
func cloneRollout(snapshot port.RolloutSnapshot) port.RolloutSnapshot {
	out := snapshot
	if snapshot.TargetRoot != nil {
		value := *snapshot.TargetRoot
		out.TargetRoot = &value
	}
	if snapshot.RollbackFrom != nil {
		value := *snapshot.RollbackFrom
		out.RollbackFrom = &value
	}
	out.Targets = make(map[domain.RootID]port.RolloutTargetSnapshot, len(snapshot.Targets))
	for id, target := range snapshot.Targets {
		out.Targets[id] = target
	}
	return out
}
