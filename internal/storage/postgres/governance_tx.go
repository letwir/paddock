package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
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

// InsertPolicyBundle stores the canonical bundle envelope and externally
// supplied signature in the current transaction. It does not verify or create
// signatures.
func (g *governanceTx) InsertPolicyBundle(ctx context.Context, bundle domain.CanonicalBundle, signerKeyID string, signature []byte) error {
	if err := bundle.Validate(); err != nil {
		return fmt.Errorf("insert policy bundle: invalid bundle: %w", err)
	}
	if signerKeyID == "" || strings.TrimSpace(signerKeyID) != signerKeyID {
		return errors.New("insert policy bundle: signer key ID must be nonempty and trimmed")
	}
	if len(signature) == 0 {
		return errors.New("insert policy bundle: signature must be nonempty")
	}
	_, err := g.tx.Exec(ctx, `INSERT INTO raw.policy_bundles
		(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature)
		VALUES ($1, $2, $3, $4, $5)`,
		string(bundle.Digest()), bundle.CanonicalBytes(), bundle.SchemaVersion(), signerKeyID, append([]byte(nil), signature...))
	if err != nil {
		return fmt.Errorf("insert policy bundle: %w", err)
	}
	return nil
}

// AppendEvent appends an event envelope and its dispatchable outbox row through
// the database function using the transaction bound to this GovernanceTx.
func (g *governanceTx) AppendEvent(ctx context.Context, event domain.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("append event/outbox: invalid domain event: %w", err)
	}
	payload := append([]byte(nil), event.Payload()...)
	_, err := g.tx.Exec(ctx, `SELECT raw.append_domain_event_and_outbox($1, $2, $3, $4, $5, $6, $7)`,
		event.ID(), event.AggregateKind(), event.AggregateID(), event.AggregateVersion(),
		event.Type(), event.SchemaVersion(), payload)
	if err != nil {
		return fmt.Errorf("append event/outbox: %w", err)
	}
	return nil
}

func (g *safetyGovernanceTx) LookupCommandReceipt(ctx context.Context, commandID string) (port.CommandReceipt, bool, error) {
	var r port.CommandReceipt
	var requestDigest string
	err := g.tx.QueryRow(ctx, `SELECT command_id, request_digest, status, response_bytes FROM raw.safety_lookup_command_receipt($1)`, commandID).Scan(&r.CommandID, &requestDigest, &r.Status, &r.Response)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.CommandReceipt{}, false, nil
	}
	if err != nil {
		return port.CommandReceipt{}, false, fmt.Errorf("lookup command receipt: %w", err)
	}
	r.RequestDigest, err = domain.ParseDigest(requestDigest)
	if err != nil {
		return port.CommandReceipt{}, false, fmt.Errorf("lookup command receipt: malformed request digest: %w", err)
	}
	if (r.Status != "SUCCEEDED" && r.Status != "REJECTED") || len(r.Response) == 0 {
		return port.CommandReceipt{}, false, fmt.Errorf("invalid or incomplete command receipt %q", commandID)
	}
	r.Expired = bytes.Equal(r.Response, []byte(port.ReceiptTombstoneResponse))
	return r, true, nil
}

func (g *safetyGovernanceTx) InsertCommandReceipt(ctx context.Context, r port.CommandReceipt) error {
	if r.CommandID == "" || r.RequestDigest.Validate() != nil || (r.Status != "SUCCEEDED" && r.Status != "REJECTED") || len(r.Response) == 0 || r.Expired || bytes.Equal(r.Response, []byte(port.ReceiptTombstoneResponse)) {
		return errors.New("invalid completed command receipt")
	}
	_, err := g.tx.Exec(ctx, `SELECT raw.safety_insert_command_receipt($1, $2, $3, $4)`, r.CommandID, string(r.RequestDigest), r.Status, r.Response)
	if err != nil {
		return fmt.Errorf("insert command receipt: %w", err)
	}
	return nil
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

func (g *safetyGovernanceTx) LockScope(ctx context.Context, id domain.ScopeID) (port.ScopeSnapshot, error) {
	if err := id.Validate(); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope: %w", err)
	}
	if snapshot, ok := g.lockedScopes[id]; ok {
		return cloneScope(snapshot), nil
	}

	rows, err := g.tx.Query(ctx, `SELECT * FROM raw.safety_lock_scope($1)`, string(id))
	if err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q: %w", id, err)
	}
	snapshot := port.ScopeSnapshot{Roots: make(map[domain.RootID]domain.RootAuthority)}
	var sawScope, missingRoot bool
	for rows.Next() {
		var got port.ScopeSnapshot
		var mode string
		var baseline, live, rootID, rootDigest pgtype.Text
		var rootEpoch pgtype.Int8
		var safeBaseline pgtype.Bool
		if err := rows.Scan(&got.ScopeID, &got.ActivationEpoch, &mode, &baseline, &live,
			&got.SecurityEpoch, &rootID, &rootEpoch, &rootDigest, &safeBaseline); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("scan safety Scope snapshot %q: %w", id, err)
		}
		got.Mode = domain.ScopeMode(mode)
		if !sawScope {
			if got.ScopeID != id {
				rows.Close()
				return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q: returned mismatched identity", id)
			}
			if err := got.Mode.Validate(); err != nil {
				rows.Close()
				return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q mode: %w", id, err)
			}
			if baseline.Valid {
				digest := domain.Digest(baseline.String)
				if err := digest.Validate(); err != nil {
					rows.Close()
					return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q baseline: %w", id, err)
				}
				got.BaselineBundle = &digest
			}
			if live.Valid {
				rolloutID := domain.RolloutID(live.String)
				if err := rolloutID.Validate(); err != nil {
					rows.Close()
					return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q live rollout: %w", id, err)
				}
				got.LiveRolloutID = &rolloutID
			}
			snapshot.ScopeID = got.ScopeID
			snapshot.ActivationEpoch = got.ActivationEpoch
			snapshot.Mode = got.Mode
			snapshot.BaselineBundle = got.BaselineBundle
			snapshot.LiveRolloutID = got.LiveRolloutID
			snapshot.SecurityEpoch = got.SecurityEpoch
			sawScope = true
		} else if got.ScopeID != snapshot.ScopeID || got.ActivationEpoch != snapshot.ActivationEpoch ||
			got.Mode != snapshot.Mode || got.SecurityEpoch != snapshot.SecurityEpoch {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("lock scope %q: inconsistent rows from safety API", id)
		}
		if !rootID.Valid {
			missingRoot = true
			continue
		}
		root := domain.RootID(rootID.String)
		if err := root.Validate(); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("invalid root identifier: %w", err)
		}
		if !rootEpoch.Valid || !safeBaseline.Valid {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("malformed root %q row from safety API", root)
		}
		binding := domain.PolicyBinding{SafeBaseline: safeBaseline.Bool}
		if rootDigest.Valid {
			binding.Digest = domain.Digest(rootDigest.String)
		}
		if err := binding.Validate(); err != nil {
			rows.Close()
			return port.ScopeSnapshot{}, fmt.Errorf("root %q policy binding: %w", root, err)
		}
		snapshot.Roots[root] = domain.RootAuthority{Policy: binding, AuthorizationEpoch: domain.Epoch(rootEpoch.Int64)}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return port.ScopeSnapshot{}, fmt.Errorf("iterate safety Scope snapshot %q: %w", id, err)
	}
	rows.Close()
	if !sawScope {
		return port.ScopeSnapshot{}, ErrScopeNotFound
	}
	if missingRoot || len(snapshot.Roots) == 0 {
		return port.ScopeSnapshot{}, domain.ErrRootNotFound
	}

	g.lockedScopes[id] = cloneScope(snapshot)
	return cloneScope(snapshot), nil
}

func (g *safetyGovernanceTx) LockRollout(ctx context.Context, scopeID domain.ScopeID, rolloutID domain.RolloutID) (port.RolloutSnapshot, error) {
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

	rows, err := g.tx.Query(ctx, `SELECT * FROM raw.safety_lock_rollout($1, $2)`, string(scopeID), string(rolloutID))
	if err != nil {
		return port.RolloutSnapshot{}, fmt.Errorf("lock rollout %q: %w", rolloutID, err)
	}
	snapshot := port.RolloutSnapshot{Targets: make(map[domain.RootID]port.RolloutTargetSnapshot)}
	var sawRollout bool
	for rows.Next() {
		var got port.RolloutSnapshot
		var state string
		var targetRoot, rollbackFrom, rootString, baseline, candidate pgtype.Text
		var baseEpoch pgtype.Int8
		if err := rows.Scan(&got.ID, &got.Scope, &state, &targetRoot,
			&got.BaseActivationEpoch, &got.LastActivationEpoch, &got.BaseSecurityEpoch, &rollbackFrom,
			&rootString, &baseline, &candidate, &baseEpoch); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("scan safety Rollout snapshot %q: %w", rolloutID, err)
		}
		got.State = domain.RolloutState(state)
		if !sawRollout {
			if err := got.State.Validate(); err != nil {
				rows.Close()
				return port.RolloutSnapshot{}, fmt.Errorf("rollout %q state: %w", rolloutID, err)
			}
			if got.ID != rolloutID || got.Scope != scopeID {
				rows.Close()
				return port.RolloutSnapshot{}, fmt.Errorf("rollout %q returned mismatched identity", rolloutID)
			}
			if targetRoot.Valid {
				rootID := domain.RootID(targetRoot.String)
				if err := rootID.Validate(); err != nil {
					rows.Close()
					return port.RolloutSnapshot{}, fmt.Errorf("rollout %q target root: %w", rolloutID, err)
				}
				got.TargetRoot = &rootID
			}
			if rollbackFrom.Valid {
				rollbackState := domain.RolloutState(rollbackFrom.String)
				if err := rollbackState.Validate(); err != nil {
					rows.Close()
					return port.RolloutSnapshot{}, fmt.Errorf("rollout %q rollback origin: %w", rolloutID, err)
				}
				got.RollbackFrom = &rollbackState
			}
			snapshot.ID = got.ID
			snapshot.Scope = got.Scope
			snapshot.State = got.State
			snapshot.TargetRoot = got.TargetRoot
			snapshot.BaseActivationEpoch = got.BaseActivationEpoch
			snapshot.LastActivationEpoch = got.LastActivationEpoch
			snapshot.BaseSecurityEpoch = got.BaseSecurityEpoch
			snapshot.RollbackFrom = got.RollbackFrom
			sawRollout = true
		} else if got.ID != snapshot.ID || got.Scope != snapshot.Scope || got.State != snapshot.State {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("lock rollout %q: inconsistent rows from safety API", rolloutID)
		}
		if !rootString.Valid {
			continue
		}
		rootID := domain.RootID(rootString.String)
		if err := rootID.Validate(); err != nil {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("invalid target root: %w", err)
		}
		if !baseEpoch.Valid {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("rollout target %q has no base Root epoch", rootID)
		}
		baseBinding := domain.PolicyBinding{SafeBaseline: !baseline.Valid}
		if baseline.Valid {
			baseBinding.Digest = domain.Digest(baseline.String)
		}
		if !candidate.Valid {
			rows.Close()
			return port.RolloutSnapshot{}, fmt.Errorf("rollout target %q has no candidate digest", rootID)
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
		snapshot.Targets[rootID] = port.RolloutTargetSnapshot{Baseline: baseBinding, Candidate: candidateBinding, BaseRootEpoch: domain.Epoch(baseEpoch.Int64)}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return port.RolloutSnapshot{}, fmt.Errorf("iterate safety Rollout snapshot %q: %w", rolloutID, err)
	}
	rows.Close()
	if !sawRollout {
		return port.RolloutSnapshot{}, ErrRolloutNotFound
	}
	if len(snapshot.Targets) == 0 {
		return port.RolloutSnapshot{}, fmt.Errorf("rollout %q has no targets", rolloutID)
	}

	g.lockedRollouts[key] = cloneRollout(snapshot)
	return cloneRollout(snapshot), nil
}

func (g *safetyGovernanceTx) ValidateTargets(ctx context.Context, scopeID domain.ScopeID, targets []domain.RootID) error {
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
	rows, err := g.tx.Query(ctx, `SELECT root_id FROM raw.safety_lock_scope_roots($1)`, string(scopeID))
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

func (g *safetyGovernanceTx) CompareAndSwapScope(ctx context.Context, expected, next port.ScopeSnapshot) error {
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
	var scopeUpdated bool
	err := g.tx.QueryRow(ctx, `SELECT raw.safety_cas_scope($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		string(expected.ScopeID), expected.ActivationEpoch, string(expected.Mode), nullableDigest(expected.BaselineBundle),
		nullableRolloutID(expected.LiveRolloutID), next.ActivationEpoch, string(next.Mode), nullableDigest(next.BaselineBundle),
		nullableRolloutID(next.LiveRolloutID), expected.SecurityEpoch).Scan(&scopeUpdated)
	if err != nil {
		return fmt.Errorf("CAS Scope %q: %w", expected.ScopeID, err)
	}
	if !scopeUpdated {
		return port.ErrStaleWrite
	}

	for _, rootID := range sortedRootIDs(expected.Roots) {
		oldRoot, newRoot := expected.Roots[rootID], next.Roots[rootID]
		if newRoot.AuthorizationEpoch < oldRoot.AuthorizationEpoch {
			return port.ErrStaleWrite
		}
		var rootUpdated bool
		err := g.tx.QueryRow(ctx, `SELECT raw.safety_cas_root($1, $2, $3, $4, $5, $6, $7, $8)`,
			string(rootID), string(expected.ScopeID), oldRoot.AuthorizationEpoch,
			nullablePolicyDigest(oldRoot.Policy), oldRoot.Policy.SafeBaseline,
			newRoot.AuthorizationEpoch, nullablePolicyDigest(newRoot.Policy), newRoot.Policy.SafeBaseline).Scan(&rootUpdated)
		if err != nil {
			return fmt.Errorf("CAS Root %q in Scope %q: %w", rootID, expected.ScopeID, err)
		}
		if !rootUpdated {
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

func (g *safetyGovernanceTx) CompareAndSwapSecurityEpoch(ctx context.Context, expected, next domain.Epoch) error {
	want, err := expected.Next()
	if err != nil {
		return fmt.Errorf("advance Security Epoch: %w", err)
	}
	if next != want {
		return errors.New("Security Epoch must advance exactly once")
	}
	var updated bool
	err = g.tx.QueryRow(ctx, `SELECT raw.safety_cas_security_epoch($1, $2)`, expected, next).Scan(&updated)
	if err != nil {
		return fmt.Errorf("CAS global Security Epoch: %w", err)
	}
	if !updated {
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
