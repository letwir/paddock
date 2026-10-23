package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SafetyService persists quorum-authorized safety transitions using one
// GovernanceTx. Completed state and command receipt are persisted atomically.
type SafetyService struct {
	transactor port.Transactor
	quorum     domain.SafetyQuorum
}

func safetyRequestDigest(action domain.SafetyAction, scope domain.ScopeID, epoch domain.Epoch, id, nonce string, activation *[32]byte, signatures []domain.SafetySignature) (domain.Digest, error) {
	v := struct {
		Action     domain.SafetyAction `json:"action"`
		Scope      domain.ScopeID      `json:"scope"`
		Epoch      domain.Epoch        `json:"expected_security_epoch"`
		CommandID  string              `json:"command_id"`
		Activation *string             `json:"activation_digest,omitempty"`
		Signatures []struct {
			ID        string `json:"signer_id"`
			Signature []byte `json:"signature"`
		} `json:"approvals"`
	}{Action: action, Scope: scope, Epoch: epoch, CommandID: id}
	if activation != nil {
		d := hex.EncodeToString(activation[:])
		v.Activation = &d
	}
	for _, sig := range signatures {
		v.Signatures = append(v.Signatures, struct {
			ID        string `json:"signer_id"`
			Signature []byte `json:"signature"`
		}{sig.SignerID, append([]byte(nil), sig.Signature...)})
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	request, err := domain.NewCanonicalRequest(id, nonce, payload)
	if err != nil {
		return "", err
	}
	return request.Digest(), nil
}
func saveReceipt(ctx context.Context, tx port.GovernanceTx, id string, digest domain.Digest, result domain.SafetyTransitionResult) error {
	b, err := marshalCommandResult(result)
	if err != nil {
		return err
	}
	return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: id, RequestDigest: digest, Status: "SUCCEEDED", Response: b})
}
func reconcileReceipt(response []byte, commandID string, current domain.AuthorityState, out *domain.SafetyTransitionResult) error {
	var recorded domain.SafetyTransitionResult
	if err := unmarshalCommandResult(response, &recorded); err != nil || recorded.CommandID != commandID || recorded.State.Validate() != nil {
		return errors.New("malformed safety command receipt response")
	}
	d1, e1 := domain.ActivationDigest(current)
	d2, e2 := domain.ActivationDigest(recorded.State)
	if e1 != nil || e2 != nil || d1 != d2 {
		return errors.New("safety command receipt is superseded by current persisted state")
	}
	*out = recorded
	return nil
}

func NewSafetyService(transactor port.Transactor, quorum domain.SafetyQuorum) *SafetyService {
	return &SafetyService{transactor: transactor, quorum: quorum}
}

type HoldExtendRequest struct {
	CommandID, Nonce         string
	Scope                    domain.ScopeID
	Rollout                  domain.RolloutID
	ExpectedSecurityEpoch    domain.Epoch
	ExpectedDecisionRevision int64
	Signatures               []domain.SafetySignature
}

// HoldExtend verifies revision-bound human approval against the locked current
// HOLD. Expired/stale approvals cannot revive a rollout; expiry processing belongs
// to MonitoringService/Reaper's safe-only exit, not this authorization command.
func (s *SafetyService) HoldExtend(ctx context.Context, q HoldExtendRequest) (MonitoringResult, error) {
	if err := s.ready(ctx); err != nil {
		return MonitoringResult{}, err
	}
	payload := struct {
		Action        domain.SafetyAction
		Scope         domain.ScopeID
		Rollout       domain.RolloutID
		SecurityEpoch domain.Epoch
		Revision      string
		Signatures    []domain.SafetySignature
	}{domain.SafetyActionHoldExtend, q.Scope, q.Rollout, q.ExpectedSecurityEpoch, strconv.FormatInt(q.ExpectedDecisionRevision, 10), q.Signatures}
	digest, err := commandDigest(q.CommandID, q.Nonce, payload)
	if err != nil {
		return MonitoringResult{}, normalizeCommandFailure(fmt.Errorf("prepare HOLD_EXTEND %s/%s: %w", q.Scope, q.Rollout, err))
	}
	var result MonitoringResult
	err = withinReceiptCommand(ctx, q.CommandID, digest, s.transactor.WithinTransaction,
		func(_ port.GovernanceTx, b []byte) error { return unmarshalCommandResult(b, &result) },
		func(tx port.GovernanceTx) error {
			sn, r, ro, err := lockMonitoring(ctx, tx, q.Scope, q.Rollout)
			if err != nil {
				return err
			}
			if sn.SecurityEpoch != q.ExpectedSecurityEpoch || r.Monitoring.DecisionRevision != q.ExpectedDecisionRevision {
				return port.ErrStaleWrite
			}
			now, err := tx.DatabaseTime(ctx)
			if err != nil {
				return err
			}
			next, err := s.quorum.HoldExtend(snapshotAuthority(sn), ro, q.ExpectedSecurityEpoch, q.CommandID, q.Nonce, domain.MonitoringExtendedCap, q.Signatures, now)
			if err != nil {
				return denyReceipt(err)
			}
			nr := rolloutSnapshot(next, r, sn)
			if err = tx.CompareAndSwapRollout(ctx, r, nr); err != nil {
				return err
			}
			result = monitoringResult(q.CommandID, sn, nr, domain.MonitoringContinue)
			if err = appendMonitoringEvent(ctx, tx, result, "rollout-hold-extension", "MonitoringHoldExtended", 1); err != nil {
				return err
			}
			b, err := marshalCommandResult(result)
			if err != nil {
				return err
			}
			return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: q.CommandID, RequestDigest: digest, Status: "SUCCEEDED", Response: b})
		})
	if err != nil {
		return MonitoringResult{}, normalizeCommandFailure(fmt.Errorf("HOLD_EXTEND %s/%s: %w", q.Scope, q.Rollout, err))
	}
	return result, nil
}

func (s *SafetyService) Stop(ctx context.Context, scopeID domain.ScopeID, expectedSecurityEpoch domain.Epoch, commandID, nonce string, signatures []domain.SafetySignature) (domain.SafetyTransitionResult, error) {
	if err := s.ready(ctx); err != nil {
		return domain.SafetyTransitionResult{}, err
	}
	digest, err := safetyRequestDigest(domain.SafetyActionStop, scopeID, expectedSecurityEpoch, commandID, nonce, nil, signatures)
	if err != nil {
		return domain.SafetyTransitionResult{}, normalizeCommandFailure(err)
	}
	var result domain.SafetyTransitionResult
	err = withinReceiptCommand(ctx, commandID, digest, s.transactor.WithinTransaction,
		func(tx port.GovernanceTx, b []byte) error {
			current, err := lockAuthority(ctx, tx, scopeID)
			if err != nil {
				return err
			}
			return reconcileReceipt(b, commandID, snapshotAuthority(current), &result)
		}, func(tx port.GovernanceTx) error {
			if err := scopeID.Validate(); err != nil {
				return denyReceipt(err)
			}
			current, err := lockAuthority(ctx, tx, scopeID)
			if err != nil {
				return err
			}
			stopped, err := s.quorum.Stop(snapshotAuthority(current), scopeID, expectedSecurityEpoch, commandID, nonce, signatures)
			if err != nil {
				return denyReceipt(err)
			}
			next := snapshotWithState(current, stopped.State)
			if err := tx.CompareAndSwapScope(ctx, current, next); err != nil {
				return err
			}
			if err := tx.CompareAndSwapSecurityEpoch(ctx, expectedSecurityEpoch, stopped.State.SecurityEpoch); err != nil {
				return err
			}
			if err := saveReceipt(ctx, tx, commandID, digest, stopped); err != nil {
				return err
			}
			if err := appendSafetyEvent(ctx, tx, domain.SafetyActionStop, commandID, current, next, stopped.State); err != nil {
				return err
			}
			result = stopped
			return nil
		})
	if err != nil {
		return domain.SafetyTransitionResult{}, normalizeCommandFailure(err)
	}
	return result, nil
}

func (s *SafetyService) Release(ctx context.Context, scopeID domain.ScopeID, expectedSecurityEpoch domain.Epoch, commandID, nonce string, proposedActivation domain.AuthorityState, signatures []domain.SafetySignature) (domain.SafetyTransitionResult, error) {
	if err := s.ready(ctx); err != nil {
		return domain.SafetyTransitionResult{}, err
	}
	activation := cloneState(proposedActivation)
	activationDigest, err := domain.ActivationDigest(activation)
	if err != nil {
		// A malformed activation cannot have a signing digest, but its complete
		// submitted value still binds a deterministic rejection to this ID. This
		// projection is used only for rejection, never for quorum authorization.
		invalidActivation := err
		digest, digestErr := commandDigest(commandID, nonce, struct {
			Action     domain.SafetyAction
			Scope      domain.ScopeID
			Epoch      domain.Epoch
			Activation domain.AuthorityState
			Signatures []domain.SafetySignature
		}{domain.SafetyActionRelease, scopeID, expectedSecurityEpoch, activation, signatures})
		if digestErr != nil {
			return domain.SafetyTransitionResult{}, normalizeCommandFailure(digestErr)
		}
		err = withinReceiptCommand(ctx, commandID, digest, s.transactor.WithinTransaction,
			func(port.GovernanceTx, []byte) error {
				return errors.New("invalid activation has a successful receipt")
			},
			func(port.GovernanceTx) error { return denyReceipt(invalidActivation) })
		return domain.SafetyTransitionResult{}, normalizeCommandFailure(err)
	}
	digest, err := safetyRequestDigest(domain.SafetyActionRelease, scopeID, expectedSecurityEpoch, commandID, nonce, &activationDigest, signatures)
	if err != nil {
		return domain.SafetyTransitionResult{}, normalizeCommandFailure(err)
	}
	var result domain.SafetyTransitionResult
	err = withinReceiptCommand(ctx, commandID, digest, s.transactor.WithinTransaction,
		func(tx port.GovernanceTx, b []byte) error {
			current, err := lockAuthority(ctx, tx, scopeID)
			if err != nil {
				return err
			}
			return reconcileReceipt(b, commandID, snapshotAuthority(current), &result)
		}, func(tx port.GovernanceTx) error {
			if err := scopeID.Validate(); err != nil {
				return denyReceipt(err)
			}
			current, err := lockAuthority(ctx, tx, scopeID)
			if err != nil {
				return err
			}
			released, err := s.quorum.Release(snapshotAuthority(current), activation, scopeID, expectedSecurityEpoch, commandID, nonce, signatures)
			if err != nil {
				return denyReceipt(err)
			}
			// Release advances Scope Activation Epoch exactly once; quorum validates
			// the complete signed activation and the next global Security Epoch.
			currentState := snapshotAuthority(current)
			nextActivation, err := currentState.ScopeActivationEpoch.Next()
			if err != nil {
				return err
			}
			if released.State.ScopeActivationEpoch != nextActivation {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			next := snapshotWithState(current, released.State)
			if err := tx.CompareAndSwapScope(ctx, current, next); err != nil {
				return err
			}
			if err := tx.CompareAndSwapSecurityEpoch(ctx, expectedSecurityEpoch, released.State.SecurityEpoch); err != nil {
				return err
			}
			if err := saveReceipt(ctx, tx, commandID, digest, released); err != nil {
				return err
			}
			if err := appendSafetyEvent(ctx, tx, domain.SafetyActionRelease, commandID, current, next, released.State); err != nil {
				return err
			}
			result = released
			return nil
		})
	if err != nil {
		return domain.SafetyTransitionResult{}, normalizeCommandFailure(err)
	}
	return result, nil
}

func (s *SafetyService) ready(ctx context.Context) error {
	if s == nil || s.transactor == nil {
		return errors.New("safety service is not initialized")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	return ctx.Err()
}

func appendSafetyEvent(ctx context.Context, tx port.GovernanceTx, action domain.SafetyAction, commandID string, current, next port.ScopeSnapshot, transition domain.AuthorityState) error {
	if current.ScopeID == "" || current.ScopeID != next.ScopeID || transition.Scope != current.ScopeID || transition.ScopeActivationEpoch != next.ActivationEpoch {
		return errors.New("append safety event: scope identity mismatch")
	}
	wantSecurityEpoch, err := current.SecurityEpoch.Next()
	if err != nil || transition.SecurityEpoch != wantSecurityEpoch {
		return errors.New("append safety event: security epoch is not the next generation")
	}

	var eventType string
	switch action {
	case domain.SafetyActionStop:
		eventType = "SafetyStopped"
		if transition.ScopeActivationEpoch != current.ActivationEpoch {
			return errors.New("append safety event: stop changed scope activation epoch")
		}
	case domain.SafetyActionRelease:
		eventType = "SafetyReleased"
		wantActivationEpoch, err := current.ActivationEpoch.Next()
		if err != nil || transition.ScopeActivationEpoch != wantActivationEpoch {
			return errors.New("append safety event: release did not advance scope activation epoch")
		}
	default:
		return fmt.Errorf("append safety event: unsupported action %q", action)
	}
	if transition.SecurityEpoch > domain.Epoch(1<<63-1) {
		return errors.New("append safety event: security epoch exceeds PostgreSQL bigint range")
	}

	payload, err := json.Marshal(struct {
		PreviousScopeActivationEpoch domain.Epoch `json:"previous_scope_activation_epoch"`
		ScopeActivationEpoch         domain.Epoch `json:"scope_activation_epoch"`
		PreviousSecurityEpoch        domain.Epoch `json:"previous_security_epoch"`
		SecurityEpoch                domain.Epoch `json:"security_epoch"`
	}{
		PreviousScopeActivationEpoch: current.ActivationEpoch,
		ScopeActivationEpoch:         transition.ScopeActivationEpoch,
		PreviousSecurityEpoch:        current.SecurityEpoch,
		SecurityEpoch:                transition.SecurityEpoch,
	})
	if err != nil {
		return fmt.Errorf("append safety event: encode minimal metadata: %w", err)
	}
	event, err := domain.NewEvent(
		"safety/"+commandID,
		"scope",
		string(next.ScopeID),
		int64(transition.SecurityEpoch),
		eventType,
		"paddock.safety-event/1",
		payload,
	)
	if err != nil {
		return fmt.Errorf("append safety event: build event envelope: %w", err)
	}
	if err := tx.AppendEvent(ctx, event); err != nil {
		return fmt.Errorf("append safety event: %w", err)
	}
	return nil
}

func lockAuthority(ctx context.Context, tx port.GovernanceTx, scopeID domain.ScopeID) (port.ScopeSnapshot, error) {
	if tx == nil {
		return port.ScopeSnapshot{}, errors.New("nil governance transaction")
	}
	if err := scopeID.Validate(); err != nil {
		return port.ScopeSnapshot{}, err
	}
	snapshot, err := tx.LockScope(ctx, scopeID)
	if err != nil {
		return port.ScopeSnapshot{}, err
	}
	if snapshot.ScopeID != scopeID {
		return port.ScopeSnapshot{}, fmt.Errorf("malformed scope snapshot: identity mismatch")
	}
	if snapshot.LiveRolloutID != nil {
		rollout, err := tx.LockRollout(ctx, scopeID, *snapshot.LiveRolloutID)
		if err != nil {
			return port.ScopeSnapshot{}, err
		}
		if rollout.ID != *snapshot.LiveRolloutID || rollout.Scope != scopeID {
			return port.ScopeSnapshot{}, errors.New("malformed rollout snapshot: identity mismatch")
		}
	}
	if err := snapshotAuthority(snapshot).Validate(); err != nil {
		return port.ScopeSnapshot{}, fmt.Errorf("malformed authority snapshot: %w", err)
	}
	ids := make([]domain.RootID, 0, len(snapshot.Roots))
	for id := range snapshot.Roots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) == 0 {
		return port.ScopeSnapshot{}, errors.New("malformed authority snapshot: no Roots")
	}
	if err := tx.ValidateTargets(ctx, scopeID, ids); err != nil {
		return port.ScopeSnapshot{}, err
	}
	return snapshot, nil
}

func snapshotAuthority(s port.ScopeSnapshot) domain.AuthorityState {
	return domain.AuthorityState{Scope: s.ScopeID, ScopeActivationEpoch: s.ActivationEpoch, SecurityEpoch: s.SecurityEpoch, Mode: s.Mode, DatabaseAvailable: true, Roots: s.Roots}
}

func snapshotWithState(old port.ScopeSnapshot, state domain.AuthorityState) port.ScopeSnapshot {
	next := old
	next.ActivationEpoch = state.ScopeActivationEpoch
	next.Mode = state.Mode
	next.SecurityEpoch = old.SecurityEpoch // Security Epoch has its own global CAS.
	next.Roots = make(map[domain.RootID]domain.RootAuthority, len(state.Roots))
	for id, root := range state.Roots {
		next.Roots[id] = root
	}
	return next
}

func cloneState(s domain.AuthorityState) domain.AuthorityState {
	out := s
	out.Roots = make(map[domain.RootID]domain.RootAuthority, len(s.Roots))
	for id, root := range s.Roots {
		out.Roots[id] = root
	}
	return out
}
