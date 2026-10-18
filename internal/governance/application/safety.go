package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

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
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: id, RequestDigest: digest, Status: "SUCCEEDED", Response: b})
}
func reconcileReceipt(r port.CommandReceipt, digest domain.Digest, current domain.AuthorityState, out *domain.SafetyTransitionResult) error {
	if r.RequestDigest != digest {
		return errors.New("safety command ID already used with a different request digest")
	}
	if r.Status != "SUCCEEDED" || len(r.Response) == 0 {
		return errors.New("invalid completed safety command receipt")
	}
	var recorded domain.SafetyTransitionResult
	if err := json.Unmarshal(r.Response, &recorded); err != nil || recorded.CommandID != r.CommandID || recorded.State.Validate() != nil {
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

func (s *SafetyService) Stop(ctx context.Context, scopeID domain.ScopeID, expectedSecurityEpoch domain.Epoch, commandID, nonce string, signatures []domain.SafetySignature) (domain.SafetyTransitionResult, error) {
	if err := s.ready(ctx); err != nil {
		return domain.SafetyTransitionResult{}, err
	}
	var result domain.SafetyTransitionResult
	err := s.transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		current, err := lockAuthority(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		digest, err := safetyRequestDigest(domain.SafetyActionStop, scopeID, expectedSecurityEpoch, commandID, nonce, nil, signatures)
		if err != nil {
			return err
		}
		if receipt, found, err := tx.LookupCommandReceipt(ctx, commandID); err != nil {
			return err
		} else if found {
			return reconcileReceipt(receipt, digest, snapshotAuthority(current), &result)
		}
		stopped, err := s.quorum.Stop(snapshotAuthority(current), scopeID, expectedSecurityEpoch, commandID, nonce, signatures)
		if err != nil {
			return err
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
		return domain.SafetyTransitionResult{}, err
	}
	return result, nil
}

func (s *SafetyService) Release(ctx context.Context, scopeID domain.ScopeID, expectedSecurityEpoch domain.Epoch, commandID, nonce string, proposedActivation domain.AuthorityState, signatures []domain.SafetySignature) (domain.SafetyTransitionResult, error) {
	if err := s.ready(ctx); err != nil {
		return domain.SafetyTransitionResult{}, err
	}
	var result domain.SafetyTransitionResult
	err := s.transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		current, err := lockAuthority(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		activation := cloneState(proposedActivation)
		activationDigest, err := domain.ActivationDigest(activation)
		if err != nil {
			return err
		}
		digest, err := safetyRequestDigest(domain.SafetyActionRelease, scopeID, expectedSecurityEpoch, commandID, nonce, &activationDigest, signatures)
		if err != nil {
			return err
		}
		if receipt, found, err := tx.LookupCommandReceipt(ctx, commandID); err != nil {
			return err
		} else if found {
			return reconcileReceipt(receipt, digest, snapshotAuthority(current), &result)
		}
		released, err := s.quorum.Release(snapshotAuthority(current), activation, scopeID, expectedSecurityEpoch, commandID, nonce, signatures)
		if err != nil {
			return err
		}
		// Release advances Scope Activation Epoch exactly once; quorum validates
		// the complete signed activation and the next global Security Epoch.
		currentState := snapshotAuthority(current)
		nextActivation, err := currentState.ScopeActivationEpoch.Next()
		if err != nil {
			return err
		}
		if released.State.ScopeActivationEpoch != nextActivation {
			return domain.ErrInvalidApproval
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
		return domain.SafetyTransitionResult{}, err
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
