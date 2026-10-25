package domain

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidRollout = errors.New("invalid policy rollout")
	ErrPolicyNoChange = errors.New("candidate policy does not change target Root")
)

// PolicyRollout captures the Scope baseline before a Root-scoped Canary and
// the desired Scope-wide policy after promotion. Values are immutable snapshots.
type PolicyRollout struct {
	ID                RolloutID
	Scope             ScopeID
	Target            RootID
	State             RolloutState
	RollbackFrom      RolloutState
	BaseActivation    Epoch
	BaseSecurityEpoch Epoch
	BaseRootEpochs    map[RootID]Epoch
	Baseline          map[RootID]PolicyBinding
	Candidate         map[RootID]PolicyBinding
	Monitoring        MonitoringWindow
}

func hasSafeBaseline(roots map[RootID]RootAuthority) bool {
	for _, root := range roots {
		if root.Policy.SafeBaseline {
			return true
		}
	}
	return false
}

func (r PolicyRollout) Validate() error {
	if err := r.ID.Validate(); err != nil {
		return err
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if r.State != RolloutCanary && r.State != RolloutMonitoring && r.State != RolloutCompleted && r.State != RolloutRollingBack && r.State != RolloutRolledBack && r.State != RolloutSafeStopped {
		return ErrInvalidRollout
	}
	if r.Monitoring != (MonitoringWindow{}) {
		if r.State == RolloutCanary || r.Monitoring.Validate() != nil {
			return ErrInvalidRollout
		}
	}
	if r.State == RolloutCompleted && (r.Monitoring.Validate() != nil || r.Monitoring.Decision != DecisionPass || r.Monitoring.DecisionAt.Before(r.Monitoring.ObservationDeadline) || !r.Monitoring.HoldSince.IsZero() || r.Monitoring.LastObservedAt.Before(r.Monitoring.ObservationDeadline)) {
		return ErrInvalidRollout
	}
	if r.State == RolloutRollingBack {
		if r.RollbackFrom != RolloutCanary && r.RollbackFrom != RolloutMonitoring {
			return ErrInvalidRollout
		}
	} else if r.RollbackFrom != "" {
		return ErrInvalidRollout
	}
	if len(r.Baseline) == 0 || len(r.Baseline) != len(r.Candidate) || len(r.Baseline) != len(r.BaseRootEpochs) {
		return ErrInvalidRollout
	}
	if _, ok := r.Baseline[r.Target]; !ok {
		return ErrInvalidRollout
	}
	for root, baseline := range r.Baseline {
		if err := root.Validate(); err != nil {
			return err
		}
		if err := baseline.Validate(); err != nil {
			return err
		}
		if _, ok := r.BaseRootEpochs[root]; !ok {
			return ErrInvalidRollout
		}
		candidate, ok := r.Candidate[root]
		if !ok {
			return ErrInvalidRollout
		}
		if err := candidate.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func sameRootSet(roots map[RootID]RootAuthority, policies map[RootID]PolicyBinding) bool {
	if len(roots) != len(policies) {
		return false
	}
	for root := range roots {
		if _, ok := policies[root]; !ok {
			return false
		}
	}
	return true
}

func checkRolloutState(s AuthorityState, r PolicyRollout, want RolloutState) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if s.Scope != r.Scope || s.SecurityEpoch != r.BaseSecurityEpoch || !sameRootSet(s.Roots, r.Baseline) {
		return ErrInvalidRollout
	}
	if r.State != want {
		return ErrInvalidRollout
	}
	var err error
	expectedActivation := r.BaseActivation
	if want == RolloutCanary {
		expectedActivation, err = expectedActivation.Next()
	} else if want == RolloutMonitoring {
		expectedActivation, err = expectedActivation.Next()
		if err == nil {
			expectedActivation, err = expectedActivation.Next()
		}
	} else if want == RolloutRollingBack {
		expectedActivation, err = expectedActivation.Next()
		if err == nil && r.RollbackFrom == RolloutMonitoring {
			expectedActivation, err = expectedActivation.Next()
		}
	} else {
		return ErrInvalidRollout
	}
	if err != nil || s.ScopeActivationEpoch != expectedActivation {
		return ErrInvalidRollout
	}
	for root, authority := range s.Roots {
		expectedRoot := r.BaseRootEpochs[root]
		changed := r.Candidate[root] != r.Baseline[root]
		if want == RolloutCanary && root == r.Target || want == RolloutMonitoring && changed || want == RolloutRollingBack && (r.RollbackFrom == RolloutCanary && root == r.Target || r.RollbackFrom == RolloutMonitoring && changed) {
			expectedRoot, err = expectedRoot.Next()
			if err != nil {
				return ErrInvalidRollout
			}
		}
		if authority.AuthorizationEpoch != expectedRoot || authority.Policy != r.Baseline[root] && authority.Policy != r.Candidate[root] {
			return ErrInvalidRollout
		}
	}
	return nil
}

// StartCanary snapshots the effective Scope baseline and activates a candidate
// for only the selected Root. It advances Scope Activation and that Root's
// authorization epoch once; unrelated Roots retain both policy and epoch.
func StartCanary(s AuthorityState, id RolloutID, target RootID, candidate Digest) (AuthorityState, PolicyRollout, error) {
	if err := s.Validate(); err != nil {
		return s, PolicyRollout{}, err
	}
	if !s.DatabaseAvailable {
		return s, PolicyRollout{}, ErrDatabaseUnavailable
	}
	if s.Mode != ScopeActive {
		return s, PolicyRollout{}, ErrScopeFrozen
	}
	if hasSafeBaseline(s.Roots) {
		return s, PolicyRollout{}, ErrSafeStopped
	}
	if err := id.Validate(); err != nil {
		return s, PolicyRollout{}, err
	}
	if err := candidate.Validate(); err != nil {
		return s, PolicyRollout{}, err
	}
	root, ok := s.Roots[target]
	if !ok {
		return s, PolicyRollout{}, ErrRootNotFound
	}
	if root.Policy.SafeBaseline {
		return s, PolicyRollout{}, ErrSafeStopped
	}
	if root.Policy.Digest == candidate {
		return s, PolicyRollout{}, ErrPolicyNoChange
	}

	activation, err := s.ScopeActivationEpoch.Next()
	if err != nil {
		return s, PolicyRollout{}, err
	}
	rootEpoch, err := root.AuthorizationEpoch.Next()
	if err != nil {
		return s, PolicyRollout{}, err
	}

	baseline := make(map[RootID]PolicyBinding, len(s.Roots))
	candidateSet := make(map[RootID]PolicyBinding, len(s.Roots))
	baseRootEpochs := make(map[RootID]Epoch, len(s.Roots))
	for rootID, authority := range s.Roots {
		baseline[rootID] = authority.Policy
		baseRootEpochs[rootID] = authority.AuthorizationEpoch
		// Promotion makes the candidate the new Scope baseline for every Root;
		// activation remains Root-scoped until Promote is called.
		candidateSet[rootID] = PolicyBinding{Digest: candidate}
	}

	candidatePolicy := PolicyBinding{Digest: candidate}
	out := cloneAuthority(s)
	root.Policy = candidatePolicy
	root.AuthorizationEpoch = rootEpoch
	out.Roots[target] = root
	out.ScopeActivationEpoch = activation
	rollout := PolicyRollout{ID: id, Scope: s.Scope, Target: target, State: RolloutCanary, BaseActivation: s.ScopeActivationEpoch, BaseSecurityEpoch: s.SecurityEpoch, BaseRootEpochs: baseRootEpochs, Baseline: baseline, Candidate: candidateSet}
	return out, rollout, nil
}

// Promote installs the candidate set as the Scope baseline and enters MONITORING.
// Root epochs advance only for Roots whose effective policy actually changes.
func Promote(s AuthorityState, r PolicyRollout) (AuthorityState, PolicyRollout, error) {
	if s.Mode != ScopeActive {
		return s, r, ErrScopeFrozen
	}
	if hasSafeBaseline(s.Roots) {
		return s, r, ErrSafeStopped
	}
	if err := checkRolloutState(s, r, RolloutCanary); err != nil {
		return s, r, err
	}
	if !s.DatabaseAvailable {
		return s, r, ErrDatabaseUnavailable
	}
	if s.Mode != ScopeActive {
		return s, r, ErrScopeFrozen
	}
	activation, err := s.ScopeActivationEpoch.Next()
	if err != nil {
		return s, r, err
	}

	out := cloneAuthority(s)
	for rootID, candidate := range r.Candidate {
		root := out.Roots[rootID]
		if root.Policy != candidate {
			epoch, err := root.AuthorizationEpoch.Next()
			if err != nil {
				return s, r, fmt.Errorf("root %s: %w", rootID, err)
			}
			root.AuthorizationEpoch = epoch
			root.Policy = candidate
			out.Roots[rootID] = root
		}
	}
	out.ScopeActivationEpoch = activation
	r.State = RolloutMonitoring
	return out, r, nil
}

// Rollback begins phase one: the Scope is frozen and the rollout enters
// ROLLING_BACK. Epochs remain unchanged until FinalizePolicyRollback.
func Rollback(s AuthorityState, r PolicyRollout) (AuthorityState, PolicyRollout, error) {
	if err := checkRolloutState(s, r, r.State); err != nil {
		return s, r, err
	}
	if r.State != RolloutCanary && r.State != RolloutMonitoring {
		return s, r, ErrInvalidRollout
	}
	if !s.DatabaseAvailable {
		return s, r, ErrDatabaseUnavailable
	}
	if s.Mode != ScopeActive || s.Scope != r.Scope || !sameRootSet(s.Roots, r.Baseline) {
		return s, r, ErrInvalidRollout
	}
	out := cloneAuthority(s)
	out.Mode = ScopeFrozen
	r.RollbackFrom = r.State
	r.State = RolloutRollingBack
	return out, r, nil
}

// FinalizePolicyRollback completes phase two. A trusted caller reports whether
// the captured LKG baseline remains usable. Any other status selects Safe Baseline.
func FinalizePolicyRollback(s AuthorityState, r PolicyRollout, lkgStatus LKGStatus) (AuthorityState, PolicyRollout, error) {
	if err := checkRolloutState(s, r, RolloutRollingBack); err != nil {
		return s, r, err
	}
	if !s.DatabaseAvailable {
		return s, r, ErrDatabaseUnavailable
	}
	if s.Mode != ScopeFrozen {
		return s, r, ErrInvalidRollout
	}
	activation, err := s.ScopeActivationEpoch.Next()
	if err != nil {
		return s, r, err
	}

	useBaseline := lkgStatus == LKGUsable
	if useBaseline {
		for _, policy := range r.Baseline {
			if policy.Validate() != nil {
				useBaseline = false
				break
			}
		}
	}
	out := cloneAuthority(s)
	for rootID, root := range out.Roots {
		var next PolicyBinding
		if useBaseline {
			next = r.Baseline[rootID]
		} else {
			next = PolicyBinding{SafeBaseline: true}
		}
		if root.Policy != next {
			epoch, err := root.AuthorizationEpoch.Next()
			if err != nil {
				return s, r, fmt.Errorf("root %s: %w", rootID, err)
			}
			root.AuthorizationEpoch = epoch
			root.Policy = next
			out.Roots[rootID] = root
		}
	}
	out.ScopeActivationEpoch = activation
	if useBaseline {
		out.Mode = ScopeActive
		r.State = RolloutRolledBack
	} else {
		out.Mode = ScopeSafeStop
		r.State = RolloutSafeStopped
	}
	r.RollbackFrom = ""
	return out, r, nil
}
