package domain

import (
	"errors"
	"fmt"
)

var (
	ErrDatabaseUnavailable = errors.New("authority database unavailable")
	ErrScopeFrozen         = errors.New("scope is frozen")
	ErrSafeStopped         = errors.New("scope is safe-stopped")
	ErrRollbackState       = errors.New("invalid rollback state")
	ErrRootNotFound        = errors.New("root not found")
	ErrStaleGrant          = errors.New("grant does not match current authority")
)

type RootID string

func (id RootID) Validate() error { return validateID(string(id)) }

type ScopeMode string

const (
	ScopeActive   ScopeMode = "ACTIVE"
	ScopeFrozen   ScopeMode = "FROZEN"
	ScopeSafeStop ScopeMode = "SAFE_STOPPED"
)

func (m ScopeMode) Validate() error {
	switch m {
	case ScopeActive, ScopeFrozen, ScopeSafeStop:
		return nil
	default:
		return fmt.Errorf("invalid scope mode %q", m)
	}
}

// PolicyBinding selects either an ordinary immutable policy digest or the
// embedded deny-all Safe Baseline. Safe Baseline has no distributable digest.
type PolicyBinding struct {
	Digest       Digest
	SafeBaseline bool
}

func (p PolicyBinding) Validate() error {
	if p.SafeBaseline {
		if p.Digest != "" {
			return errors.New("safe baseline must not carry a bundle digest")
		}
		return nil
	}
	return p.Digest.Validate()
}

type RootAuthority struct {
	Policy             PolicyBinding
	AuthorizationEpoch Epoch
}

func (r RootAuthority) Validate() error { return r.Policy.Validate() }

// AuthorityState is a value snapshot used by pure Domain transitions. Map
// values are copied by every transition so callers' input snapshots stay unchanged.
type AuthorityState struct {
	Scope                ScopeID
	ScopeActivationEpoch Epoch
	SecurityEpoch        Epoch
	Mode                 ScopeMode
	DatabaseAvailable    bool
	Roots                map[RootID]RootAuthority
}

func (s AuthorityState) Validate() error {
	if err := s.Scope.Validate(); err != nil {
		return err
	}
	if err := s.Mode.Validate(); err != nil {
		return err
	}
	if len(s.Roots) == 0 {
		return errors.New("authority state requires at least one root")
	}
	for id, root := range s.Roots {
		if err := id.Validate(); err != nil {
			return fmt.Errorf("root %q: %w", id, err)
		}
		if err := root.Validate(); err != nil {
			return fmt.Errorf("root %q: %w", id, err)
		}
	}
	return nil
}

// LKGAssessment is the result produced by the outer trusted bundle verifier.
// The Domain package models that result; it does not verify signatures, revocation,
// compatibility, or policy eligibility itself. Only LKGUsable may activate a digest.
type LKGStatus string

const (
	LKGUsable      LKGStatus = "USABLE"
	LKGUnavailable LKGStatus = "UNAVAILABLE"
	LKGInvalid     LKGStatus = "INVALID"
)

type LKGAssessment struct {
	Status LKGStatus
	Digest Digest
}

func (a LKGAssessment) usableDigest() (Digest, bool) {
	if a.Status != LKGUsable || a.Digest.Validate() != nil {
		return "", false
	}
	return a.Digest, true
}

// RollbackPlan records the two phases. BeginRollback freezes the Scope without
// advancing epochs; FinalizeRollback performs the effective policy switch once.
type RollbackPlan struct {
	Scope     ScopeID
	Root      RootID
	State     RolloutState
	Finalized bool
}

func (p RollbackPlan) Validate() error {
	if err := p.Scope.Validate(); err != nil {
		return err
	}
	if err := p.Root.Validate(); err != nil {
		return err
	}
	if p.State != RolloutRollingBack && p.State != RolloutRolledBack && p.State != RolloutSafeStopped {
		return ErrRollbackState
	}
	if p.Finalized != (p.State == RolloutRolledBack || p.State == RolloutSafeStopped) {
		return ErrRollbackState
	}
	return nil
}

func cloneAuthority(s AuthorityState) AuthorityState {
	out := s
	out.Roots = make(map[RootID]RootAuthority, len(s.Roots))
	for id, root := range s.Roots {
		out.Roots[id] = root
	}
	return out
}

// BeginRollback starts phase one: freeze the Scope and enter ROLLING_BACK.
// No activation or Root epoch changes until the final policy switch.
func BeginRollback(s AuthorityState, root RootID) (AuthorityState, RollbackPlan, error) {
	if err := s.Validate(); err != nil {
		return s, RollbackPlan{}, err
	}
	if !s.DatabaseAvailable {
		return s, RollbackPlan{}, ErrDatabaseUnavailable
	}
	if s.Mode == ScopeSafeStop {
		return s, RollbackPlan{}, ErrSafeStopped
	}
	if s.Mode != ScopeActive {
		return s, RollbackPlan{}, ErrScopeFrozen
	}
	if _, ok := s.Roots[root]; !ok {
		return s, RollbackPlan{}, ErrRootNotFound
	}
	out := cloneAuthority(s)
	out.Mode = ScopeFrozen
	return out, RollbackPlan{Scope: s.Scope, Root: root, State: RolloutRollingBack}, nil
}

// FinalizeRollback performs phase two. A trusted verifier's usable LKG assessment
// is selected when provided; unavailable/invalid assessments select the embedded
// Safe Baseline. Scope and target Root epochs advance exactly once at this switch.
func FinalizeRollback(s AuthorityState, p RollbackPlan, lkg LKGAssessment) (AuthorityState, RollbackPlan, error) {
	if err := s.Validate(); err != nil {
		return s, p, err
	}
	if err := p.Validate(); err != nil {
		return s, p, err
	}
	if p.Finalized || p.State != RolloutRollingBack || s.Mode != ScopeFrozen || s.Scope != p.Scope {
		return s, p, ErrRollbackState
	}
	if !s.DatabaseAvailable {
		return s, p, ErrDatabaseUnavailable
	}
	root, ok := s.Roots[p.Root]
	if !ok {
		return s, p, ErrRootNotFound
	}

	activation, err := s.ScopeActivationEpoch.Next()
	if err != nil {
		return s, p, err
	}
	rootEpoch, err := root.AuthorizationEpoch.Next()
	if err != nil {
		return s, p, err
	}

	out := cloneAuthority(s)
	out.ScopeActivationEpoch = activation
	root.AuthorizationEpoch = rootEpoch
	digest, usableLKG := lkg.usableDigest()
	if !usableLKG {
		root.Policy = PolicyBinding{SafeBaseline: true}
		out.Mode = ScopeSafeStop
		p.State = RolloutSafeStopped
	} else {
		root.Policy = PolicyBinding{Digest: digest}
		out.Mode = ScopeActive
		p.State = RolloutRolledBack
	}
	out.Roots[p.Root] = root
	p.Finalized = true
	return out, p, nil
}

// applyEmergencyStop applies an already-authenticated stop intent as a pure
// state transition. Authentication and durable persistence belong to outer layers.
func applyEmergencyStop(s AuthorityState) (AuthorityState, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	if !s.DatabaseAvailable {
		return s, ErrDatabaseUnavailable
	}
	security, err := s.SecurityEpoch.Next()
	if err != nil {
		return s, err
	}
	out := cloneAuthority(s)
	out.SecurityEpoch = security
	out.Mode = ScopeSafeStop
	return out, nil
}

type Grant struct {
	Root               RootID
	Policy             PolicyBinding
	AuthorizationEpoch Epoch
	SecurityEpoch      Epoch
}

// EffectivePolicy returns the Root-local effective policy only when current
// authority is available and the Scope is ACTIVE. Scope activation epoch is
// intentionally not a blanket grant-revocation check across unrelated Roots.
func EffectivePolicy(s AuthorityState, root RootID) (RootAuthority, error) {
	if err := s.Validate(); err != nil {
		return RootAuthority{}, err
	}
	if !s.DatabaseAvailable {
		return RootAuthority{}, ErrDatabaseUnavailable
	}
	switch s.Mode {
	case ScopeFrozen:
		return RootAuthority{}, ErrScopeFrozen
	case ScopeSafeStop:
		return RootAuthority{}, ErrSafeStopped
	}
	policy, ok := s.Roots[root]
	if !ok {
		return RootAuthority{}, ErrRootNotFound
	}
	return policy, nil
}

func Authorize(s AuthorityState, grant Grant) error {
	current, err := EffectivePolicy(s, grant.Root)
	if err != nil {
		return err
	}
	if grant.Policy != current.Policy || grant.AuthorizationEpoch != current.AuthorizationEpoch || grant.SecurityEpoch != s.SecurityEpoch {
		return ErrStaleGrant
	}
	return nil
}
