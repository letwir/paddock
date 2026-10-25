// Package domain contains database- and transport-independent governance values.
package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidDigest = errors.New("invalid digest")
	ErrInvalidID     = errors.New("invalid identifier")
	ErrEpochOverflow = errors.New("epoch overflow")
)

// Digest is a SHA-256 digest encoded as exactly 64 lowercase hexadecimal
// characters (the canonical textual form). Its zero value is invalid.
type Digest string

func ParseDigest(value string) (Digest, error) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return "", fmt.Errorf("%w: want 64 lowercase hexadecimal characters", ErrInvalidDigest)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDigest, err)
	}
	return Digest(value), nil
}

func (d Digest) Validate() error {
	_, err := ParseDigest(string(d))
	return err
}

// Epoch is an unsigned monotonic generation counter.
type Epoch uint64

// Next returns the next epoch without wrapping. The receiver is unchanged.
func (e Epoch) Next() (Epoch, error) {
	if e == Epoch(^uint64(0)) {
		return e, ErrEpochOverflow
	}
	return e + 1, nil
}

type ScopeID string

// Validate checks a Scope identifier is non-empty and contains no surrounding whitespace.
func (id ScopeID) Validate() error { return validateID(string(id)) }

// Scope is the pure domain identity for an authorization/evaluation scope.
// Additional policy and Root binding is introduced by later domain issues.
type Scope struct {
	ID ScopeID
}

func (s Scope) Validate() error { return s.ID.Validate() }

type RolloutID string

// Validate checks a Rollout identifier is non-empty and contains no surrounding whitespace.
func (id RolloutID) Validate() error { return validateID(string(id)) }

// Rollout is the minimal pure aggregate identity/state value. Transition rules
// are defined by the follow-up state-machine issue, not by this type contract.
type Rollout struct {
	ID    RolloutID
	Scope ScopeID
	State RolloutState
}

func (r Rollout) Validate() error {
	if err := r.ID.Validate(); err != nil {
		return err
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	return r.State.Validate()
}

func validateID(value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: empty or surrounding whitespace", ErrInvalidID)
	}
	return nil
}

type RolloutState string

const (
	RolloutShadow      RolloutState = "SHADOW"
	RolloutCanary      RolloutState = "CANARY"
	RolloutMonitoring  RolloutState = "MONITORING"
	RolloutCompleted   RolloutState = "COMPLETED"
	RolloutRollingBack RolloutState = "ROLLING_BACK"
	RolloutRolledBack  RolloutState = "ROLLED_BACK"
	RolloutSafeStopped RolloutState = "SAFE_STOPPED"
)

func (s RolloutState) Validate() error {
	switch s {
	case RolloutShadow, RolloutCanary, RolloutMonitoring, RolloutCompleted,
		RolloutRollingBack, RolloutRolledBack, RolloutSafeStopped:
		return nil
	default:
		return fmt.Errorf("invalid rollout state %q", s)
	}
}

// Hold is a finite monitoring decision/outcome, never a RolloutState.
type MonitoringDecision string

const (
	DecisionPass  MonitoringDecision = "PASS"
	DecisionFail  MonitoringDecision = "FAIL"
	DecisionHold  MonitoringDecision = "HOLD"
	DecisionAbort MonitoringDecision = "ABORT"
)

func (d MonitoringDecision) Validate() error {
	switch d {
	case DecisionPass, DecisionFail, DecisionHold, DecisionAbort:
		return nil
	default:
		return fmt.Errorf("invalid monitoring decision %q", d)
	}
}
