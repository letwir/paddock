package application

import (
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// FailureKind is a stable command outcome classification, not a retry policy.
type FailureKind string

const (
	FailureStale         FailureKind = "STALE"
	FailureBusy          FailureKind = "BUSY"
	FailureForbidden     FailureKind = "FORBIDDEN"
	FailureInvalid       FailureKind = "INVALID"
	FailureRetryable     FailureKind = "RETRYABLE"
	FailureUnknownCommit FailureKind = "UNKNOWN_COMMIT"
)

// CommandFailure preserves the underlying error for errors.Is and errors.As.
// UNKNOWN_COMMIT requires same-command receipt reconciliation, never automatic
// retry, even if Cause also exposes a normally retryable SQLSTATE.
type CommandFailure struct {
	Kind  FailureKind
	Cause error
}

func (e *CommandFailure) Error() string {
	if e.Cause == nil {
		return string(e.Kind)
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Cause)
}

func (e *CommandFailure) Unwrap() error { return e.Cause }

// Is makes explicit outcome uncertainty visible at the port boundary even when
// the caller constructed the typed failure without separately joining a marker.
func (e *CommandFailure) Is(target error) bool {
	return target == port.ErrCommitOutcomeUnknown && e.Kind == FailureUnknownCommit
}

func commandFailure(kind FailureKind, cause error) error {
	return &CommandFailure{Kind: kind, Cause: cause}
}

// normalizeCommandFailure only recognizes explicit contracts. In particular,
// neither arbitrary adapter errors nor database error messages imply INVALID.
func normalizeCommandFailure(err error) error {
	if err == nil {
		return nil
	}
	// Outcome uncertainty takes precedence over every wrapped classification.
	if errors.Is(err, port.ErrCommitOutcomeUnknown) {
		var failure *CommandFailure
		if errors.As(err, &failure) && failure.Kind == FailureUnknownCommit {
			return err
		}
		return commandFailure(FailureUnknownCommit, err)
	}
	var failure *CommandFailure
	if errors.As(err, &failure) {
		return err
	}
	var kind FailureKind
	switch {
	case errors.Is(err, port.ErrStaleWrite):
		kind = FailureStale
	case errors.Is(err, domain.ErrInvalidApproval), errors.Is(err, domain.ErrInvalidBundleSignature),
		errors.Is(err, domain.ErrScopeFrozen), errors.Is(err, domain.ErrSafeStopped):
		kind = FailureForbidden
	case errors.Is(err, domain.ErrInvalidID), errors.Is(err, domain.ErrInvalidDigest),
		errors.Is(err, domain.ErrInvalidCanonicalInput), errors.Is(err, domain.ErrPolicyNoChange):
		kind = FailureInvalid
	default:
		var stateErr sqlStateError
		if errors.Is(err, port.ErrTransactionRolledBack) && errors.As(err, &stateErr) {
			switch stateErr.SQLState() {
			case "55P03":
				kind = FailureBusy
			case "42501":
				kind = FailureForbidden
			case "40001", "40P01":
				// Retry classification requires explicit rollback evidence from
				// the transaction boundary, not merely the SQLSTATE.
				kind = FailureRetryable
			}
		}
	}
	if kind == "" {
		return err
	}
	return commandFailure(kind, err)
}
