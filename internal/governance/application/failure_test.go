package application

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func TestFailureKindsAreStable(t *testing.T) {
	for _, tc := range []struct {
		kind FailureKind
		want string
	}{
		{FailureStale, "STALE"}, {FailureBusy, "BUSY"},
		{FailureForbidden, "FORBIDDEN"}, {FailureInvalid, "INVALID"},
		{FailureRetryable, "RETRYABLE"}, {FailureUnknownCommit, "UNKNOWN_COMMIT"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.kind) != tc.want {
				t.Fatalf("kind=%q want=%q", tc.kind, tc.want)
			}
		})
	}
}

func TestNormalizeCommandFailureRequiresRollbackForSQLState(t *testing.T) {
	for _, state := range []string{"40001", "40P01", "55P03", "42501"} {
		t.Run(state, func(t *testing.T) {
			for _, cause := range []error{stateErr{state}, fmt.Errorf("outside transaction: %w", stateErr{state})} {
				if got := normalizeCommandFailure(cause); got != cause {
					t.Fatalf("unmarked SQLSTATE changed: %v => %v", cause, got)
				}
			}
			uncertain := errors.Join(port.ErrTransactionRolledBack, stateErr{state}, port.ErrCommitOutcomeUnknown)
			requireFailureKind(t, normalizeCommandFailure(uncertain), FailureUnknownCommit)
		})
	}
}

func TestNormalizeCommandFailureMappingsAndCausePreservation(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		kind FailureKind
	}{
		{"stale", port.ErrStaleWrite, FailureStale},
		{"lock unavailable", errors.Join(port.ErrTransactionRolledBack, stateErr{"55P03"}), FailureBusy},
		{"approval", domain.ErrInvalidApproval, FailureForbidden},
		{"bundle signature", domain.ErrInvalidBundleSignature, FailureForbidden},
		{"frozen authorization", domain.ErrScopeFrozen, FailureForbidden},
		{"safe stopped authorization", domain.ErrSafeStopped, FailureForbidden},
		{"ACL", errors.Join(port.ErrTransactionRolledBack, stateErr{"42501"}), FailureForbidden},
		{"identifier", domain.ErrInvalidID, FailureInvalid},
		{"digest", domain.ErrInvalidDigest, FailureInvalid},
		{"canonical input", domain.ErrInvalidCanonicalInput, FailureInvalid},
		{"no change", domain.ErrPolicyNoChange, FailureInvalid},
		{"serialization", errors.Join(port.ErrTransactionRolledBack, stateErr{"40001"}), FailureRetryable},
		{"deadlock", errors.Join(port.ErrTransactionRolledBack, stateErr{"40P01"}), FailureRetryable},
		{"unknown commit", port.ErrCommitOutcomeUnknown, FailureUnknownCommit},
		{"unknown commit serialization", errors.Join(port.ErrCommitOutcomeUnknown, stateErr{"40001"}), FailureUnknownCommit},
		{"unknown commit deadlock", errors.Join(stateErr{"40P01"}, port.ErrCommitOutcomeUnknown), FailureUnknownCommit},
		{"unknown overrides stale", errors.Join(port.ErrStaleWrite, port.ErrCommitOutcomeUnknown), FailureUnknownCommit},
		{"unknown overrides rollback", errors.Join(port.ErrTransactionRolledBack, stateErr{"40001"}, port.ErrCommitOutcomeUnknown), FailureUnknownCommit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cause := fmt.Errorf("operation: %w", tc.err)
			got := normalizeCommandFailure(cause)
			failure := requireFailureKind(t, got, tc.kind)
			if failure.Cause != cause || errors.Unwrap(failure) != cause || !errors.Is(got, tc.err) {
				t.Fatalf("cause lost: %v", got)
			}
			var original, preserved sqlStateError
			if errors.As(cause, &original) && (!errors.As(got, &preserved) || preserved.SQLState() != original.SQLState()) {
				t.Fatalf("SQLState cause lost: %v", got)
			}
			if normalizeCommandFailure(got) != got {
				t.Fatal("normalization wrapped an already classified error")
			}
		})
	}
}

func TestNormalizeCommandFailureLeavesUnmatchedErrorsIdentical(t *testing.T) {
	for _, cause := range []error{
		nil, errors.New("unrecognized failure"), context.Canceled, context.DeadlineExceeded,
		domain.ErrDatabaseUnavailable, domain.ErrEpochOverflow, domain.ErrInvalidRollout,
		stateErr{"23505"}, stateErr{"22023"}, stateErr{"08006"},
		port.ErrTransactionRolledBack, errors.Join(port.ErrTransactionRolledBack, stateErr{"23505"}),
		errors.New("SQLSTATE 40001 40P01 55P03 42501 invalid approval commit outcome unknown"),
	} {
		if got := normalizeCommandFailure(cause); got != cause {
			t.Errorf("unmatched error changed: %v => %v", cause, got)
		}
	}
}

func TestCommandFailurePreservesTypedCauseAndExplicitClassification(t *testing.T) {
	cause := &failureTestCause{}
	failure := &CommandFailure{Kind: FailureBusy, Cause: cause}
	wrapped := fmt.Errorf("outer: %w", failure)
	var got *failureTestCause
	if !errors.Is(wrapped, cause) || !errors.As(wrapped, &got) || got != cause || normalizeCommandFailure(wrapped) != wrapped {
		t.Fatal("typed cause or explicit classification lost")
	}
	if failure.Error() != "BUSY: test cause" || (&CommandFailure{Kind: FailureBusy}).Error() != "BUSY" {
		t.Fatal("unexpected error description")
	}
	uncertain := errors.Join(&CommandFailure{Kind: FailureRetryable, Cause: stateErr{"40001"}}, port.ErrCommitOutcomeUnknown)
	requireFailureKind(t, normalizeCommandFailure(uncertain), FailureUnknownCommit)
	typedUnknown := &CommandFailure{Kind: FailureUnknownCommit, Cause: cause}
	if !errors.Is(typedUnknown, port.ErrCommitOutcomeUnknown) || !errors.Is(typedUnknown, cause) {
		t.Fatal("typed unknown must preserve both uncertainty and cause")
	}
	uncertain = &CommandFailure{Kind: FailureRetryable, Cause: typedUnknown}
	requireFailureKind(t, normalizeCommandFailure(uncertain), FailureUnknownCommit)
}

type failureTestCause struct{}

func (*failureTestCause) Error() string { return "test cause" }

func requireFailureKind(t *testing.T, err error, kind FailureKind) *CommandFailure {
	t.Helper()
	var failure *CommandFailure
	if !errors.As(err, &failure) || failure.Kind != kind {
		t.Fatalf("error=%v want CommandFailure kind=%s", err, kind)
	}
	return failure
}
