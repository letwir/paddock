package port

import (
	"context"
	"errors"

	"github.com/letwir/paddock/internal/governance/domain"
)

// MaxRolloutDeadlineBatch bounds one Coordinator sweep, not lifetime work.
const MaxRolloutDeadlineBatch = 1000

var ErrInvalidDeadlineBatch = errors.New("invalid rollout deadline batch")

func ValidateRolloutDeadlineBatch(limit int) error {
	if limit < 1 || limit > MaxRolloutDeadlineBatch {
		return ErrInvalidDeadlineBatch
	}
	return nil
}

// RolloutDeadlineCandidate is an untrusted scheduling hint, not authority to
// mutate a row. Monitoring fences both new Decisions and extensions, which do
// not advance DecisionRevision. Reapers re-read Scope -> Rollout, compare this
// snapshot, validate Roots, read transaction-bound DB time, and CAS current state.
type RolloutDeadlineCandidate struct {
	Scope      domain.ScopeID
	Rollout    domain.RolloutID
	Monitoring domain.MonitoringWindow
}

// RolloutDeadlineStore lists at most limit due MONITORING rows using DB
// clock_timestamp(), never a caller timestamp. Due means HoldDeadline <= DB time
// during HOLD, otherwise ObservationDeadline <= DB time (or current FAIL/ABORT).
// Use deterministic deadline/Scope/Rollout order. Listing takes no row locks that
// could invert Scope -> Rollout order. Each candidate is later processed in its
// own short GovernanceTx, with locked current-state comparison and CAS. Listing
// alone claims no work; concurrent/replayed hints are safe to skip after locking.
// Implementations must validate limit and obey context cancellation.
type RolloutDeadlineStore interface {
	ListRolloutDeadlines(ctx context.Context, limit int) ([]RolloutDeadlineCandidate, error)
}
