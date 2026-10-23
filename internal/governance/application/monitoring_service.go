package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// MonitoringDecisionRequest accepts Gate assertions, not a Worker decision or
// timestamp. As with EvaluateCanaryGate, it does not measure/attest those inputs.
// The Coordinator is responsible for supplying its required check policy.
type MonitoringDecisionRequest struct {
	CommandID, Nonce         string
	Scope                    domain.ScopeID
	Rollout                  domain.RolloutID
	ExpectedScopeEpoch       domain.Epoch
	ExpectedSecurityEpoch    domain.Epoch
	ExpectedDecisionRevision int64
	Gate                     domain.CanaryGateInput
}

type MonitoringResult struct {
	CommandID  string
	Scope      domain.ScopeID
	Rollout    domain.RolloutID
	ScopeEpoch domain.Epoch
	State      domain.RolloutState
	Mode       domain.ScopeMode
	Outcome    domain.MonitoringOutcome
	Monitoring domain.MonitoringWindow
}

type MonitoringService struct {
	tx  port.Transactor
	lkg LKGVerifier
}

func NewMonitoringService(tx port.Transactor, lkg LKGVerifier) *MonitoringService {
	return &MonitoringService{tx: tx, lkg: lkg}
}

// canonicalGateEvidence hashes canonical, order-independent Gate assertions.
// Even invalid Gate structure has deterministic evidence and yields ABORT.
func canonicalGateEvidence(input domain.CanaryGateInput) (domain.Digest, error) {
	input.RequiredChecks = append([]domain.CanaryCheckID(nil), input.RequiredChecks...)
	input.Checks = append([]domain.CanaryCheck(nil), input.Checks...)
	sort.Slice(input.RequiredChecks, func(i, j int) bool { return input.RequiredChecks[i] < input.RequiredChecks[j] })
	sort.Slice(input.Checks, func(i, j int) bool {
		if input.Checks[i].ID == input.Checks[j].ID {
			return input.Checks[i].State < input.Checks[j].State
		}
		return input.Checks[i].ID < input.Checks[j].ID
	})
	b, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	b, err = canonical.NewJCSCodec().CanonicalizeJSON(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return domain.Digest(hex.EncodeToString(sum[:])), nil
}

// lockMonitoring enforces the existing Scope -> Rollout -> Roots order. Calling
// the pure Rollback validator also checks the pinned activation/security/root
// epochs and current policies without changing or persisting authority.
func lockMonitoring(ctx context.Context, tx port.GovernanceTx, scope domain.ScopeID, id domain.RolloutID) (port.ScopeSnapshot, port.RolloutSnapshot, domain.PolicyRollout, error) {
	if scope.Validate() != nil || id.Validate() != nil {
		return port.ScopeSnapshot{}, port.RolloutSnapshot{}, domain.PolicyRollout{}, domain.ErrInvalidID
	}
	sn, err := tx.LockScope(ctx, scope)
	if err != nil {
		return sn, port.RolloutSnapshot{}, domain.PolicyRollout{}, err
	}
	if sn.ScopeID != scope || sn.LiveRolloutID == nil || *sn.LiveRolloutID != id {
		return sn, port.RolloutSnapshot{}, domain.PolicyRollout{}, port.ErrStaleWrite
	}
	r, err := tx.LockRollout(ctx, scope, id)
	if err != nil {
		return sn, r, domain.PolicyRollout{}, err
	}
	if r.Scope != scope || r.ID != id || r.State != domain.RolloutMonitoring || r.LastActivationEpoch != sn.ActivationEpoch {
		return sn, r, domain.PolicyRollout{}, port.ErrStaleWrite
	}
	if err = tx.ValidateTargets(ctx, scope, targetSnapshotIDs(r.Targets)); err != nil {
		return sn, r, domain.PolicyRollout{}, err
	}
	ro := rolloutDomain(sn, r)
	if !targetsHaveLockedRoots(sn, r.Targets) || ro.Monitoring.Validate() != nil {
		return sn, r, ro, domain.ErrInvalidMonitoring
	}
	_, _, err = domain.Rollback(snapshotAuthority(sn), ro)
	return sn, r, ro, err
}

func monitoringResult(commandID string, sn port.ScopeSnapshot, r port.RolloutSnapshot, outcome domain.MonitoringOutcome) MonitoringResult {
	return MonitoringResult{CommandID: commandID, Scope: sn.ScopeID, Rollout: r.ID, ScopeEpoch: sn.ActivationEpoch, State: r.State, Mode: sn.Mode, Outcome: outcome, Monitoring: r.Monitoring}
}

// persistMonitoring applies the selected exit using the already locked state.
// There are no nested transactions, ordinary Candidate approvals, or worker clocks.
func persistMonitoring(ctx context.Context, tx port.GovernanceTx, lkg LKGVerifier, sn port.ScopeSnapshot, r port.RolloutSnapshot, next domain.PolicyRollout, outcome domain.MonitoringOutcome, commandID string) (MonitoringResult, error) {
	ns := sn
	nr := rolloutSnapshot(next, r, ns)
	var err error
	switch outcome {
	case domain.MonitoringContinue:
	case domain.MonitoringComplete:
		ns.LiveRolloutID = nil
	case domain.MonitoringSafeRollback:
		ns, nr, err = safeRollbackSnapshots(ctx, lkg, sn, r, next)
		if err != nil {
			return MonitoringResult{}, err
		}
	default:
		return MonitoringResult{}, domain.ErrInvalidMonitoring
	}
	if ns.LiveRolloutID == nil {
		if err = tx.CompareAndSwapScope(ctx, sn, ns); err != nil {
			return MonitoringResult{}, err
		}
	}
	if err = tx.CompareAndSwapRollout(ctx, r, nr); err != nil {
		return MonitoringResult{}, err
	}
	result := monitoringResult(commandID, ns, nr, outcome)
	if nr.Monitoring.DecisionRevision != r.Monitoring.DecisionRevision {
		if err = appendMonitoringEvent(ctx, tx, result, "rollout-decision", "MonitoringDecisionRecorded", nr.Monitoring.DecisionRevision); err != nil {
			return MonitoringResult{}, err
		}
	}
	if outcome != domain.MonitoringContinue {
		if err = appendMonitoringEvent(ctx, tx, result, "rollout-monitoring-terminal", "MonitoringTerminated", 1); err != nil {
			return MonitoringResult{}, err
		}
	}
	return result, nil
}

func appendMonitoringEvent(ctx context.Context, tx port.GovernanceTx, result MonitoringResult, kind, eventType string, version int64) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	// IDs may themselves contain '/'; length-prefix the Scope to avoid
	// cross-Scope composite-key collisions in the immutable event stream.
	aggregate := strconv.Itoa(len(result.Scope)) + ":" + string(result.Scope) + string(result.Rollout)
	ev, err := domain.NewEvent(kind+"/"+aggregate+"/"+strconv.FormatInt(version, 10), kind, aggregate, version, eventType, "paddock.monitoring-event/1", b)
	if err != nil {
		return err
	}
	return tx.AppendEvent(ctx, ev)
}

func (s *MonitoringService) RecordDecision(ctx context.Context, q MonitoringDecisionRequest) (MonitoringResult, error) {
	if s == nil || s.tx == nil || ctx == nil {
		return MonitoringResult{}, errors.New("monitoring service/context is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return MonitoringResult{}, err
	}
	// Decimal revision mirrors the signing protocol and supports full int64.
	payload := struct {
		Operation                 string
		Scope                     domain.ScopeID
		Rollout                   domain.RolloutID
		ScopeEpoch, SecurityEpoch domain.Epoch
		Revision                  string
		Gate                      domain.CanaryGateInput
	}{"MONITORING_DECISION", q.Scope, q.Rollout, q.ExpectedScopeEpoch, q.ExpectedSecurityEpoch, strconv.FormatInt(q.ExpectedDecisionRevision, 10), q.Gate}
	digest, err := commandDigest(q.CommandID, q.Nonce, payload)
	if err != nil {
		return MonitoringResult{}, normalizeCommandFailure(fmt.Errorf("prepare monitoring decision %s/%s: %w", q.Scope, q.Rollout, err))
	}
	var result MonitoringResult
	err = withinReceiptCommand(ctx, q.CommandID, digest, s.tx.WithinTransaction,
		func(_ port.GovernanceTx, b []byte) error { return unmarshalCommandResult(b, &result) },
		func(tx port.GovernanceTx) error {
			sn, r, ro, err := lockMonitoring(ctx, tx, q.Scope, q.Rollout)
			if err != nil {
				return err
			}
			if sn.ActivationEpoch != q.ExpectedScopeEpoch || sn.SecurityEpoch != q.ExpectedSecurityEpoch || r.Monitoring.DecisionRevision != q.ExpectedDecisionRevision {
				return port.ErrStaleWrite
			}
			now, err := tx.DatabaseTime(ctx)
			if err != nil {
				return err
			}
			// Expired HOLD cannot be revived by a late decision. Persist ABORT and
			// its safe exit rather than returning a denial that leaves it stuck.
			if ro.Monitoring.Decision == domain.DecisionHold && !now.Before(ro.Monitoring.HoldDeadline) {
				var outcome domain.MonitoringOutcome
				ro, outcome, err = domain.EvaluateMonitoring(ro, now)
				if err != nil {
					return err
				}
				result, err = persistMonitoring(ctx, tx, s.lkg, sn, r, ro, outcome, q.CommandID)
			} else {
				evidence, e := canonicalGateEvidence(q.Gate)
				if e != nil {
					return e
				}
				gate := domain.EvaluateCanaryGate(q.Gate)
				ro, err = domain.RecordMonitoringDecision(ro, domain.MonitoringDecision(gate.Outcome), evidence, now)
				if err != nil {
					return err
				}
				var outcome domain.MonitoringOutcome
				ro, outcome, err = domain.EvaluateMonitoring(ro, now)
				if err != nil {
					return err
				}
				result, err = persistMonitoring(ctx, tx, s.lkg, sn, r, ro, outcome, q.CommandID)
			}
			if err != nil {
				return err
			}
			b, err := marshalCommandResult(result)
			if err != nil {
				return err
			}
			return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: q.CommandID, RequestDigest: digest, Status: "SUCCEEDED", Response: b})
		})
	if err != nil {
		return MonitoringResult{}, normalizeCommandFailure(fmt.Errorf("record monitoring decision %s/%s: %w", q.Scope, q.Rollout, err))
	}
	return result, nil
}
