package application

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type ProposeRequest struct {
	CommandID, Nonce                    string
	Scope                               domain.ScopeID
	ProposalID, ProposerID, BundleKeyID string
	Bundle                              domain.CanonicalBundle
	Signature                           []byte
}

func targetsHaveLockedRoots(s port.ScopeSnapshot, targets map[domain.RootID]port.RolloutTargetSnapshot) bool {
	if len(targets) == 0 {
		return false
	}
	for id := range targets {
		if _, ok := s.Roots[id]; !ok {
			return false
		}
	}
	return true
}

func targetSnapshotIDs(m map[domain.RootID]port.RolloutTargetSnapshot) []domain.RootID {
	a := make([]domain.RootID, 0, len(m))
	for id := range m {
		a = append(a, id)
	}
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	return a
}
func lockedTargetEpochs(s port.ScopeSnapshot, targets map[domain.RootID]port.RolloutTargetSnapshot) map[domain.RootID]domain.Epoch {
	out := make(map[domain.RootID]domain.Epoch, len(targets))
	for id := range targets {
		if root, ok := s.Roots[id]; ok {
			out[id] = root.AuthorizationEpoch
		}
	}
	return out
}

func sameEpochMap(a, b map[domain.RootID]domain.Epoch) bool { return reflect.DeepEqual(a, b) }
func sameRootSet(a, b []domain.RootID) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]domain.RootID(nil), a...)
	y := append([]domain.RootID(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	return reflect.DeepEqual(x, y)
}
func lockedRootEpochs(s port.ScopeSnapshot) map[domain.RootID]domain.Epoch {
	out := make(map[domain.RootID]domain.Epoch, len(s.Roots))
	for id, r := range s.Roots {
		out[id] = r.AuthorizationEpoch
	}
	return out
}

type ProposeResult struct {
	CommandID    string
	ProposalID   string
	BundleDigest domain.Digest
}
type StartCanaryRequest struct {
	CommandID, Nonce                                             string
	Scope                                                        domain.ScopeID
	Rollout                                                      domain.RolloutID
	Root                                                         domain.RootID
	Candidate                                                    domain.DomainCandidate
	ExpectedScopeEpoch, ExpectedRootEpoch, ExpectedSecurityEpoch domain.Epoch
	Approvals                                                    []domain.DomainApproval
}
type StartCanaryResult struct {
	CommandID             string
	State                 domain.RolloutState
	ScopeEpoch, RootEpoch domain.Epoch
}
type PromoteRequest struct {
	CommandID, Nonce                          string
	Scope                                     domain.ScopeID
	Rollout                                   domain.RolloutID
	ExpectedState                             domain.RolloutState
	ExpectedScopeEpoch, ExpectedSecurityEpoch domain.Epoch
	ExpectedRootEpochs                        map[domain.RootID]domain.Epoch
	Candidate                                 domain.DomainCandidate
	CandidateApprovals                        []domain.DomainApproval
	Approval                                  domain.RolloutTransitionApproval
}
type PromoteResult struct {
	CommandID  string
	State      domain.RolloutState
	ScopeEpoch domain.Epoch
}
type RollbackRequest struct {
	CommandID, Nonce                          string
	Scope                                     domain.ScopeID
	Rollout                                   domain.RolloutID
	ExpectedState                             domain.RolloutState
	ExpectedScopeEpoch, ExpectedSecurityEpoch domain.Epoch
	ExpectedRootEpochs                        map[domain.RootID]domain.Epoch
}
type RollbackResult struct {
	CommandID  string
	State      domain.RolloutState
	ScopeEpoch domain.Epoch
	Mode       domain.ScopeMode
}

type LKGVerifier interface {
	VerifyLKG(context.Context, domain.Digest) (domain.LKGAssessment, error)
}
type RolloutService struct {
	tx           port.RolloutTransactor
	bundles      *BundleRegistrationService
	lkg          LKGVerifier
	kernel       domain.KernelSnapshot
	kernelDigest domain.Digest
}

func cloneKernelSnapshot(k domain.KernelSnapshot) domain.KernelSnapshot {
	k.Signers = append([]domain.KernelSigner(nil), k.Signers...)
	for i := range k.Signers {
		k.Signers[i].PublicKey = append([]byte(nil), k.Signers[i].PublicKey...)
	}
	k.Thresholds = append([]domain.TierThreshold(nil), k.Thresholds...)
	k.Capabilities = append([]string(nil), k.Capabilities...)
	k.IssuerCeilings = append([]domain.IssuerCeiling(nil), k.IssuerCeilings...)
	for i := range k.IssuerCeilings {
		k.IssuerCeilings[i].Capabilities = append([]string(nil), k.IssuerCeilings[i].Capabilities...)
	}
	return k
}

func NewRolloutService(tx port.RolloutTransactor, bundles *BundleRegistrationService, lkg LKGVerifier, kernel domain.KernelSnapshot, expectedDigest domain.Digest) (service *RolloutService, err error) {
	defer func() { err = normalizeCommandFailure(err) }()
	if tx == nil {
		return nil, errors.New("rollout transactor is not initialized")
	}
	d, err := kernel.Digest()
	if err != nil {
		return nil, commandFailure(FailureInvalid, err)
	}
	if err = expectedDigest.Validate(); err != nil {
		return nil, err
	}
	if d != expectedDigest {
		return nil, commandFailure(FailureInvalid, errors.New("kernel snapshot digest mismatch"))
	}
	if err = validateKernelForService(kernel); err != nil {
		return nil, commandFailure(FailureInvalid, err)
	}
	return &RolloutService{tx: tx, bundles: bundles, lkg: lkg, kernel: cloneKernelSnapshot(kernel), kernelDigest: expectedDigest}, nil
}

func validateKernelForService(k domain.KernelSnapshot) error {
	if _, err := k.CanonicalBytes(); err != nil {
		return err
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, signer := range k.Signers {
		if domain.ScopeID(signer.ID).Validate() != nil || len(signer.PublicKey) != ed25519.PublicKeySize || ids[signer.ID] || keys[string(signer.PublicKey)] {
			return errors.New("malformed kernel signer set")
		}
		ids[signer.ID], keys[string(signer.PublicKey)] = true, true
	}
	seenTiers := map[domain.GovernanceTier]bool{}
	for _, threshold := range k.Thresholds {
		if (threshold.Tier != domain.TierG0 && threshold.Tier != domain.TierG1) || threshold.Threshold < 1 || threshold.Threshold > len(k.Signers) || seenTiers[threshold.Tier] {
			return errors.New("malformed kernel thresholds")
		}
		seenTiers[threshold.Tier] = true
	}
	if len(seenTiers) != 2 {
		return errors.New("missing kernel thresholds")
	}
	capabilities := map[string]bool{}
	for _, capability := range k.Capabilities {
		if !kernelCapabilityID.MatchString(capability) || capabilities[capability] {
			return errors.New("malformed kernel capabilities")
		}
		capabilities[capability] = true
	}
	if len(capabilities) == 0 {
		return errors.New("missing kernel capabilities")
	}
	issuers := map[string]bool{}
	for _, ceiling := range k.IssuerCeilings {
		if domain.ScopeID(ceiling.IssuerID).Validate() != nil || issuers[ceiling.IssuerID] {
			return errors.New("malformed kernel issuer ceilings")
		}
		issuers[ceiling.IssuerID] = true
		seen := map[string]bool{}
		for _, capability := range ceiling.Capabilities {
			if !capabilities[capability] || seen[capability] {
				return errors.New("malformed kernel issuer capabilities")
			}
			seen[capability] = true
		}
	}
	return nil
}

var kernelCapabilityID = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$`)

func (s *RolloutService) checkKernel() error {
	if s == nil {
		return errors.New("rollout service is not initialized")
	}
	d, err := s.kernel.Digest()
	if err != nil || d != s.kernelDigest {
		return errors.New("pinned kernel integrity check failed")
	}
	return nil
}

func commandDigest(id, nonce string, payload any) (domain.Digest, error) {
	b, e := json.Marshal(payload)
	if e != nil {
		return "", e
	}
	r, e := domain.NewCanonicalRequest(id, nonce, b)
	if e != nil {
		return "", e
	}
	return r.Digest(), nil
}

// CanonicalBundle has private fields, so encoding/json sees only {}. These
// digest-only projections bind its metadata and bytes without changing public
// request serialization or the canonical command envelope.
type commandBundle struct {
	SchemaVersion, BundleID, Nonce string
	CanonicalBytes, SigningBytes   []byte
	Digest                         domain.Digest
}

func bundleForCommand(b domain.CanonicalBundle) commandBundle {
	return commandBundle{b.SchemaVersion(), b.BundleID(), b.Nonce(), b.CanonicalBytes(), b.SigningBytes(), b.Digest()}
}

type commandCandidate struct {
	domain.DomainCandidate
	Bundle commandBundle
}

type commandStartCanaryRequest struct {
	StartCanaryRequest
	Candidate commandCandidate
}

type commandPromoteRequest struct {
	PromoteRequest
	Candidate commandCandidate
}

func proposeCommandDigest(q ProposeRequest) (domain.Digest, error) {
	return commandDigest(q.CommandID, q.Nonce, struct {
		ProposeRequest
		Bundle commandBundle
	}{q, bundleForCommand(q.Bundle)})
}

func startCanaryCommandDigest(q StartCanaryRequest, proposer domain.ProposalContext) (domain.Digest, error) {
	return commandDigest(q.CommandID, q.Nonce, struct {
		Request  commandStartCanaryRequest
		Proposer domain.ProposalContext
	}{commandStartCanaryRequest{q, commandCandidate{q.Candidate, bundleForCommand(q.Candidate.Bundle)}}, proposer})
}

func promoteCommandDigest(q PromoteRequest, candidateProposer, transitionProposer domain.ProposalContext) (domain.Digest, error) {
	return commandDigest(q.CommandID, q.Nonce, struct {
		Request                               commandPromoteRequest
		CandidateProposer, TransitionProposer domain.ProposalContext
	}{commandPromoteRequest{q, commandCandidate{q.Candidate, bundleForCommand(q.Candidate.Bundle)}}, candidateProposer, transitionProposer})
}

func (s *RolloutService) ready(ctx context.Context) error {
	if s == nil || s.tx == nil {
		return errors.New("rollout service is not initialized")
	}
	if ctx == nil {
		return commandFailure(FailureInvalid, errors.New("nil context"))
	}
	return ctx.Err()
}
func persistCommand(ctx context.Context, tx port.GovernanceTx, id string, d domain.Digest, result any, eventType string, scope domain.ScopeID, version domain.Epoch) error {
	b, e := marshalCommandResult(result)
	if e != nil {
		return e
	}
	if e = tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: id, RequestDigest: d, Status: "SUCCEEDED", Response: b}); e != nil {
		return e
	}
	evPayload, e := json.Marshal(result)
	if e != nil {
		return e
	}
	kind, aggregateID := "scope", string(scope)
	if eventType == "PolicyProposed" {
		kind, aggregateID = "proposal", result.(ProposeResult).ProposalID
	}
	ev, e := domain.NewEvent("rollout/"+id, kind, aggregateID, int64(version), eventType, "paddock.rollout-event/1", evPayload)
	if e != nil {
		return e
	}
	return tx.AppendEvent(ctx, ev)
}
func rolloutDomain(s port.ScopeSnapshot, r port.RolloutSnapshot) domain.PolicyRollout {
	out := domain.PolicyRollout{ID: r.ID, Scope: r.Scope, State: r.State, BaseActivation: r.BaseActivationEpoch, BaseSecurityEpoch: r.BaseSecurityEpoch, Baseline: map[domain.RootID]domain.PolicyBinding{}, Candidate: map[domain.RootID]domain.PolicyBinding{}, BaseRootEpochs: map[domain.RootID]domain.Epoch{}}
	out.Monitoring = r.Monitoring
	if r.RollbackFrom != nil {
		out.RollbackFrom = *r.RollbackFrom
	}
	if r.TargetRoot != nil {
		out.Target = *r.TargetRoot
	}
	for id, t := range r.Targets {
		out.Baseline[id] = t.Baseline
		out.Candidate[id] = t.Candidate
		out.BaseRootEpochs[id] = t.BaseRootEpoch
	}
	return out
}
func rolloutSnapshot(r domain.PolicyRollout, old port.RolloutSnapshot, state port.ScopeSnapshot) port.RolloutSnapshot {
	n := old
	n.State = r.State
	n.Monitoring = r.Monitoring
	n.LastActivationEpoch = state.ActivationEpoch
	n.RollbackFrom = nil
	if r.RollbackFrom != "" {
		v := r.RollbackFrom
		n.RollbackFrom = &v
	}
	return n
}
func (s *RolloutService) Propose(ctx context.Context, q ProposeRequest) (result ProposeResult, err error) {
	defer func() { err = normalizeCommandFailure(err) }()
	if e := s.ready(ctx); e != nil {
		return ProposeResult{}, e
	}
	if s.bundles == nil {
		return ProposeResult{}, errors.New("bundle registration service unavailable")
	}
	digest, e := proposeCommandDigest(q)
	if e != nil {
		return ProposeResult{}, e
	}
	var out ProposeResult
	e = withinReceiptCommand(ctx, q.CommandID, digest, s.tx.WithinRolloutTransaction,
		func(_ port.RolloutTx, b []byte) error { return unmarshalCommandResult(b, &out) }, func(tx port.RolloutTx) error {
			if e := s.checkKernel(); e != nil {
				return e
			}
			if e := s.checkKernel(); e != nil {
				return e
			}
			if e := q.Scope.Validate(); e != nil {
				return denyReceipt(e)
			}
			// These checks have no typed signal in BundleRegistrationService. Mark
			// only the known input failures here, never arbitrary resolver/DB errors.
			if q.BundleKeyID == "" || strings.TrimSpace(q.BundleKeyID) != q.BundleKeyID {
				return denyReceipt(commandFailure(FailureInvalid, errors.New("invalid bundle signer key ID")))
			}
			if e := q.Bundle.Validate(); e != nil {
				return denyReceipt(e)
			}
			if q.Bundle.SchemaVersion() != domain.BundleSchemaVersion {
				return denyReceipt(commandFailure(FailureInvalid, errors.New("unsupported bundle schema version")))
			}
			guard := &receiptBundleTx{GovernanceTx: tx}
			bd, e := s.bundles.RegisterWithin(ctx, guard, q.Bundle, q.BundleKeyID, q.Signature)
			if e != nil {
				if !guard.writeAttempted {
					return denyReceipt(e)
				}
				return e
			}
			out = ProposeResult{CommandID: q.CommandID, ProposalID: q.ProposalID, BundleDigest: bd}
			if e = persistCommand(ctx, tx, q.CommandID, digest, out, "PolicyProposed", q.Scope, 1); e != nil {
				return e
			}
			return nil
		})
	return out, e
}
func (s *RolloutService) StartCanary(ctx context.Context, q StartCanaryRequest, proposer domain.ProposalContext) (result StartCanaryResult, err error) {
	defer func() { err = normalizeCommandFailure(err) }()
	if e := s.ready(ctx); e != nil {
		return StartCanaryResult{}, e
	}
	if e := s.checkKernel(); e != nil {
		return StartCanaryResult{}, e
	}
	return s.startCanary(ctx, q, proposer)
}

func (s *RolloutService) startCanary(ctx context.Context, q StartCanaryRequest, proposer domain.ProposalContext) (StartCanaryResult, error) {
	d, e := startCanaryCommandDigest(q, proposer)
	if e != nil {
		return StartCanaryResult{}, e
	}
	var out StartCanaryResult
	e = withinReceiptCommand(ctx, q.CommandID, d, s.tx.WithinRolloutTransaction,
		func(_ port.RolloutTx, b []byte) error { return unmarshalCommandResult(b, &out) }, func(tx port.RolloutTx) error {
			if e := q.Scope.Validate(); e != nil {
				return denyReceipt(e)
			}
			snap, e := tx.LockScope(ctx, q.Scope)
			if e != nil {
				return e
			}
			// Receipt replay must remain possible after this command occupied the
			// slot. For a new command, decide BUSY from the locked Scope before writes.
			if snap.LiveRolloutID != nil {
				return commandFailure(FailureBusy, errors.New("scope active rollout slot is occupied"))
			}
			if snap.ActivationEpoch != q.ExpectedScopeEpoch || snap.SecurityEpoch != q.ExpectedSecurityEpoch {
				return port.ErrStaleWrite
			}
			root, ok := snap.Roots[q.Root]
			if !ok || root.AuthorizationEpoch != q.ExpectedRootEpoch {
				return port.ErrStaleWrite
			}
			if e = tx.ValidateTargets(ctx, q.Scope, []domain.RootID{q.Root}); e != nil {
				return e
			}
			ev := domain.VerifyDomainApproval(s.kernel, s.kernelDigest, q.Candidate, proposer, q.Approvals)
			if !ev.Accepted {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			next, ro, e := domain.StartCanary(snapshotAuthority(snap), q.Rollout, q.Root, q.Candidate.Bundle.Digest())
			if e != nil {
				return denyReceipt(e)
			}
			sn := snapshotWithState(snap, next)
			sn.LiveRolloutID = &q.Rollout
			rs := port.RolloutSnapshot{ID: ro.ID, Scope: ro.Scope, State: ro.State, TargetRoot: &ro.Target, BaseActivationEpoch: ro.BaseActivation, LastActivationEpoch: next.ScopeActivationEpoch, BaseSecurityEpoch: ro.BaseSecurityEpoch, Targets: map[domain.RootID]port.RolloutTargetSnapshot{}}
			for id, b := range ro.Baseline {
				rs.Targets[id] = port.RolloutTargetSnapshot{Baseline: b, Candidate: ro.Candidate[id], BaseRootEpoch: ro.BaseRootEpochs[id]}
			}
			if e = tx.CreateRollout(ctx, rs); e != nil {
				return e
			}
			if e = tx.CompareAndSwapScope(ctx, snap, sn); e != nil {
				return e
			}
			out = StartCanaryResult{CommandID: q.CommandID, State: ro.State, ScopeEpoch: next.ScopeActivationEpoch, RootEpoch: next.Roots[q.Root].AuthorizationEpoch}
			return persistCommand(ctx, tx, q.CommandID, d, out, "RolloutCanaryStarted", q.Scope, next.ScopeActivationEpoch)
		})
	return out, e
}
func (s *RolloutService) Promote(ctx context.Context, q PromoteRequest, candidateProposer, transitionProposer domain.ProposalContext) (result PromoteResult, err error) {
	defer func() { err = normalizeCommandFailure(err) }()
	if e := s.ready(ctx); e != nil {
		return PromoteResult{}, e
	}
	if e := s.checkKernel(); e != nil {
		return PromoteResult{}, e
	}
	d, e := promoteCommandDigest(q, candidateProposer, transitionProposer)
	if e != nil {
		return PromoteResult{}, e
	}
	var out PromoteResult
	e = withinReceiptCommand(ctx, q.CommandID, d, s.tx.WithinRolloutTransaction,
		func(_ port.RolloutTx, b []byte) error { return unmarshalCommandResult(b, &out) }, func(tx port.RolloutTx) error {
			if e := q.Scope.Validate(); e != nil {
				return denyReceipt(e)
			}
			sn, e := tx.LockScope(ctx, q.Scope)
			if e != nil {
				return e
			}
			if sn.LiveRolloutID == nil || *sn.LiveRolloutID != q.Rollout {
				return port.ErrStaleWrite
			}
			r, e := tx.LockRollout(ctx, q.Scope, q.Rollout)
			if e != nil {
				return e
			}
			if e = tx.ValidateTargets(ctx, q.Scope, targetSnapshotIDs(r.Targets)); e != nil {
				return e
			}
			lockedEpochs := lockedTargetEpochs(sn, r.Targets)
			lockedIDs := targetSnapshotIDs(r.Targets)
			if sn.ScopeID != q.Scope || r.Scope != q.Scope || r.ID != q.Rollout || !targetsHaveLockedRoots(sn, r.Targets) || sn.ActivationEpoch != q.ExpectedScopeEpoch || sn.SecurityEpoch != q.ExpectedSecurityEpoch || r.State != q.ExpectedState || !sameEpochMap(q.ExpectedRootEpochs, lockedEpochs) {
				return port.ErrStaleWrite
			}
			ro := rolloutDomain(sn, r)
			kd, err := s.kernel.Digest()
			if err != nil || kd != s.kernelDigest {
				return errors.New("pinned kernel integrity check failed")
			}
			if q.Approval.ProposerID != transitionProposer.ProposerID || q.Approval.Scope != q.Scope || q.Approval.RolloutID != q.Rollout || q.Approval.RolloutState != q.ExpectedState || q.Approval.ScopeEpoch != q.ExpectedScopeEpoch || q.Approval.SecurityEpoch != q.ExpectedSecurityEpoch || q.Approval.KernelDigest != s.kernelDigest || q.Approval.Nonce != q.Nonce || q.Approval.ProposalID != q.Candidate.ProposalID || q.Approval.CandidateDigest != q.Candidate.Bundle.Digest() || q.Approval.Tier != q.Candidate.Tier {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			if !sameEpochMap(q.ExpectedRootEpochs, q.Approval.RootEpochs) || !sameEpochMap(q.Approval.RootEpochs, lockedEpochs) || !sameRootSet(q.Approval.Roots, lockedIDs) {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			candidateEvidence := domain.VerifyDomainApproval(s.kernel, s.kernelDigest, q.Candidate, candidateProposer, q.CandidateApprovals)
			if !candidateEvidence.Accepted {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			if candidateEvidence.CandidateDigest != q.Approval.CandidateDigest {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			if r.TargetRoot == nil || q.Candidate.Bundle.Digest() != q.Approval.CandidateDigest {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			if _, ok := r.Targets[*r.TargetRoot]; !ok {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			for _, target := range r.Targets {
				if target.Candidate.SafeBaseline || target.Candidate.Digest != q.Approval.CandidateDigest {
					return denyReceipt(domain.ErrInvalidApproval)
				}
			}
			ev := domain.VerifyRolloutTransitionApproval(s.kernel, s.kernelDigest, q.Approval)
			if !ev.Accepted {
				return denyReceipt(domain.ErrInvalidApproval)
			}
			next, nro, e := domain.Promote(snapshotAuthority(sn), ro)
			if e != nil {
				return denyReceipt(e)
			}
			dbNow, e := tx.DatabaseTime(ctx)
			if e != nil {
				return e
			}
			nro, e = domain.StartMonitoring(nro, dbNow)
			if e != nil {
				return e
			}
			ns := snapshotWithState(sn, next)
			nr := rolloutSnapshot(nro, r, ns)
			if e = tx.CompareAndSwapScope(ctx, sn, ns); e != nil {
				return e
			}
			if e = tx.CompareAndSwapRollout(ctx, r, nr); e != nil {
				return e
			}
			out = PromoteResult{CommandID: q.CommandID, State: nro.State, ScopeEpoch: next.ScopeActivationEpoch}
			return persistCommand(ctx, tx, q.CommandID, d, out, "RolloutPromoted", q.Scope, next.ScopeActivationEpoch)
		})
	return out, e
}
func (s *RolloutService) Rollback(ctx context.Context, q RollbackRequest) (result RollbackResult, err error) {
	defer func() { err = normalizeCommandFailure(err) }()
	if e := s.ready(ctx); e != nil {
		return RollbackResult{}, e
	}
	if e := s.checkKernel(); e != nil {
		return RollbackResult{}, e
	}
	d, e := commandDigest(q.CommandID, q.Nonce, q)
	if e != nil {
		return RollbackResult{}, e
	}
	var out RollbackResult
	e = withinReceiptCommand(ctx, q.CommandID, d, s.tx.WithinRolloutTransaction,
		func(_ port.RolloutTx, b []byte) error { return unmarshalCommandResult(b, &out) }, func(tx port.RolloutTx) error {
			if e := q.Scope.Validate(); e != nil {
				return denyReceipt(e)
			}
			sn, e := tx.LockScope(ctx, q.Scope)
			if e != nil {
				return e
			}
			if sn.LiveRolloutID == nil || *sn.LiveRolloutID != q.Rollout {
				return port.ErrStaleWrite
			}
			r, e := tx.LockRollout(ctx, q.Scope, q.Rollout)
			if e != nil {
				return e
			}
			if e = tx.ValidateTargets(ctx, q.Scope, targetSnapshotIDs(r.Targets)); e != nil {
				return e
			}
			if sn.ScopeID != q.Scope || r.Scope != q.Scope || r.ID != q.Rollout || !targetsHaveLockedRoots(sn, r.Targets) || sn.ActivationEpoch != q.ExpectedScopeEpoch || sn.SecurityEpoch != q.ExpectedSecurityEpoch || r.State != q.ExpectedState || !sameEpochMap(q.ExpectedRootEpochs, lockedTargetEpochs(sn, r.Targets)) {
				return port.ErrStaleWrite
			}
			ns, nr, e := safeRollbackSnapshots(ctx, s.lkg, sn, r, rolloutDomain(sn, r))
			if e != nil {
				return denyReceipt(e)
			}
			if e = tx.CompareAndSwapScope(ctx, sn, ns); e != nil {
				return e
			}
			if e = tx.CompareAndSwapRollout(ctx, r, nr); e != nil {
				return e
			}
			out = RollbackResult{CommandID: q.CommandID, State: nr.State, ScopeEpoch: ns.ActivationEpoch, Mode: ns.Mode}
			return persistCommand(ctx, tx, q.CommandID, d, out, "RolloutRolledBack", q.Scope, ns.ActivationEpoch)
		})
	return out, e
}

// safeRollbackSnapshots shares the existing preauthorized Rollback/LKG path.
// It has no persistence effects; callers CAS both snapshots and append their
// outcome event/receipt in the same transaction that locked the input rows.
func safeRollbackSnapshots(ctx context.Context, lkg LKGVerifier, sn port.ScopeSnapshot, r port.RolloutSnapshot, ro domain.PolicyRollout) (port.ScopeSnapshot, port.RolloutSnapshot, error) {
	frozen, ro, e := domain.Rollback(snapshotAuthority(sn), ro)
	if e != nil {
		return sn, r, e
	}
	assessment := domain.LKGAssessment{Status: domain.LKGUnavailable}
	digests := map[domain.Digest]bool{}
	for _, p := range ro.Baseline {
		if !p.SafeBaseline {
			digests[p.Digest] = true
		}
	}
	for d := range digests {
		if e := ctx.Err(); e != nil {
			return sn, r, e
		}
		if lkg != nil {
			a, err := lkg.VerifyLKG(ctx, d)
			if err == nil && a.Status == domain.LKGUsable && a.Digest == d {
				assessment = a
			} else {
				assessment = domain.LKGAssessment{Status: domain.LKGUnavailable}
			}
		}
		if assessment.Status != domain.LKGUsable {
			break
		}
	}
	if ctx.Err() != nil {
		return sn, r, ctx.Err()
	}
	final, nro, e := domain.FinalizePolicyRollback(frozen, ro, assessment.Status)
	if e != nil {
		return sn, r, e
	}
	ns := snapshotWithState(sn, final)
	ns.LiveRolloutID = nil
	return ns, rolloutSnapshot(nro, r, ns), nil
}
