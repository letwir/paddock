package domain

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/letwir/paddock/internal/canonical"
)

const RolloutTransitionApprovalSchema = "paddock.rollout-transition-approval/1"

type RolloutTransitionApproval struct {
	Scope                         ScopeID
	Roots                         []RootID
	ScopeEpoch, SecurityEpoch     Epoch
	RootEpochs                    map[RootID]Epoch
	RolloutID                     RolloutID
	RolloutState                  RolloutState
	CandidateDigest, KernelDigest Digest
	Tier                          GovernanceTier
	ProposerID, ProposalID, Nonce string
	Approvals                     []DomainApproval
}

func (a RolloutTransitionApproval) SigningBytes() ([]byte, error) {
	if a.Scope.Validate() != nil || a.RolloutID.Validate() != nil || a.RolloutState.Validate() != nil || a.CandidateDigest.Validate() != nil || a.KernelDigest.Validate() != nil || !validTier(a.Tier) || validateID(a.ProposerID) != nil || validateID(a.ProposalID) != nil || validateID(a.Nonce) != nil || len(a.Roots) == 0 || len(a.Roots) != len(a.RootEpochs) {
		return nil, fmt.Errorf("%w: malformed rollout approval context", ErrKernelApproval)
	}
	roots := append([]RootID(nil), a.Roots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
	for i, r := range roots {
		if r.Validate() != nil || (i > 0 && roots[i-1] == r) {
			return nil, fmt.Errorf("%w: invalid root set", ErrKernelApproval)
		}
	}
	type rootEpoch struct {
		Root  RootID `json:"root"`
		Epoch Epoch  `json:"epoch"`
	}
	re := make([]rootEpoch, len(roots))
	for i, r := range roots {
		e, ok := a.RootEpochs[r]
		if !ok {
			return nil, fmt.Errorf("%w: missing root epoch", ErrKernelApproval)
		}
		re[i] = rootEpoch{r, e}
	}
	payload := struct {
		Operation       string         `json:"operation"`
		Scope           ScopeID        `json:"scope"`
		Roots           []rootEpoch    `json:"roots"`
		ScopeEpoch      Epoch          `json:"scope_epoch"`
		SecurityEpoch   Epoch          `json:"security_epoch"`
		RolloutID       RolloutID      `json:"rollout_id"`
		RolloutState    RolloutState   `json:"rollout_state"`
		CandidateDigest Digest         `json:"candidate_digest"`
		KernelDigest    Digest         `json:"kernel_digest"`
		Tier            GovernanceTier `json:"tier"`
		ProposerID      string         `json:"proposer_id"`
		ProposalID      string         `json:"proposal_id"`
	}{"PROMOTE", a.Scope, re, a.ScopeEpoch, a.SecurityEpoch, a.RolloutID, a.RolloutState, a.CandidateDigest, a.KernelDigest, a.Tier, a.ProposerID, a.ProposalID}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(b)
	if err != nil {
		return nil, err
	}
	return canonical.Envelope(canonical.NewJCSCodec(), canonical.DomainApproval, canonical.Context{SchemaVersion: RolloutTransitionApprovalSchema, Audience: "governance", RequestID: a.ProposalID, Nonce: a.Nonce}, cb)
}

func VerifyRolloutTransitionApproval(snapshot KernelSnapshot, expectedKernel Digest, a RolloutTransitionApproval) ApprovalEvidence {
	msg, err := a.SigningBytes()
	if err != nil {
		return ApprovalEvidence{Tier: a.Tier, Reason: "invalid proposal context"}
	}
	if a.KernelDigest != expectedKernel {
		return ApprovalEvidence{Tier: a.Tier, KernelDigest: a.KernelDigest, Reason: "kernel digest mismatch"}
	}
	return VerifyKernelApprovalSignatures(snapshot, expectedKernel, a.Tier, a.ProposerID, msg, a.Approvals)
}
