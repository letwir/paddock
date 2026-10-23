package domain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
)

func TestRolloutTransitionApprovalCanonicalRootsAndBinding(t *testing.T) {
	s, privs := fixtureKernel(t)
	kd, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateFor(t, TierG0)
	base := RolloutTransitionApproval{
		Scope: "scope", Roots: []RootID{"root-b", "root-a"}, ScopeEpoch: 3, SecurityEpoch: 4,
		RootEpochs: map[RootID]Epoch{"root-a": 5, "root-b": 6}, RolloutID: "rollout",
		RolloutState: RolloutCanary, CandidateDigest: candidate.Bundle.Digest(), KernelDigest: kd,
		Tier: TierG0, ProposerID: "proposer", ProposalID: "proposal", Nonce: "nonce",
	}
	msg, err := base.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	reordered := base
	reordered.Roots = []RootID{"root-a", "root-b"}
	msg2, err := reordered.SigningBytes()
	if err != nil || !bytes.Equal(msg, msg2) {
		t.Fatalf("root order changed bytes: %v", err)
	}
	base.Approvals = []DomainApproval{
		{SignerID: "a", Signature: ed25519.Sign(privs[0], msg)},
		{SignerID: "b", Signature: ed25519.Sign(privs[1], msg)},
	}
	if got := VerifyRolloutTransitionApproval(s, kd, base); !got.Accepted {
		t.Fatalf("valid approval rejected: %+v", got)
	}

	otherBundle, err := NewCanonicalBundle(BundleSchemaVersion, []byte(`{"policy":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	otherKernel := s
	otherKernel.Version++
	otherKernelDigest, err := otherKernel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*RolloutTransitionApproval)
	}{
		{"Scope", func(a *RolloutTransitionApproval) { a.Scope = "other-scope" }},
		{"Root membership", func(a *RolloutTransitionApproval) {
			a.Roots = []RootID{"root-a", "root-c"}
			a.RootEpochs = map[RootID]Epoch{"root-a": 5, "root-c": 6}
		}},
		{"ScopeEpoch", func(a *RolloutTransitionApproval) { a.ScopeEpoch++ }},
		{"SecurityEpoch", func(a *RolloutTransitionApproval) { a.SecurityEpoch++ }},
		{"RootEpoch root-a", func(a *RolloutTransitionApproval) { a.RootEpochs["root-a"]++ }},
		{"RootEpoch root-b", func(a *RolloutTransitionApproval) { a.RootEpochs["root-b"]++ }},
		{"RolloutID", func(a *RolloutTransitionApproval) { a.RolloutID = "other-rollout" }},
		{"RolloutState", func(a *RolloutTransitionApproval) { a.RolloutState = RolloutMonitoring }},
		{"CandidateDigest", func(a *RolloutTransitionApproval) { a.CandidateDigest = otherBundle.Digest() }},
		{"KernelDigest", func(a *RolloutTransitionApproval) { a.KernelDigest = otherKernelDigest }},
		{"Tier", func(a *RolloutTransitionApproval) { a.Tier = TierG1 }},
		{"ProposerID", func(a *RolloutTransitionApproval) { a.ProposerID = "other-proposer" }},
		{"ProposalID", func(a *RolloutTransitionApproval) { a.ProposalID = "other-proposal" }},
		{"Nonce", func(a *RolloutTransitionApproval) { a.Nonce = "other-nonce" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			mutated.Roots = append([]RootID(nil), base.Roots...)
			mutated.RootEpochs = make(map[RootID]Epoch, len(base.RootEpochs))
			for root, epoch := range base.RootEpochs {
				mutated.RootEpochs[root] = epoch
			}
			tc.mutate(&mutated)
			if got := VerifyRolloutTransitionApproval(s, kd, mutated); got.Accepted {
				t.Fatalf("approval accepted after %s mutation", tc.name)
			}
		})
	}
}

func TestRolloutTransitionApprovalRejectsAlternateOperation(t *testing.T) {
	s, privs := fixtureKernel(t)
	kd, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateFor(t, TierG0)
	approval := RolloutTransitionApproval{
		Scope: "scope", Roots: []RootID{"root-a", "root-b"}, ScopeEpoch: 3, SecurityEpoch: 4,
		RootEpochs: map[RootID]Epoch{"root-a": 5, "root-b": 6}, RolloutID: "rollout",
		RolloutState: RolloutCanary, CandidateDigest: candidate.Bundle.Digest(), KernelDigest: kd,
		Tier: TierG0, ProposerID: "proposer", ProposalID: "proposal", Nonce: "nonce",
	}
	type rootEpoch struct {
		Root  RootID `json:"root"`
		Epoch Epoch  `json:"epoch"`
	}
	roots := []rootEpoch{{Root: "root-a", Epoch: 5}, {Root: "root-b", Epoch: 6}}
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
	}{"ROLLBACK", approval.Scope, roots, approval.ScopeEpoch, approval.SecurityEpoch, approval.RolloutID, approval.RolloutState, approval.CandidateDigest, approval.KernelDigest, approval.Tier, approval.ProposerID, approval.ProposalID}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	codec := canonical.NewJCSCodec()
	canonicalPayload, err := codec.CanonicalizeJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	message, err := canonical.Envelope(codec, canonical.DomainApproval, canonical.Context{
		SchemaVersion: RolloutTransitionApprovalSchema, Audience: "governance", RequestID: approval.ProposalID, Nonce: approval.Nonce,
	}, canonicalPayload)
	if err != nil {
		t.Fatal(err)
	}
	approval.Approvals = []DomainApproval{
		{SignerID: "a", Signature: ed25519.Sign(privs[0], message)},
		{SignerID: "b", Signature: ed25519.Sign(privs[1], message)},
	}
	if got := VerifyRolloutTransitionApproval(s, kd, approval); got.Accepted {
		t.Fatal("approval signed for ROLLBACK operation accepted as PROMOTE")
	}
}
