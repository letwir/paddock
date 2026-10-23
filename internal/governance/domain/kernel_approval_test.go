package domain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func fixtureKernel(t *testing.T) (KernelSnapshot, []ed25519.PrivateKey) {
	t.Helper()
	signers := make([]KernelSigner, 3)
	privs := make([]ed25519.PrivateKey, 3)
	for i := range signers {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		signers[i] = KernelSigner{ID: string(rune('a' + i)), PublicKey: pub}
		privs[i] = priv
	}
	return KernelSnapshot{SchemaVersion: KernelSnapshotSchema, Version: 1, Signers: signers, Thresholds: []TierThreshold{{TierG0, 2}, {TierG1, 3}}, Capabilities: []string{"work.read", "work.write"}, IssuerCeilings: []IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"work.read", "work.write"}}}}, privs
}
func candidateFor(t *testing.T, tier GovernanceTier) DomainCandidate {
	t.Helper()
	b, e := NewCanonicalBundle(BundleSchemaVersion, []byte(`{"policy":"safe"}`))
	if e != nil {
		t.Fatal(e)
	}
	return DomainCandidate{Bundle: b, Tier: tier, IssuerID: "issuer", ProposalID: "proposal-1", Nonce: "nonce-1", CapabilityIDs: []string{"work.read"}}
}
func approvalFor(t *testing.T, c DomainCandidate, s KernelSnapshot, privs []ed25519.PrivateKey, ids ...int) []DomainApproval {
	t.Helper()
	d, e := s.Digest()
	if e != nil {
		t.Fatal(e)
	}
	msg, e := DomainApprovalSigningBytes(c, d, "proposer")
	if e != nil {
		t.Fatal(e)
	}
	out := make([]DomainApproval, len(ids))
	for i, n := range ids {
		out[i] = DomainApproval{SignerID: s.Signers[n].ID, Signature: ed25519.Sign(privs[n], msg)}
	}
	return out
}
func TestVerifyDomainApprovalThresholdsAndSelfApproval(t *testing.T) {
	s, p := fixtureKernel(t)
	d, _ := s.Digest()
	for _, tc := range []struct {
		tier GovernanceTier
		ids  []int
	}{{TierG0, []int{0, 1}}, {TierG1, []int{0, 1, 2}}} {
		c := candidateFor(t, tc.tier)
		got := VerifyDomainApproval(s, d, c, ProposalContext{ProposerID: "proposer"}, approvalFor(t, c, s, p, tc.ids...))
		if !got.Accepted {
			t.Fatalf("valid %s rejected: %+v", tc.tier, got)
		}
	}
	c := candidateFor(t, TierG0)
	a := approvalFor(t, c, s, p, 0, 1)
	a[0].SignerID = "proposer"
	if VerifyDomainApproval(s, d, c, ProposalContext{ProposerID: "proposer"}, a).Accepted {
		t.Fatal("self approval accepted")
	}
}
func TestApprovalContextBindingAndTampering(t *testing.T) {
	s, p := fixtureKernel(t)
	d, _ := s.Digest()
	base := candidateFor(t, TierG0)
	msg, _ := DomainApprovalSigningBytes(base, d, "proposer")
	sig := []DomainApproval{{SignerID: "a", Signature: ed25519.Sign(p[0], msg)}, {SignerID: "b", Signature: ed25519.Sign(p[1], msg)}}
	if VerifyDomainApproval(s, d, base, ProposalContext{ProposerID: "proposer"}, sig).Accepted != true {
		t.Fatal("valid rejected")
	}
	cases := []struct {
		name   string
		mutate func(*DomainCandidate, *KernelSnapshot, *Digest, *ProposalContext)
	}{{"candidate", func(c *DomainCandidate, _ *KernelSnapshot, _ *Digest, _ *ProposalContext) {
		c.Bundle, _ = NewCanonicalBundle(BundleSchemaVersion, []byte(`{"policy":"changed"}`))
	}}, {"tier", func(c *DomainCandidate, _ *KernelSnapshot, _ *Digest, _ *ProposalContext) { c.Tier = TierG1 }}, {"issuer", func(c *DomainCandidate, _ *KernelSnapshot, _ *Digest, _ *ProposalContext) { c.IssuerID = "other" }}, {"proposal", func(c *DomainCandidate, _ *KernelSnapshot, _ *Digest, _ *ProposalContext) { c.ProposalID = "other" }}, {"nonce", func(c *DomainCandidate, _ *KernelSnapshot, _ *Digest, _ *ProposalContext) { c.Nonce = "other" }}, {"proposer", func(_ *DomainCandidate, _ *KernelSnapshot, _ *Digest, p *ProposalContext) { p.ProposerID = "other" }}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			ctx := ProposalContext{ProposerID: "proposer"}
			kd := d
			tc.mutate(&c, &s, &kd, &ctx)
			if VerifyDomainApproval(s, kd, c, ctx, sig).Accepted {
				t.Fatal("tampered context accepted")
			}
		})
	}
	bad := d
	bad = Digest("0000000000000000000000000000000000000000000000000000000000000000")
	if VerifyDomainApproval(s, bad, base, ProposalContext{ProposerID: "proposer"}, sig).Accepted {
		t.Fatal("wrong kernel accepted")
	}
}
func TestApprovalBindsCanonicalCapabilitySet(t *testing.T) {
	s, p := fixtureKernel(t)
	d, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}

	base := candidateFor(t, TierG0)
	original := append([]string(nil), base.CapabilityIDs...)
	sig := approvalFor(t, base, s, p, 0, 1)
	if got := VerifyDomainApproval(s, d, base, ProposalContext{ProposerID: "proposer"}, sig); !got.Accepted {
		t.Fatalf("valid approval rejected: %+v", got)
	}

	for _, capabilities := range [][]string{{"work.write"}, {"work.read", "work.write"}} {
		candidate := base
		candidate.CapabilityIDs = capabilities
		if got := VerifyDomainApproval(s, d, candidate, ProposalContext{ProposerID: "proposer"}, sig); got.Accepted {
			t.Fatalf("approval for %v reused for %v", original, capabilities)
		}
	}

	multi := base
	multi.CapabilityIDs = []string{"work.read", "work.write"}
	multiMsg, err := DomainApprovalSigningBytes(multi, d, "proposer")
	if err != nil {
		t.Fatal(err)
	}
	reordered := multi
	reordered.CapabilityIDs = []string{"work.write", "work.read"}
	before := append([]string(nil), reordered.CapabilityIDs...)
	reorderedMsg, err := DomainApprovalSigningBytes(reordered, d, "proposer")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(multiMsg, reorderedMsg) {
		t.Fatal("equivalent capability sets produced different signing bytes")
	}
	if reordered.CapabilityIDs[0] != before[0] || reordered.CapabilityIDs[1] != before[1] {
		t.Fatalf("signing bytes mutated caller capability slice: got %v, want %v", reordered.CapabilityIDs, before)
	}
	multiSig := approvalFor(t, multi, s, p, 0, 1)
	if got := VerifyDomainApproval(s, d, reordered, ProposalContext{ProposerID: "proposer"}, multiSig); !got.Accepted {
		t.Fatalf("approval rejected for reordered equivalent set: %+v", got)
	}
}

func TestKernelAndCapabilityFailures(t *testing.T) {
	s, p := fixtureKernel(t)
	d, _ := s.Digest()
	cases := []struct {
		name   string
		change func(*KernelSnapshot, *DomainCandidate)
	}{{"duplicate signer", func(s *KernelSnapshot, _ *DomainCandidate) { s.Signers[1].ID = s.Signers[0].ID }}, {"duplicate key", func(s *KernelSnapshot, _ *DomainCandidate) {
		s.Signers[1].PublicKey = append([]byte(nil), s.Signers[0].PublicKey...)
	}}, {"bad key", func(s *KernelSnapshot, _ *DomainCandidate) { s.Signers[0].PublicKey = []byte{1} }}, {"zero threshold", func(s *KernelSnapshot, _ *DomainCandidate) { s.Thresholds[0].Threshold = 0 }}, {"high threshold", func(s *KernelSnapshot, _ *DomainCandidate) { s.Thresholds[0].Threshold = 4 }}, {"unknown capability", func(_ *KernelSnapshot, c *DomainCandidate) { c.CapabilityIDs = []string{"unknown"} }}, {"duplicate capability", func(_ *KernelSnapshot, c *DomainCandidate) { c.CapabilityIDs = []string{"work.read", "work.read"} }}, {"noncanonical capability", func(_ *KernelSnapshot, c *DomainCandidate) { c.CapabilityIDs = []string{"Work.Read"} }}, {"ceiling excess", func(s *KernelSnapshot, _ *DomainCandidate) { s.IssuerCeilings[0].Capabilities = []string{"work.read"} }}, {"missing issuer", func(_ *KernelSnapshot, c *DomainCandidate) { c.IssuerID = "missing" }}, {"G2", func(_ *KernelSnapshot, c *DomainCandidate) { c.Tier = TierG2 }}, {"G3", func(_ *KernelSnapshot, c *DomainCandidate) { c.Tier = TierG3 }}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := s
			c := candidateFor(t, TierG0)
			tc.change(&x, &c)
			xd, e := x.Digest()
			if e != nil {
				xd = d
			}
			// Construct approvals against the supported baseline tier; mutated G2/G3
			// requests must fail before interpreting approval bytes.
			signingCandidate := c
			if !validTier(signingCandidate.Tier) {
				signingCandidate.Tier = TierG0
			}
			a := approvalFor(t, signingCandidate, s, p, 0, 1)
			if VerifyDomainApproval(x, xd, c, ProposalContext{ProposerID: "proposer"}, a).Accepted {
				t.Fatal("invalid input accepted")
			}
		})
	}
	c := candidateFor(t, TierG0)
	a := approvalFor(t, c, s, p, 0, 1)
	a = append(a, a[0])
	if VerifyDomainApproval(s, d, c, ProposalContext{ProposerID: "proposer"}, a).Accepted {
		t.Fatal("repeated signer accepted")
	}
	if VerifyDomainApproval(s, d, c, ProposalContext{ProposerID: "proposer"}, approvalFor(t, c, s, p, 0)).Accepted {
		t.Fatal("insufficient quorum accepted")
	}
}
func TestKernelDigestMutationAndStrictDecode(t *testing.T) {
	s, _ := fixtureKernel(t)
	d, _ := s.Digest()
	s.Version++
	if VerifyDomainApproval(s, d, candidateFor(t, TierG0), ProposalContext{ProposerID: "p"}, nil).Accepted {
		t.Fatal("mutated snapshot accepted")
	}
	raw, _ := json.Marshal(s)
	if _, e := DecodeKernelSnapshot(append(raw[:len(raw)-1], []byte(`,"extra":1}`)...)); e == nil {
		t.Fatal("unknown field accepted")
	}
	if _, e := DecodeKernelSnapshot([]byte(`{"schema_version":"paddock.kernel-snapshot/1","version":1,"signers":[],"thresholds":[],"capabilities":[],"issuer_ceilings":[]}`)); e == nil {
		t.Fatal("malformed snapshot accepted")
	}
}
