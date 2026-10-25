package domain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
)

// These are raw documents, not reconstituted Go policy maps. Array order is
// intentionally preserved by all policy digest expectations.
const evolutionBasePolicy = `{"schema_version":"paddock.trust-policy/1","policy_type":"risk_adaptive_threshold_table","rules":[{"risk_tier":"G0","capability":"work.read","q1_min_independent":2,"q2_min_independent":4,"q3_min_independent":6,"integrity_demote_to":"Q0"},{"risk_tier":"G1","capability":"work.read","q1_min_independent":2,"q2_min_independent":4,"q3_min_independent":6,"integrity_demote_to":"Q0"},{"risk_tier":"G2","capability":"work.read","q1_min_independent":2,"q2_min_independent":4,"q3_min_independent":6,"integrity_demote_to":"Q0"},{"risk_tier":"G3","capability":"work.read","q1_min_independent":2,"q2_min_independent":4,"q3_min_independent":6,"integrity_demote_to":"Q0"}]}`

type evolutionFixture struct {
	kernel          KernelSnapshot
	keys            map[string]ed25519.PrivateKey
	base, candidate []byte
	domains         ControlDomainSnapshot
	proposal        ProposalContext
}

func newEvolutionFixture(t *testing.T) evolutionFixture {
	t.Helper()
	f := evolutionFixture{keys: map[string]ed25519.PrivateKey{}, base: []byte(evolutionBasePolicy), proposal: ProposalContext{"a"}}
	f.candidate = []byte(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(evolutionBasePolicy, `"q1_min_independent":2`, `"q1_min_independent":3`), `"q2_min_independent":4`, `"q2_min_independent":5`), `"q3_min_independent":6`, `"q3_min_independent":7`))
	f.kernel = KernelSnapshot{SchemaVersion: KernelSnapshotSchemaV2, Version: 1, Thresholds: []TierThreshold{{TierG0, 2}, {TierG1, 3}}, Capabilities: []string{"work.read"}, IssuerCeilings: []IssuerCeiling{{"issuer", []string{"work.read"}}}}
	var entries []EvidenceControlDomain
	for i, id := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize))
		f.keys[id] = key
		f.kernel.Signers = append(f.kernel.Signers, KernelSigner{id, append([]byte(nil), key.Public().(ed25519.PublicKey)...)})
		entries = append(entries, EvidenceControlDomain{EvidenceSignerID(id), EvidenceControlDomainID("domain-" + id)})
	}
	var bounds []EvolutionRuleBound
	var quorums []EvolutionRiskQuorum
	for _, tier := range []GovernanceTier{TierG0, TierG1, TierG2, TierG3} {
		bounds = append(bounds, EvolutionRuleBound{tier, "work.read", 2, 3, 4, 5, 6, 7, []CapabilityTrustTier{CapabilityTrustQ0, CapabilityTrustQ1, CapabilityTrustQ2}})
		quorums = append(quorums, EvolutionRiskQuorum{tier, 2, 2})
	}
	config, err := NewEvolutionKernelConfig(bounds, quorums)
	if err != nil {
		t.Fatal(err)
	}
	f.kernel.EvolutionKernelConfig = &config
	f.domains, err = NewControlDomainSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func mustEvolutionDigest(t *testing.T, raw []byte) Digest {
	t.Helper()
	d, err := EvolutionPolicyDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Independent hash over the original validated raw bytes after existing JCS.
	if _, err := DecodeTrustPolicy(raw); err != nil {
		t.Fatal(err)
	}
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cb)
	if d != Digest(hex.EncodeToString(sum[:])) {
		t.Fatal("policy digest not raw JCS hash")
	}
	return d
}
func (f evolutionFixture) graph(t *testing.T, tier GovernanceTier, reviewers, approvers []string) EvolutionApprovalGraph {
	t.Helper()
	kd, err := f.kernel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ctx := EvolutionApprovalContext{EvolutionApprovalGraphSchema, kd, mustEvolutionDigest(t, f.base), mustEvolutionDigest(t, f.candidate), tier, f.proposal.ProposerID, "proposal-1", "nonce-1"}
	return f.sign(t, ctx, reviewers, approvers)
}
func (f evolutionFixture) sign(t *testing.T, ctx EvolutionApprovalContext, reviewers, approvers []string) EvolutionApprovalGraph {
	t.Helper()
	var reviews []EvolutionReview
	for _, id := range reviewers {
		review := EvolutionReview{ReviewerID: id, Role: EvolutionVerifierRole, Verdict: EvolutionPassVerdict, EvidenceDigest: Digest(strings.Repeat("1", 64))}
		message, err := EvolutionReviewSigningBytes(ctx, review)
		if err != nil {
			t.Fatal(err)
		}
		key := f.keys[id]
		if key == nil {
			key = f.keys["g"]
		}
		review.Signature = ed25519.Sign(key, message)
		reviews = append(reviews, review)
	}
	rsd, err := EvolutionReviewSetDigest(reviews)
	if err != nil {
		t.Fatal(err)
	}
	var approvals []EvolutionApproval
	for _, id := range approvers {
		approval := EvolutionApproval{ApproverID: id, Role: EvolutionApproverRole}
		message, err := EvolutionApprovalSigningBytes(ctx, rsd, approval)
		if err != nil {
			t.Fatal(err)
		}
		key := f.keys[id]
		if key == nil {
			key = f.keys["g"]
		}
		approval.Signature = ed25519.Sign(key, message)
		approvals = append(approvals, approval)
	}
	g, err := NewEvolutionApprovalGraph(ctx, reviews, approvals)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func (f evolutionFixture) verify(t *testing.T, g EvolutionApprovalGraph) (EvolutionApprovalEvidence, error) {
	t.Helper()
	kd, err := f.kernel.Digest()
	if err != nil {
		return EvolutionApprovalEvidence{}, err
	}
	return VerifyEvolutionApprovalGraph(f.kernel, kd, mustEvolutionDigest(t, f.base), f.base, f.candidate, f.proposal, f.domains, g)
}
func evolutionJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEvolutionV1GoldenAndLegacyBoundary(t *testing.T) {
	s := KernelSnapshot{SchemaVersion: KernelSnapshotSchema, Version: 1, Signers: []KernelSigner{{"a", make([]byte, 32)}}, Thresholds: []TierThreshold{{TierG0, 1}, {TierG1, 1}}, Capabilities: []string{"work.read"}, IssuerCeilings: []IssuerCeiling{}}
	const golden = `{"capabilities":["work.read"],"issuer_ceilings":[],"schema_version":"paddock.kernel-snapshot/1","signers":[{"id":"a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}],"thresholds":[{"threshold":1,"tier":"G0"},{"threshold":1,"tier":"G1"}],"version":1}`
	cb, err := s.CanonicalBytes()
	if err != nil || string(cb) != golden {
		t.Fatalf("v1 bytes changed: %s %v", cb, err)
	}
	digest, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const goldenDigest Digest = "bcba85e0651336d915dca689e01ac997105acc4b5b1454ff374bba40016409d0"
	if digest != goldenDigest {
		t.Fatalf("v1 digest = %s; want %s", digest, goldenDigest)
	}
	decoded, err := DecodeKernelSnapshot([]byte(golden))
	if err != nil || decoded.EvolutionKernelConfig != nil {
		t.Fatalf("v1 decode: %+v %v", decoded, err)
	}
	if round, err := decoded.CanonicalBytes(); err != nil || !bytes.Equal(round, cb) {
		t.Fatal("v1 roundtrip")
	}
	f := newEvolutionFixture(t)
	legacy := f.kernel
	legacy.SchemaVersion, legacy.EvolutionKernelConfig = KernelSnapshotSchema, nil
	kd, err := legacy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateFor(t, TierG0)
	msg, err := DomainApprovalSigningBytes(candidate, kd, "a")
	if err != nil {
		t.Fatal(err)
	}
	sigs := []DomainApproval{{"b", ed25519.Sign(f.keys["b"], msg)}, {"c", ed25519.Sign(f.keys["c"], msg)}}
	if !VerifyKernelApprovalSignatures(legacy, kd, TierG0, "a", msg, sigs).Accepted || !VerifyDomainApproval(legacy, kd, candidate, ProposalContext{"a"}, sigs).Accepted {
		t.Fatal("legacy v1 rejected")
	}
	v2d, err := f.kernel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyKernelApprovalSignatures(f.kernel, v2d, TierG0, "a", msg, sigs).Accepted || VerifyDomainApproval(f.kernel, v2d, candidate, ProposalContext{"a"}, sigs).Accepted {
		t.Fatal("legacy API accepted v2")
	}
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	if _, err := VerifyEvolutionApprovalGraph(legacy, kd, mustEvolutionDigest(t, f.base), f.base, f.candidate, f.proposal, f.domains, g); err == nil {
		t.Fatal("v1 authorized S04")
	}
	legacy.EvolutionKernelConfig = f.kernel.EvolutionKernelConfig
	if _, err := legacy.CanonicalBytes(); err == nil {
		t.Fatal("v1 nonnil config")
	}
}

func TestEvolutionRawKernelClosedSchemas(t *testing.T) {
	f := newEvolutionFixture(t)
	v2 := string(evolutionJSON(t, f.kernel))
	legacy := f.kernel
	legacy.SchemaVersion, legacy.EvolutionKernelConfig = KernelSnapshotSchema, nil
	v1 := string(evolutionJSON(t, legacy))
	for _, raw := range []string{v1, v2} {
		if _, err := DecodeKernelSnapshot([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		var direct KernelSnapshot
		if err := json.Unmarshal([]byte(raw), &direct); err != nil {
			t.Fatal("direct Kernel decode", err)
		}
		cases := []string{
			strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1),
			strings.Replace(raw, `"id":"a"`, `"id":"a","id":"a"`, 1),
			strings.Replace(raw, `"threshold":2`, `"threshold":2,"threshold":2`, 1),
			strings.Replace(raw, `"issuer_id":"issuer"`, `"issuer_id":"issuer","issuer_id":"issuer"`, 1),
			strings.Replace(raw, `"version":1`, `"version":9007199254740992`, 1),
			strings.Replace(raw, `"version":1`, `"version":1e400`, 1),
			strings.Replace(raw, `"version":1`, `"version":0`, 1),
			strings.Replace(raw, `"version":1`, `"version":null`, 1),
			strings.Replace(raw, `"version":1,`, ``, 1),
			strings.Replace(raw, `"version":1`, `"version":1,"extra":true`, 1),
			strings.Replace(raw, `"id":"a"`, `"ID":"a"`, 1),
			strings.Replace(raw, `"public_key":"`+base64.StdEncoding.EncodeToString(f.kernel.Signers[0].PublicKey)+`"`, `"public_key":[1,2,3]`, 1),
			raw + ` {}`, raw + ` !`, raw[:len(raw)-1], `null`,
		}
		for i, invalid := range cases {
			if invalid == raw {
				t.Fatalf("case %d did not mutate", i)
			}
			if _, err := DecodeKernelSnapshot([]byte(invalid)); err == nil {
				t.Errorf("accepted kernel case %d: %s", i, invalid)
			}
			before := evolutionJSON(t, direct)
			if err := json.Unmarshal([]byte(invalid), &direct); err == nil {
				t.Errorf("direct Kernel decode accepted case %d", i)
			}
			if !bytes.Equal(before, evolutionJSON(t, direct)) {
				t.Errorf("failed direct Kernel decode mutated receiver: %d", i)
			}
		}
	}
	for _, invalid := range []string{
		strings.Replace(v2, KernelSnapshotSchemaV2, KernelSnapshotSchema, 1),
		strings.Replace(v1, KernelSnapshotSchema, KernelSnapshotSchemaV2, 1),
		strings.Replace(v2, `"rule_bounds":`, `"rule_bounds":[],"rule_bounds":`, 1),
		strings.Replace(v2, `"q1_min":2`, `"q1_min":2,"q1_min":2`, 1),
		strings.Replace(v2, `"q1_min":2`, `"q1_min":2,"unknown":0`, 1),
		strings.Replace(v2, `"q1_min":2,`, ``, 1),
		strings.Replace(v2, `"min_verifier_control_domains":2`, `"min_verifier_control_domains":2,"min_verifier_control_domains":2`, 1),
		strings.Replace(v2, `,"min_approver_control_domains":2`, ``, 1),
		strings.Replace(v2, `"q1_min":2`, `"q1_min":9007199254740992`, 1),
		strings.Replace(v2, `"q1_min":2`, `"q1_min":"2"`, 1),
		strings.Replace(v2, `"q1_min":2`, `"q1_min":null`, 1),
		strings.Replace(v2, `"evolution_kernel_config":{`, `"evolution_kernel_config":null,"discarded":{`, 1),
	} {
		if invalid == v2 {
			t.Fatal("v2 negative test did not mutate its input")
		}
		if _, err := DecodeKernelSnapshot([]byte(invalid)); err == nil {
			t.Errorf("accepted v2 config/schema: %s", invalid)
		}
	}
	// A sole null config is distinct from omission and cannot authorize v2.
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v2), &root); err != nil {
		t.Fatal(err)
	}
	root["evolution_kernel_config"] = json.RawMessage("null")
	if _, err := DecodeKernelSnapshot(evolutionJSON(t, root)); err == nil {
		t.Fatal("null v2 config")
	}
	delete(root, "evolution_kernel_config")
	if _, err := DecodeKernelSnapshot(evolutionJSON(t, root)); err == nil {
		t.Fatal("missing v2 config")
	}
}

func TestEvolutionBoundsAndQuorumConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]EvolutionRuleBound, []EvolutionRiskQuorum)
	}{
		{"q1 minimum", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q1Min = 1 }},
		{"zero minimum", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q2Min = 0 }},
		{"inverted", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q2Min = 6 }},
		{"unsafe", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q3Max = maxTrustPolicySafeInteger + 1 }},
		{"infeasible q2", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q1Min = 5; b[0].Q1Max = 5 }},
		{"infeasible q3", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Q2Min = 7; b[0].Q2Max = 7 }},
		{"duplicate key", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[1] = b[0] }},
		{"unsorted key", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0], b[1] = b[1], b[0] }},
		{"unknown risk", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].RiskTier = "G4" }},
		{"empty capability", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].Capability = "" }},
		{"empty demotions", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) { b[0].IntegrityDemoteTo = nil }},
		{"unknown demotion", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) {
			b[0].IntegrityDemoteTo = []CapabilityTrustTier{CapabilityTrustQ3}
		}},
		{"unsorted demotions", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) {
			b[0].IntegrityDemoteTo = []CapabilityTrustTier{CapabilityTrustQ1, CapabilityTrustQ0}
		}},
		{"duplicate demotions", func(b []EvolutionRuleBound, _ []EvolutionRiskQuorum) {
			b[0].IntegrityDemoteTo = []CapabilityTrustTier{CapabilityTrustQ0, CapabilityTrustQ0}
		}},
		{"zero verifier quorum", func(_ []EvolutionRuleBound, q []EvolutionRiskQuorum) { q[0].MinVerifierControlDomains = 0 }},
		{"zero approver quorum", func(_ []EvolutionRuleBound, q []EvolutionRiskQuorum) { q[0].MinApproverControlDomains = 0 }},
		{"quorum order", func(_ []EvolutionRuleBound, q []EvolutionRiskQuorum) { q[0], q[1] = q[1], q[0] }},
		{"quorum duplicate", func(_ []EvolutionRuleBound, q []EvolutionRiskQuorum) { q[1] = q[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvolutionFixture(t)
			b, q := f.kernel.EvolutionKernelConfig.RuleBounds(), f.kernel.EvolutionKernelConfig.RiskQuorums()
			tc.mutate(b, q)
			if _, err := NewEvolutionKernelConfig(b, q); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	f := newEvolutionFixture(t)
	b, q := f.kernel.EvolutionKernelConfig.RuleBounds(), f.kernel.EvolutionKernelConfig.RiskQuorums()
	for _, bounds := range [][]EvolutionRuleBound{nil, b[:3]} {
		if len(bounds) == 0 {
			if _, err := NewEvolutionKernelConfig(bounds, q); err == nil {
				t.Fatal("empty bounds")
			}
		} else {
			cfg, err := NewEvolutionKernelConfig(bounds, q)
			if err != nil {
				t.Fatal(err)
			}
			base, err := DecodeTrustPolicy(f.base)
			if err != nil {
				t.Fatal(err)
			}
			cand, err := DecodeTrustPolicy(f.candidate)
			if err != nil {
				t.Fatal(err)
			}
			if validateEvolutionPolicies(cfg, base, cand) == nil {
				t.Fatal("missing exact rule bound")
			}
		}
	}
	if _, err := NewEvolutionKernelConfig(b, q[:3]); err == nil {
		t.Fatal("missing risk quorum")
	}
	q[0].MinVerifierControlDomains = uint64(len(f.kernel.Signers) + 1)
	cfg, err := NewEvolutionKernelConfig(b, q)
	if err != nil {
		t.Fatal(err)
	}
	f.kernel.EvolutionKernelConfig = &cfg
	if _, err := f.kernel.CanonicalBytes(); err == nil {
		t.Fatal("quorum > pinned count")
	}
	// Safe endpoint arithmetic, including a tuple touching the largest safe integer.
	b, q = newEvolutionFixture(t).kernel.EvolutionKernelConfig.RuleBounds(), newEvolutionFixture(t).kernel.EvolutionKernelConfig.RiskQuorums()
	b[0].Q1Min, b[0].Q1Max = maxTrustPolicySafeInteger-2, maxTrustPolicySafeInteger-2
	b[0].Q2Min, b[0].Q2Max = maxTrustPolicySafeInteger-1, maxTrustPolicySafeInteger-1
	b[0].Q3Min, b[0].Q3Max = maxTrustPolicySafeInteger, maxTrustPolicySafeInteger
	if _, err := NewEvolutionKernelConfig(b, q); err != nil {
		t.Fatal(err)
	}
	// Feasibility does not require all endpoints themselves to be ordered.
	b[0].Q1Min, b[0].Q1Max, b[0].Q2Min, b[0].Q2Max, b[0].Q3Min, b[0].Q3Max = 2, 9, 1, 10, 1, 11
	if _, err := NewEvolutionKernelConfig(b, q); err != nil {
		t.Fatal(err)
	}
	b[0].Q1Min, b[0].Q1Max, b[0].Q2Min, b[0].Q2Max, b[0].Q3Min, b[0].Q3Max = maxTrustPolicySafeInteger, maxTrustPolicySafeInteger, 1, maxTrustPolicySafeInteger, 1, maxTrustPolicySafeInteger
	if _, err := NewEvolutionKernelConfig(b, q); err == nil {
		t.Fatal("infeasible safe endpoint")
	}
}

func TestEvolutionPolicyImmutabilityAndFullS03(t *testing.T) {
	f := newEvolutionFixture(t)
	for _, raw := range [][]byte{f.base, f.candidate} {
		f.candidate = raw
		g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
		if _, err := f.verify(t, g); err != nil {
			t.Fatal("inclusive endpoint", err)
		}
	}
	for _, replace := range [][2]string{
		{`"schema_version":"paddock.trust-policy/1"`, `"schema_version":"paddock.trust-policy/2"`},
		{`"policy_type":"risk_adaptive_threshold_table"`, `"policy_type":"other"`},
		{`"q1_min_independent":2`, `"q1_min_independent":1`},
		{`"q2_min_independent":4`, `"q2_min_independent":2`},
		{`"q3_min_independent":6`, `"q3_min_independent":4`},
		{`"q3_min_independent":6`, `"q3_min_independent":9007199254740992`},
		{`"integrity_demote_to":"Q0"`, `"integrity_demote_to":"Q3"`},
		{`"q1_min_independent":2`, `"q1_min_independent":2,"q1_min_independent":2`},
		{`"q1_min_independent":2,`, ``},
		{`"q1_min_independent":2`, `"q1_min_independent":2,"extra":0`},
	} {
		raw := []byte(strings.Replace(evolutionBasePolicy, replace[0], replace[1], 1))
		if _, err := EvolutionPolicyDigest(raw); err == nil {
			t.Fatalf("invalid S03 digest accepted: %s", raw)
		}
		good := newEvolutionFixture(t)
		g := good.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
		good.candidate = raw
		kd, err := good.kernel.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEvolutionApprovalGraph(good.kernel, kd, mustEvolutionDigest(t, good.base), good.base, raw, good.proposal, good.domains, g); err == nil {
			t.Fatal("invalid S03 verified")
		}
	}
	for _, tc := range []struct {
		name string
		edit func(string) string
	}{
		{"extra key", func(s string) string {
			return strings.Replace(s, `"capability":"work.read"`, `"capability":"work.write"`, 1)
		}},
		{"missing rule", func(s string) string { start := strings.LastIndex(s, `,{"risk_tier":"G3"`); return s[:start] + `]}` }},
		{"outside q1", func(s string) string {
			return strings.Replace(s, `"q1_min_independent":2`, `"q1_min_independent":4`, 1)
		}},
		{"outside q2", func(s string) string {
			return strings.Replace(s, `"q2_min_independent":4`, `"q2_min_independent":3`, 1)
		}},
		{"outside q3", func(s string) string {
			return strings.Replace(s, `"q3_min_independent":6`, `"q3_min_independent":8`, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvolutionFixture(t)
			f.candidate = []byte(tc.edit(evolutionBasePolicy))
			if tc.name == "outside q1" {
				f.candidate = []byte(strings.Replace(string(f.candidate), `"q2_min_independent":4`, `"q2_min_independent":5`, 1))
			}
			g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
			if _, err := f.verify(t, g); err == nil {
				t.Fatal("out of bounds/keyset accepted")
			}
		})
	}
	f = newEvolutionFixture(t)
	b, q := f.kernel.EvolutionKernelConfig.RuleBounds(), f.kernel.EvolutionKernelConfig.RiskQuorums()
	b[0].IntegrityDemoteTo = []CapabilityTrustTier{CapabilityTrustQ0}
	cfg, err := NewEvolutionKernelConfig(b, q)
	if err != nil {
		t.Fatal(err)
	}
	f.kernel.EvolutionKernelConfig = &cfg
	f.candidate = []byte(strings.Replace(string(f.candidate), `"integrity_demote_to":"Q0"`, `"integrity_demote_to":"Q1"`, 1))
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	if _, err := f.verify(t, g); err == nil {
		t.Fatal("disallowed demotion")
	}
	for _, tier := range []CapabilityTrustTier{CapabilityTrustQ0, CapabilityTrustQ1, CapabilityTrustQ2} {
		f := newEvolutionFixture(t)
		f.candidate = []byte(strings.ReplaceAll(string(f.candidate), `"integrity_demote_to":"Q0"`, `"integrity_demote_to":"`+string(tier)+`"`))
		g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
		if _, err := f.verify(t, g); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEvolutionIdentityAndDomainQuorums(t *testing.T) {
	for _, tier := range []GovernanceTier{TierG0, TierG1, TierG2, TierG3} {
		f := newEvolutionFixture(t)
		g := f.graph(t, tier, []string{"b", "c"}, []string{"d", "e"})
		ev, err := f.verify(t, g)
		if err != nil || ev.VerifierControlDomains != 2 || ev.ApproverControlDomains != 2 {
			t.Fatalf("tier %s: %+v %v", tier, ev, err)
		}
	}
	for _, tc := range []struct {
		name               string
		mutate             func(*evolutionFixture)
		reviews, approvals []string
		valid              bool
	}{
		{"unknown reviewer", func(*evolutionFixture) {}, []string{"b", "z"}, []string{"d", "e"}, false},
		{"unknown approver", func(*evolutionFixture) {}, []string{"b", "c"}, []string{"d", "z"}, false},
		{"builder reviewer", func(*evolutionFixture) {}, []string{"a", "b"}, []string{"d", "e"}, false},
		{"builder approver", func(*evolutionFixture) {}, []string{"b", "c"}, []string{"a", "d"}, false},
		{"missing builder mapping", func(f *evolutionFixture) { delete(f.domains.domains, "a") }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"unknown builder", func(f *evolutionFixture) { f.proposal.ProposerID = "z" }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"outside mapping", func(f *evolutionFixture) { f.domains.domains["z"] = "domain-z" }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"malformed label", func(f *evolutionFixture) { f.domains.domains["g"] = " bad" }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"malformed signer mapping", func(f *evolutionFixture) { f.domains.domains[" "] = "domain-z" }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"missing verifier contributes zero", func(f *evolutionFixture) { delete(f.domains.domains, "c") }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"missing approver contributes zero", func(f *evolutionFixture) { delete(f.domains.domains, "e") }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"missing extra verifier still zero", func(f *evolutionFixture) { delete(f.domains.domains, "g") }, []string{"b", "c", "g"}, []string{"d", "e"}, true},
		{"missing extra approver still zero", func(f *evolutionFixture) { delete(f.domains.domains, "g") }, []string{"b", "c"}, []string{"d", "e", "g"}, true},
		{"shared verifier domain counts once", func(f *evolutionFixture) { f.domains.domains["c"] = f.domains.domains["b"] }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"shared approver domain counts once", func(f *evolutionFixture) { f.domains.domains["e"] = f.domains.domains["d"] }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"shared extra verifier domain allowed", func(f *evolutionFixture) { f.domains.domains["g"] = f.domains.domains["b"] }, []string{"b", "c", "g"}, []string{"d", "e"}, true},
		{"builder verifier domain", func(f *evolutionFixture) { f.domains.domains["c"] = f.domains.domains["a"] }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"builder approver domain", func(f *evolutionFixture) { f.domains.domains["e"] = f.domains.domains["a"] }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"cross role domain", func(f *evolutionFixture) { f.domains.domains["e"] = f.domains.domains["b"] }, []string{"b", "c"}, []string{"d", "e"}, false},
		{"one verifier below edge", func(*evolutionFixture) {}, []string{"b"}, []string{"d", "e"}, false},
		{"one approver below edge", func(*evolutionFixture) {}, []string{"b", "c"}, []string{"d"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvolutionFixture(t)
			tc.mutate(&f)
			g := f.graph(t, TierG0, tc.reviews, tc.approvals)
			_, err := f.verify(t, g)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
	for _, mutate := range []func(*KernelSnapshot){
		func(s *KernelSnapshot) { s.Signers[1].ID = s.Signers[0].ID },
		func(s *KernelSnapshot) { s.Signers[1].PublicKey = append([]byte(nil), s.Signers[0].PublicKey...) },
		func(s *KernelSnapshot) { s.Signers[1].PublicKey = []byte{1} },
		func(s *KernelSnapshot) { s.Signers[1].ID = " " },
		func(s *KernelSnapshot) { s.Thresholds[0].Tier = TierG2 },
		func(s *KernelSnapshot) { s.Thresholds[0].Threshold = 0 },
		func(s *KernelSnapshot) { s.Capabilities = []string{"work.read", "work.read"} },
		func(s *KernelSnapshot) { s.IssuerCeilings[0].Capabilities = []string{"work.write"} },
	} {
		f := newEvolutionFixture(t)
		g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
		mutate(&f.kernel)
		if _, err := f.verify(t, g); err == nil {
			t.Fatal("malformed pinned v2 kernel")
		}
	}
	for _, entries := range [][]EvidenceControlDomain{{{"b", "domain-b"}, {"b", "domain-c"}}, {{"b", " bad"}}, {{"", "domain"}}} {
		if _, err := NewControlDomainSnapshot(entries); err == nil {
			t.Fatal("mapping constructor accepted malformed/duplicate entries")
		}
	}
}

func TestEvolutionGraphRawRecordsAndOrder(t *testing.T) {
	f := newEvolutionFixture(t)
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	raw := string(evolutionJSON(t, g))
	if _, err := DecodeEvolutionApprovalGraph([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	for _, replace := range [][2]string{
		{`"schema_version":"paddock.evolution-approval-graph/1"`, `"schema_version":"paddock.evolution-approval-graph/1","schema_version":"paddock.evolution-approval-graph/1"`},
		{`"builder_id":"a"`, `"builder_id":"a","builder_id":"a"`},
		{`"reviewer_id":"b"`, `"reviewer_id":"b","reviewer_id":"b"`},
		{`"approver_id":"d"`, `"approver_id":"d","approver_id":"d"`},
		{`"builder_id":"a",`, ``},
		{`"builder_id":"a"`, `"builder_id":null`},
		{`"builder_id":"a"`, `"builder_id":"a","extra":1`},
		{`"reviewer_id":"b"`, `"reviewer_id":"b","extra":1`},
		{`"reviewer_id":"b",`, ``},
		{`"approver_id":"d",`, ``},
		{`"approver_id":"d"`, `"approver_id":"d","extra":1`},
		{`"role":"VERIFIER"`, `"role":"APPROVER"`},
		{`"role":"APPROVER"`, `"role":"VERIFIER"`},
		{`"verdict":"PASS"`, `"verdict":"FAIL"`},
		{`"reviewer_id":"b"`, `"reviewer_id":" c"`},
		{`"risk_tier":"G0"`, `"risk_tier":"G4"`},
		{`"builder_id":"a"`, `"builder_id":9007199254740992`},
		{`"nonce":"nonce-1"`, `"nonce":" "`},
		{`"reviewer_id":"c"`, `"reviewer_id":"b"`},
		{`"approver_id":"e"`, `"approver_id":"d"`},
		{`"approver_id":"d"`, `"approver_id":"b"`},
		{`"signature":"` + base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature) + `"`, `"signature":[1,2,3]`},
		{`"signature":"` + base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature) + `"`, `"signature":"!"`},
		{`"signature":"` + base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature) + `"`, `"signature":null`},
	} {
		invalid := strings.Replace(raw, replace[0], replace[1], 1)
		if invalid == raw {
			t.Fatalf("no mutation: %s", replace[0])
		}
		if _, err := DecodeEvolutionApprovalGraph([]byte(invalid)); err == nil {
			t.Fatalf("accepted graph: %s", invalid)
		}
	}
	for _, invalid := range []string{raw + ` {}`, raw + `!`, raw[:len(raw)-1], strings.Replace(raw, `"context":`, `"extra":0,"context":`, 1), `null`} {
		if _, err := DecodeEvolutionApprovalGraph([]byte(invalid)); err == nil {
			t.Fatal("invalid graph JSON accepted")
		}
	}
	ctx, reviews, approvals := g.Context(), g.Reviews(), g.Approvals()
	for _, mutate := range []func([]EvolutionReview, []EvolutionApproval){
		func(r []EvolutionReview, _ []EvolutionApproval) { r[0], r[1] = r[1], r[0] },
		func(_ []EvolutionReview, a []EvolutionApproval) { a[0], a[1] = a[1], a[0] },
		func(r []EvolutionReview, _ []EvolutionApproval) { r[1] = r[0] },
		func(_ []EvolutionReview, a []EvolutionApproval) { a[1] = a[0] },
		func(r []EvolutionReview, a []EvolutionApproval) { a[0].ApproverID = r[0].ReviewerID },
	} {
		r, a := copyEvolutionReviews(reviews), copyEvolutionApprovals(approvals)
		mutate(r, a)
		if _, err := NewEvolutionApprovalGraph(ctx, r, a); err == nil {
			t.Fatal("duplicate/unsorted/overlap accepted")
		}
	}
	if _, err := NewEvolutionApprovalGraph(ctx, nil, approvals); err == nil {
		t.Fatal("missing reviews")
	}
	if _, err := NewEvolutionApprovalGraph(ctx, reviews, nil); err == nil {
		t.Fatal("missing approvals")
	}
	if _, err := (EvolutionApprovalGraph{}).CanonicalBytes(); err == nil {
		t.Fatal("zero graph")
	}
}

func TestEvolutionSigningAndDigestGoldens(t *testing.T) {
	f := newEvolutionFixture(t)
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	ev, err := f.verify(t, g)
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, err := EvolutionReviewSigningBytes(g.Context(), g.Reviews()[0])
	if err != nil {
		t.Fatal(err)
	}
	approvalBytes, err := EvolutionApprovalSigningBytes(g.Context(), ev.ReviewSetDigest, g.Approvals()[0])
	if err != nil {
		t.Fatal(err)
	}
	wantEvidence := EvolutionApprovalEvidence{
		KernelDigest:           "46e89505581910d3ab92af572cb25a1c4e81121ef192673e2fb0cab2c386183f",
		BasePolicyDigest:       "5b54f2c32e0867aeb324038010163a657e96e8f96dd97582647e5b955e5a6e40",
		CandidateDigest:        "d3565e71a5cedc85694de1a412e7dc0d0a4d7b227930f6aa659f4ae4a5ff3eed",
		ContextDigest:          "b3bf37e0bba42e43e9368cd817a3bd96632f61685d73c4dc66b13d8342240bcc",
		ReviewSetDigest:        "f173cb214b414cfc510513dc8b043c35b3377b15d4c21dce8d5c935ccd505aa5",
		FinalGraphDigest:       "acddb0f5b0137d030e29eed29c67d893589abe97478d4b1a2432b1b9b1c4fcd9",
		VerifierControlDomains: 2, ApproverControlDomains: 2,
	}
	if ev != wantEvidence {
		t.Fatalf("digest goldens changed: got %+v; want %+v", ev, wantEvidence)
	}
	const wantReview = `{"audience":"governance","domain":"paddock.approval","nonce":"nonce-1","payload":{"context_digest":"b3bf37e0bba42e43e9368cd817a3bd96632f61685d73c4dc66b13d8342240bcc","evidence_digest":"1111111111111111111111111111111111111111111111111111111111111111","reviewer_id":"b","role":"VERIFIER","verdict":"PASS"},"request_id":"proposal-1","schema_version":"paddock.evolution-review/1"}`
	const wantApproval = `{"audience":"governance","domain":"paddock.approval","nonce":"nonce-1","payload":{"approver_id":"d","context_digest":"b3bf37e0bba42e43e9368cd817a3bd96632f61685d73c4dc66b13d8342240bcc","review_set_digest":"f173cb214b414cfc510513dc8b043c35b3377b15d4c21dce8d5c935ccd505aa5","role":"APPROVER"},"request_id":"proposal-1","schema_version":"paddock.evolution-approval/1"}`
	if string(reviewBytes) != wantReview || string(approvalBytes) != wantApproval {
		t.Fatalf("signing envelope changed: review=%s approval=%s", reviewBytes, approvalBytes)
	}
	if base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature) != "yvL58hquobiYLDH2HGlzR7IFLxhuRNCwOdRjfxtS/NGUAwOcKLq6ScIU+nzXftFTYu8PkI6Inqf0QNzAMbVSCQ==" || base64.StdEncoding.EncodeToString(g.Approvals()[0].Signature) != "lMXuZf6RQLQ/cwKxszq2WHZZLILzmRTYGZtm/g0HDXxTbAmlk+YSQbMbkW20Rdpj48zOKpZ4y/VGIXTSmRrDAQ==" {
		t.Fatal("signature base64 goldens changed")
	}
	cb, err := g.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEvolutionApprovalGraph(cb)
	if err != nil {
		t.Fatal(err)
	}
	round, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(round, cb) {
		t.Fatal("graph bytes unstable")
	}
	if !bytes.Contains(cb, []byte(`"signature":"`+base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature)+`"`)) {
		t.Fatal("signature not JSON base64")
	}
	if bytes.Contains(reviewBytes, []byte(`"signature"`)) || bytes.Contains(approvalBytes, []byte(`"signature"`)) {
		t.Fatal("signature included in its own payload")
	}
	// Every signed context component and every signature stage must bind exactly.
	for _, mutate := range []func(*evolutionGraphDocument){
		func(d *evolutionGraphDocument) { d.Context.KernelDigest = Digest(strings.Repeat("2", 64)) },
		func(d *evolutionGraphDocument) { d.Context.BasePolicyDigest = Digest(strings.Repeat("2", 64)) },
		func(d *evolutionGraphDocument) { d.Context.CandidateDigest = Digest(strings.Repeat("2", 64)) },
		func(d *evolutionGraphDocument) { d.Context.RiskTier = TierG1 },
		func(d *evolutionGraphDocument) { d.Context.BuilderID = "f" },
		func(d *evolutionGraphDocument) { d.Context.ProposalID = "proposal-2" },
		func(d *evolutionGraphDocument) { d.Context.Nonce = "nonce-2" },
		func(d *evolutionGraphDocument) { d.Reviews[0].EvidenceDigest = Digest(strings.Repeat("2", 64)) },
		func(d *evolutionGraphDocument) { d.Reviews[0].Signature[0] ^= 1 },
		func(d *evolutionGraphDocument) { d.Approvals[0].Signature[0] ^= 1 },
	} {
		doc := g.document
		doc.Reviews = g.Reviews()
		doc.Approvals = g.Approvals()
		mutate(&doc)
		if _, err := f.verify(t, EvolutionApprovalGraph{doc}); err == nil {
			t.Fatal("tampered graph accepted")
		}
	}
	// A newly valid review signature still invalidates the previous approval stage.
	doc := g.document
	doc.Reviews = g.Reviews()
	doc.Reviews[0].EvidenceDigest = Digest(strings.Repeat("2", 64))
	msg, err := EvolutionReviewSigningBytes(doc.Context, doc.Reviews[0])
	if err != nil {
		t.Fatal(err)
	}
	doc.Reviews[0].Signature = ed25519.Sign(f.keys["b"], msg)
	changed := EvolutionApprovalGraph{doc}
	changedRSD, err := changed.ReviewSetDigest()
	if err != nil || changedRSD == ev.ReviewSetDigest {
		t.Fatal("review set did not bind signature/full review")
	}
	if _, err := f.verify(t, changed); err == nil {
		t.Fatal("approval failed to bind new signed review set")
	}
}

func TestEvolutionSigningDomainAndCanonicalBase64(t *testing.T) {
	f := newEvolutionFixture(t)
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	message, err := EvolutionReviewSigningBytes(g.Context(), g.Reviews()[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, wrongMessage := range [][]byte{
		bytes.Replace(message, []byte(`"domain":"paddock.approval"`), []byte(`"domain":"paddock.bundle"`), 1),
		bytes.Replace(message, []byte(EvolutionReviewSchema), []byte(EvolutionApprovalSchema), 1),
		bytes.Replace(message, []byte(`"audience":"governance"`), []byte(`"audience":"other"`), 1),
	} {
		doc := g.document
		doc.Reviews = g.Reviews()
		doc.Reviews[0].Signature = ed25519.Sign(f.keys["b"], wrongMessage)
		if _, err := f.verify(t, EvolutionApprovalGraph{doc}); err == nil {
			t.Fatal("cross-domain/schema/audience signature verified")
		}
	}
	doc := g.document
	doc.Reviews = g.Reviews()
	doc.Reviews[0].Signature = ed25519.Sign(f.keys["c"], message)
	if _, err := f.verify(t, EvolutionApprovalGraph{doc}); err == nil {
		t.Fatal("wrong pinned signer key verified")
	}

	// StdEncoding's decoder normally permits CR/LF, and a permissive decoder
	// could accept nonzero pad bits. Require the single canonical base64 spelling.
	raw := string(evolutionJSON(t, g))
	signature := base64.StdEncoding.EncodeToString(g.Reviews()[0].Signature)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, signature[len(signature)-3])
	nonzeroPad := signature[:len(signature)-3] + string(alphabet[index+1]) + "=="
	for _, bad := range []string{signature[:8] + `\n` + signature[8:], strings.TrimRight(signature, "="), nonzeroPad} {
		invalid := strings.Replace(raw, signature, bad, 1)
		if _, err := DecodeEvolutionApprovalGraph([]byte(invalid)); err == nil {
			t.Fatal("noncanonical signature base64 accepted")
		}
		before, err := g.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(invalid), &g); err == nil {
			t.Fatal("direct graph decoder accepted noncanonical base64")
		}
		after, err := g.CanonicalBytes()
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed graph decode mutated receiver")
		}
	}
}

func TestEvolutionExpectedDigestsRevalidationAndDeepImmutability(t *testing.T) {
	f := newEvolutionFixture(t)
	g := f.graph(t, TierG0, []string{"b", "c"}, []string{"d", "e"})
	first, err := f.verify(t, g)
	if err != nil {
		t.Fatal(err)
	}
	kernelBefore := evolutionJSON(t, f.kernel)
	baseBefore, candidateBefore := append([]byte(nil), f.base...), append([]byte(nil), f.candidate...)
	domainsBefore := make(map[EvidenceSignerID]EvidenceControlDomainID)
	for k, v := range f.domains.domains {
		domainsBefore[k] = v
	}
	graphBefore, err := g.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ev, err := f.verify(t, g)
		if err != nil || ev != first {
			t.Fatalf("revalidation: %+v %v", ev, err)
		}
	}
	for _, tc := range []struct {
		kernel, base Digest
		proposer     string
	}{
		{Digest(strings.Repeat("0", 64)), first.BasePolicyDigest, "a"},
		{Digest(strings.ToUpper(string(first.KernelDigest))), first.BasePolicyDigest, "a"},
		{Digest(" " + string(first.KernelDigest)), first.BasePolicyDigest, "a"},
		{first.KernelDigest, Digest(strings.Repeat("0", 64)), "a"},
		{first.KernelDigest, Digest(strings.ToUpper(string(first.BasePolicyDigest))), "a"},
		{first.KernelDigest, Digest(string(first.BasePolicyDigest) + " "), "a"},
		{first.KernelDigest, first.BasePolicyDigest, "b"},
	} {
		if _, err := VerifyEvolutionApprovalGraph(f.kernel, tc.kernel, tc.base, f.base, f.candidate, ProposalContext{tc.proposer}, f.domains, g); err == nil {
			t.Fatal("non-exact expected digest/proposer accepted")
		}
	}
	if !bytes.Equal(kernelBefore, evolutionJSON(t, f.kernel)) || !bytes.Equal(baseBefore, f.base) || !bytes.Equal(candidateBefore, f.candidate) || !reflect.DeepEqual(domainsBefore, f.domains.domains) {
		t.Fatal("verification mutated input")
	}
	if after, err := g.CanonicalBytes(); err != nil || !bytes.Equal(graphBefore, after) {
		t.Fatal("verification mutated graph")
	}
	b, q := f.kernel.EvolutionKernelConfig.RuleBounds(), f.kernel.EvolutionKernelConfig.RiskQuorums()
	cfg, err := NewEvolutionKernelConfig(b, q)
	if err != nil {
		t.Fatal(err)
	}
	cfgBefore := evolutionJSON(t, cfg)
	b[0].IntegrityDemoteTo[0] = CapabilityTrustQ2
	b[0].Capability = "changed"
	q[0].MinVerifierControlDomains = 7
	returned := cfg.RuleBounds()
	returned[0].IntegrityDemoteTo[0] = CapabilityTrustQ2
	returned[0].Capability = "changed"
	rq := cfg.RiskQuorums()
	rq[0].MinApproverControlDomains = 7
	if !bytes.Equal(cfgBefore, evolutionJSON(t, cfg)) {
		t.Fatal("config aliases constructor/getters")
	}
	reviews, approvals := g.Reviews(), g.Approvals()
	copyGraph, err := NewEvolutionApprovalGraph(g.Context(), reviews, approvals)
	if err != nil {
		t.Fatal(err)
	}
	reviews[0].Signature[0] ^= 1
	reviews[0].ReviewerID = "changed"
	approvals[0].Signature[0] ^= 1
	approvals[0].ApproverID = "changed"
	getterR, getterA := copyGraph.Reviews(), copyGraph.Approvals()
	getterR[0].Signature[0] ^= 1
	getterA[0].Signature[0] ^= 1
	if cb, err := copyGraph.CanonicalBytes(); err != nil || !bytes.Equal(cb, graphBefore) {
		t.Fatal("graph aliases signatures or records")
	}
	raw := evolutionJSON(t, g)
	decoded, err := DecodeEvolutionApprovalGraph(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if cb, err := decoded.CanonicalBytes(); err != nil || !bytes.Equal(cb, graphBefore) {
		t.Fatal("graph retains raw input")
	}
	raw = evolutionJSON(t, f.kernel)
	decodedKernel, err := DecodeKernelSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if cb, err := decodedKernel.CanonicalBytes(); err != nil {
		t.Fatal(err)
	} else {
		original, err := f.kernel.CanonicalBytes()
		if err != nil || !bytes.Equal(cb, original) {
			t.Fatal("kernel retains raw input")
		}
	}
	// Reordering rules changes the raw-policy digest even when the semantic map is
	// identical; this catches accidental map reconstruction at the digest boundary.
	var doc trustPolicyDocument
	if err := json.Unmarshal(f.base, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Rules[0], doc.Rules[1] = doc.Rules[1], doc.Rules[0]
	reordered := evolutionJSON(t, doc)
	if mustEvolutionDigest(t, reordered) == first.BasePolicyDigest {
		t.Fatal("raw rule order was lost")
	}
	if _, err := VerifyEvolutionApprovalGraph(f.kernel, first.KernelDigest, first.BasePolicyDigest, reordered, f.candidate, f.proposal, f.domains, g); err == nil {
		t.Fatal("semantic policy reconstruction authorized stale digest")
	}
}
