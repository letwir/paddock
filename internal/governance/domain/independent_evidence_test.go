package domain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"testing"
)

type independentTestNode struct {
	id         EvidenceNodeID
	spec       EvidenceNodeSpec
	privateKey ed25519.PrivateKey
}

func independentTestGraph(t *testing.T, specs []EvidenceNodeSpec) (EvidenceGraph, EvidenceVerifierSnapshot) {
	t.Helper()
	keys := make(map[EvidenceSignerID]ed25519.PrivateKey, len(specs))
	verifiers := make([]EvidenceVerifier, 0, len(specs))
	nodes := make([]independentTestNode, 0, len(specs))
	var seed byte = 11
	for _, spec := range specs {
		key, ok := keys[spec.SignerID]
		if !ok {
			key = evidenceTestKey(seed)
			seed++
			keys[spec.SignerID] = key
			verifiers = append(verifiers, EvidenceVerifier{
				SignerID: spec.SignerID, DomainID: spec.DomainID,
				PublicKey: key.Public().(ed25519.PublicKey),
			})
		}
		id, err := EvidenceNodeIDFor(spec)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, independentTestNode{id: id, spec: cloneEvidenceSpec(spec), privateKey: key})
	}
	trusted, err := NewEvidenceVerifierSnapshot(verifiers)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].id < nodes[j].id })
	ids := make([]EvidenceNodeID, len(nodes))
	for i := range nodes {
		ids[i] = nodes[i].id
	}
	snapshot, err := GraphSnapshotIDFor(ids)
	if err != nil {
		t.Fatal(err)
	}
	verifiedNodes := make([]EvidenceNode, len(nodes))
	for i, item := range nodes {
		message, err := EvidenceNodeSigningBytes(item.spec, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		verifiedNodes[i], err = NewEvidenceNode(item.id, item.spec, ed25519.Sign(item.privateKey, message))
		if err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewEvidenceGraph(snapshot, verifiedNodes)
	if err != nil {
		t.Fatal(err)
	}
	return graph, trusted
}

func independentTestSpecs(count int, subject EvidenceSubjectID, digest Digest) []EvidenceNodeSpec {
	specs := make([]EvidenceNodeSpec, count)
	for i := range specs {
		specs[i] = EvidenceNodeSpec{
			Subject: subject, PayloadDigest: digest,
			SignerID: EvidenceSignerID(fmt.Sprintf("signer-%02d", i)),
			DomainID: EvidenceDomainID(fmt.Sprintf("verifier-%02d", i)),
			Edges:    []EvidenceRelation{},
		}
	}
	return specs
}

func TestCountIndependentEvidenceTenSignersInOneControlDomainCountOnce(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:temperature"
	const digest Digest = Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	specs := independentTestSpecs(10, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)
	entries := make([]EvidenceControlDomain, len(specs))
	for i, spec := range specs {
		entries[i] = EvidenceControlDomain{SignerID: spec.SignerID, ControlDomainID: "control-shared"}
	}
	controlDomains, err := NewControlDomainSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}

	got, err := CountIndependentEvidence(graph, verifiers, controlDomains, subject, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("count = %d, want 1 for ten signers in one control domain", got)
	}
}

func TestCountIndependentEvidenceSkipsUnknownAlongsideKnownDomains(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:altitude"
	const digest Digest = Digest("2222222222222222222222222222222222222222222222222222222222222222")
	specs := independentTestSpecs(3, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)
	controlDomains, err := NewControlDomainSnapshot([]EvidenceControlDomain{
		{SignerID: specs[0].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[1].SignerID, ControlDomainID: "control-b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := CountIndependentEvidence(graph, verifiers, controlDomains, subject, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("count = %d, want 2 known domains; unmapped signer must contribute zero", got)
	}
}

func TestCountIndependentEvidenceUnknownAndEmptySnapshotContributeZero(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:pressure"
	const digest Digest = Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	specs := independentTestSpecs(3, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)

	for name, entries := range map[string][]EvidenceControlDomain{
		"empty constructor snapshot": nil,
		"zero value snapshot":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			var snapshot ControlDomainSnapshot
			if name == "empty constructor snapshot" {
				var err error
				snapshot, err = NewControlDomainSnapshot(entries)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := CountIndependentEvidence(graph, verifiers, snapshot, subject, digest)
			if err != nil {
				t.Fatal(err)
			}
			if got != 0 {
				t.Fatalf("count = %d, want 0 for unknown independence", got)
			}
		})
	}
}

func TestCountIndependentEvidenceCountsDistinctDomainsPerExactMeasurement(t *testing.T) {
	const digestA Digest = Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	const digestB Digest = Digest("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	specs := independentTestSpecs(3, "measurement:voltage", digestA)
	specs = append(specs,
		independentTestSpecs(1, "measurement:voltage", digestB)[0],
		independentTestSpecs(1, "measurement:current", digestA)[0],
	)
	// Keep signers unique while varying each component of the measurement key.
	specs[3].SignerID = "signer-other-measurement"
	specs[3].DomainID = "verifier-other-measurement"
	specs[4].SignerID = "signer-other-subject"
	specs[4].DomainID = "verifier-other-subject"
	graph, verifiers := independentTestGraph(t, specs)
	entries := []EvidenceControlDomain{
		{SignerID: specs[0].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[1].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[2].SignerID, ControlDomainID: "control-b"},
		{SignerID: specs[3].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[4].SignerID, ControlDomainID: "control-c"},
	}
	controlDomains, err := NewControlDomainSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		subject EvidenceSubjectID
		digest  Digest
		want    int
	}{
		{name: "different control domains count once each", subject: "measurement:voltage", digest: digestA, want: 2},
		{name: "different payload is separate measurement", subject: "measurement:voltage", digest: digestB, want: 1},
		{name: "different subject with same payload is separate measurement", subject: "measurement:current", digest: digestA, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CountIndependentEvidence(graph, verifiers, controlDomains, tc.subject, tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestNewControlDomainSnapshotValidatesCopiesAndIgnoresEntryOrder(t *testing.T) {
	entries := []EvidenceControlDomain{
		{SignerID: "signer-a", ControlDomainID: "control-a"},
		{SignerID: "signer-b", ControlDomainID: "control-b"},
	}
	snapshot, err := NewControlDomainSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].ControlDomainID = "mutated-after-construction"
	if got := snapshot.domains["signer-a"]; got != "control-a" {
		t.Fatalf("constructor retained caller alias: got %q", got)
	}
	reversed, err := NewControlDomainSnapshot([]EvidenceControlDomain{entries[1], {SignerID: "signer-a", ControlDomainID: "control-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.domains["signer-a"] != reversed.domains["signer-a"] || snapshot.domains["signer-b"] != reversed.domains["signer-b"] {
		t.Fatal("mapping changed with input order")
	}
}

func TestNewControlDomainSnapshotRejectsDuplicateOrMalformedEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []EvidenceControlDomain
	}{
		{name: "duplicate signer", entries: []EvidenceControlDomain{
			{SignerID: "signer-a", ControlDomainID: "control-a"},
			{SignerID: "signer-a", ControlDomainID: "control-b"},
		}},
		{name: "empty signer", entries: []EvidenceControlDomain{{ControlDomainID: "control-a"}}},
		{name: "empty domain", entries: []EvidenceControlDomain{{SignerID: "signer-a"}}},
		{name: "trimmed signer", entries: []EvidenceControlDomain{{SignerID: " signer-a", ControlDomainID: "control-a"}}},
		{name: "control byte", entries: []EvidenceControlDomain{{SignerID: "signer-a", ControlDomainID: "control-a\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewControlDomainSnapshot(tc.entries); !errors.Is(err, ErrIndependentEvidence) {
				t.Fatalf("want ErrIndependentEvidence, got %v", err)
			}
		})
	}
}

func TestCountIndependentEvidenceFailsClosedForBadMeasurementOrGraph(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:humidity"
	const digest Digest = Digest("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	specs := independentTestSpecs(1, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)
	controlDomains, err := NewControlDomainSnapshot([]EvidenceControlDomain{{
		SignerID: specs[0].SignerID, ControlDomainID: "control-a",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CountIndependentEvidence(graph, verifiers, controlDomains, " ", digest); !errors.Is(err, ErrIndependentEvidence) {
		t.Fatalf("want measurement validation error, got %v", err)
	}
	if _, err := CountIndependentEvidence(graph, verifiers, controlDomains, subject, "bad-digest"); !errors.Is(err, ErrIndependentEvidence) {
		t.Fatalf("want digest validation error, got %v", err)
	}

	badNodes := graph.Nodes()
	badNodes[0].signature[0] ^= 0xff
	badGraph := EvidenceGraph{snapshot: graph.snapshot, nodes: badNodes}
	if _, err := CountIndependentEvidence(badGraph, verifiers, controlDomains, subject, digest); !errors.Is(err, ErrEvidenceGraph) {
		t.Fatalf("want graph verification error, got %v", err)
	}
}

func TestCountIndependentEvidenceDoesNotMutateGraph(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:light"
	const digest Digest = Digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	specs := independentTestSpecs(2, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)
	controlDomains, err := NewControlDomainSnapshot([]EvidenceControlDomain{
		{SignerID: specs[0].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[1].SignerID, ControlDomainID: "control-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range graph.Nodes() {
		node.signature[0] ^= 0xff
		node.spec.Subject = "mutated-copy"
	}
	got, err := CountIndependentEvidence(graph, verifiers, controlDomains, subject, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("count after mutating returned graph copies = %d, want 1", got)
	}
}

func TestControlDomainIDsAreExactLabels(t *testing.T) {
	const subject EvidenceSubjectID = "measurement:current"
	const digest Digest = Digest("1111111111111111111111111111111111111111111111111111111111111111")
	specs := independentTestSpecs(2, subject, digest)
	graph, verifiers := independentTestGraph(t, specs)
	entries := []EvidenceControlDomain{
		{SignerID: specs[0].SignerID, ControlDomainID: "control-a"},
		{SignerID: specs[1].SignerID, ControlDomainID: "CONTROL-A"},
	}
	snapshot, err := NewControlDomainSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CountIndependentEvidence(graph, verifiers, snapshot, subject, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("case-sensitive control labels count = %d, want 2", got)
	}
}
