package domain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
)

func evidenceTestSpec(subject string) EvidenceNodeSpec {
	return EvidenceNodeSpec{
		Subject: EvidenceSubjectID(subject), PayloadDigest: Digest(strings.Repeat("a", 64)),
		SignerID: "alice", DomainID: "lab-a",
	}
}

func TestEvidenceGraphNodeAndEdgeChangesRequireResigning(t *testing.T) {
	baseSpecs := evidenceTestDAG(t)
	base := evidenceTestGraph(t, baseSpecs)
	for _, change := range []string{"node payload", "edge kind", "edge target", "edge removal"} {
		t.Run(change, func(t *testing.T) {
			specs := evidenceTestDAG(t)
			switch change {
			case "node payload":
				oldTarget := evidenceTestID(t, specs[1])
				specs[1].PayloadDigest = Digest(strings.Repeat("b", 64))
				newTarget := evidenceTestID(t, specs[1])
				for i := range specs[0].Edges {
					if specs[0].Edges[i].Target == oldTarget {
						specs[0].Edges[i].Target = newTarget
					}
				}
			case "edge kind":
				specs[0].Edges = []EvidenceRelation{{EvidenceObservedBy, specs[0].Edges[0].Target}}
			case "edge target":
				specs[0].Edges[0].Target = evidenceTestID(t, specs[2])
			case "edge removal":
				specs[0].Edges = specs[0].Edges[1:]
			}
			sort.Slice(specs[0].Edges, func(i, j int) bool { return evidenceEdgeLess(specs[0].Edges[i], specs[0].Edges[j]) })
			resigned := evidenceTestGraph(t, specs)
			if resigned.SnapshotID() == base.SnapshotID() {
				t.Fatal("changed graph retained snapshot ID")
			}
			trusted := evidenceTestTrust(t)
			if err := VerifyEvidenceGraph(resigned, trusted); err != nil {
				t.Fatal(err)
			}
			for i, n := range resigned.Nodes() {
				// Even a signature on a completely unchanged leaf is unusable in
				// the changed snapshot. Check every individual stale signature.
				nodes := resigned.Nodes()
				for _, old := range base.Nodes() {
					if old.Spec().Subject == n.Spec().Subject {
						nodes[i].signature = old.Signature()
					}
				}
				requireEvidenceError(t, VerifyEvidenceGraph(EvidenceGraph{resigned.snapshot, nodes}, trusted))
			}
		})
	}
}

func evidenceTestKey(n byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
}

func evidenceTestID(t *testing.T, spec EvidenceNodeSpec) EvidenceNodeID {
	t.Helper()
	id, err := EvidenceNodeIDFor(spec)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func evidenceTestSnapshot(t *testing.T, nodes []EvidenceNode) GraphSnapshotID {
	t.Helper()
	ids := make([]EvidenceNodeID, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	id, err := GraphSnapshotIDFor(ids)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func evidenceTestTrust(t *testing.T) EvidenceVerifierSnapshot {
	t.Helper()
	s, err := NewEvidenceVerifierSnapshot([]EvidenceVerifier{
		{SignerID: "alice", DomainID: "lab-a", PublicKey: evidenceTestKey(1).Public().(ed25519.PublicKey)},
		{SignerID: "bob", DomainID: "lab-b", PublicKey: evidenceTestKey(2).Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Fixtures deliberately own signing: the production domain takes public keys
// and signature bytes only and performs no key generation/custody or randomness.
func evidenceTestGraph(t *testing.T, specs []EvidenceNodeSpec) EvidenceGraph {
	t.Helper()
	nodes := make([]EvidenceNode, len(specs))
	for i, spec := range specs {
		nodes[i] = EvidenceNode{id: evidenceTestID(t, spec), spec: cloneEvidenceSpec(spec)}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].id < nodes[j].id })
	snapshot := evidenceTestSnapshot(t, nodes)
	for i, n := range nodes {
		message, err := EvidenceNodeSigningBytes(n.spec, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		key := evidenceTestKey(1)
		if n.spec.SignerID == "bob" {
			key = evidenceTestKey(2)
		}
		nodes[i], err = NewEvidenceNode(n.id, n.spec, ed25519.Sign(key, message))
		if err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewEvidenceGraph(snapshot, nodes)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func evidenceTestDAG(t *testing.T) []EvidenceNodeSpec {
	t.Helper()
	a, b := evidenceTestSpec("artifact-a"), evidenceTestSpec("artifact-b")
	b.SignerID, b.DomainID = "bob", "lab-b"
	aID, bID := evidenceTestID(t, a), evidenceTestID(t, b)
	root := evidenceTestSpec("measurement")
	root.Edges = []EvidenceRelation{
		{EvidenceControlledBy, aID}, {EvidenceDerivedFrom, aID},
		{EvidenceDerivedFrom, bID}, {EvidenceObservedBy, bID},
	}
	sort.Slice(root.Edges, func(i, j int) bool { return evidenceEdgeLess(root.Edges[i], root.Edges[j]) })
	return []EvidenceNodeSpec{root, a, b}
}

func requireEvidenceError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrEvidenceGraph) {
		t.Fatalf("want ErrEvidenceGraph, got %v", err)
	}
}

func TestEvidenceGraphJCSAndSignatureVector(t *testing.T) {
	// Literal semantic bytes, node hash, snapshot hash and envelope were computed
	// separately with Python hashlib/json (ASCII keys, no numeric values).
	// Signing seed/public key are RFC 8032 section 7.1 test vector 1, public data.
	spec := evidenceTestSpec("subject:<&>é😀")
	const semantic = `{"domain_id":"lab-a","edges":[],"payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signer_id":"alice","subject":"subject:<&>é😀"}`
	const nodeID EvidenceNodeID = "dc691cf0c18faa69444047e76b78f8938e9f346bf0ab2bfaadc45679c07fb45d"
	const snapshot GraphSnapshotID = "8f0371497a0aab3de0aea610fca6affce4e7c7fde60de1c9b2794d4c8f1e92e6"
	const envelope = `{"audience":"evidence-graph","domain":"paddock.evidence","nonce":"8f0371497a0aab3de0aea610fca6affce4e7c7fde60de1c9b2794d4c8f1e92e6","payload":{"domain_id":"lab-a","edges":[],"id":"dc691cf0c18faa69444047e76b78f8938e9f346bf0ab2bfaadc45679c07fb45d","payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signer_id":"alice","subject":"subject:<&>é😀"},"request_id":"dc691cf0c18faa69444047e76b78f8938e9f346bf0ab2bfaadc45679c07fb45d","schema_version":"paddock.evidence-node/1"}`
	b, err := evidenceJCS(cloneEvidenceSpec(spec))
	if err != nil || string(b) != semantic {
		t.Fatalf("semantic JCS %s, %v", b, err)
	}
	if got := evidenceTestID(t, spec); got != nodeID {
		t.Fatalf("node ID %s", got)
	}
	gotSnapshot, err := GraphSnapshotIDFor([]EvidenceNodeID{nodeID})
	if err != nil || gotSnapshot != snapshot {
		t.Fatalf("snapshot %s, %v", gotSnapshot, err)
	}
	message, err := EvidenceNodeSigningBytes(spec, snapshot)
	if err != nil || string(message) != envelope {
		t.Fatalf("envelope %s, %v", message, err)
	}
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(key.Public().(ed25519.PublicKey)); got != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatalf("RFC public key %s", got)
	}
	sig := ed25519.Sign(key, message)
	// Frozen Ed25519 result for this exact Evidence/1 transcript, not merely a
	// sign/verify round trip. The semantic/hash vectors above are independent.
	const signature = "e74754c39e96002b9a26b40ea33ddafbe046d089086bff88237de400fb8ad6dca0c66efa37fa4ac22b65420ac620d67fbca5967d172353cb3c954d6d2f8ba207"
	if hex.EncodeToString(sig) != signature {
		t.Fatalf("signature vector %x", sig)
	}
	node, err := NewEvidenceNode(nodeID, spec, sig)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewEvidenceGraph(snapshot, []EvidenceNode{node})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := NewEvidenceVerifierSnapshot([]EvidenceVerifier{{"alice", "lab-a", key.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceGraph(g, trusted); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceGraphDeterminismAndIdempotence(t *testing.T) {
	specs := evidenceTestDAG(t)
	g := evidenceTestGraph(t, specs)
	trusted := evidenceTestTrust(t)
	for i := 0; i < 3; i++ {
		if err := VerifyEvidenceGraph(g, trusted); err != nil {
			t.Fatalf("verification %d: %v", i, err)
		}
	}
	other := evidenceTestGraph(t, []EvidenceNodeSpec{specs[2], specs[0], specs[1]})
	if g.SnapshotID() != other.SnapshotID() {
		t.Fatal("input construction order changed snapshot")
	}
	for i, n := range g.Nodes() {
		if n.ID() != other.Nodes()[i].ID() || !bytes.Equal(n.Signature(), other.Nodes()[i].Signature()) {
			t.Fatal("IDs/signatures not deterministic")
		}
	}
	spec := evidenceTestSpec("nil-edges")
	nilID := evidenceTestID(t, spec)
	spec.Edges = []EvidenceRelation{}
	if evidenceTestID(t, spec) != nilID {
		t.Fatal("nil and empty edge sets differ")
	}
	// The empty graph is an exact immutable snapshot, not proof of any evidence.
	empty, err := GraphSnapshotIDFor(nil)
	if err != nil || empty != "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" {
		t.Fatalf("empty graph hash %s, %v", empty, err)
	}
	g0, err := NewEvidenceGraph(empty, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceGraph(g0, trusted); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceGraphBindsEverySemanticField(t *testing.T) {
	base := evidenceTestDAG(t)[0]
	baseID := evidenceTestID(t, base)
	snapshot := GraphSnapshotID(strings.Repeat("b", 64))
	message, err := EvidenceNodeSigningBytes(base, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	key := evidenceTestKey(1)
	sig := ed25519.Sign(key, message)
	for _, tc := range []struct {
		name string
		edit func(*EvidenceNodeSpec)
	}{
		{"subject", func(s *EvidenceNodeSpec) { s.Subject = "other-subject" }},
		{"digest", func(s *EvidenceNodeSpec) { s.PayloadDigest = Digest(strings.Repeat("b", 64)) }},
		{"signer", func(s *EvidenceNodeSpec) { s.SignerID = "bob" }},
		{"domain", func(s *EvidenceNodeSpec) { s.DomainID = "lab-b" }},
		{"edge kind", func(s *EvidenceNodeSpec) { s.Edges = []EvidenceRelation{{EvidenceObservedBy, s.Edges[0].Target}} }},
		{"edge target", func(s *EvidenceNodeSpec) { s.Edges[0].Target = EvidenceNodeID(strings.Repeat("c", 64)) }},
		{"edge removal", func(s *EvidenceNodeSpec) { s.Edges = s.Edges[1:] }},
		{"edge addition", func(s *EvidenceNodeSpec) {
			s.Edges = append(s.Edges, EvidenceRelation{EvidenceObservedBy, EvidenceNodeID(strings.Repeat("f", 64))})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloneEvidenceSpec(base)
			tc.edit(&changed)
			if evidenceTestID(t, changed) == baseID {
				t.Fatal("semantic change retained content ID")
			}
			changedMessage, err := EvidenceNodeSigningBytes(changed, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(message, changedMessage) || ed25519.Verify(key.Public().(ed25519.PublicKey), changedMessage, sig) {
				t.Fatal("semantic change reused signature")
			}
			_, err = NewEvidenceNode(baseID, changed, sig)
			requireEvidenceError(t, err)
		})
	}
}

func TestEvidenceGraphRejectsChangedEnvelopeContext(t *testing.T) {
	spec := evidenceTestSpec("context")
	g := evidenceTestGraph(t, []EvidenceNodeSpec{spec})
	node := g.Nodes()[0]
	message, err := EvidenceNodeSigningBytes(spec, g.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(message, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ field, value string }{
		{"domain", "paddock.approval"}, {"domain", ""},
		{"schema_version", "paddock.evidence-node/2"}, {"schema_version", ""},
		{"audience", "other-graph"}, {"audience", ""},
		{"request_id", strings.Repeat("b", 64)}, {"request_id", "bad"},
		{"nonce", strings.Repeat("c", 64)}, {"nonce", ""},
	} {
		t.Run(tc.field+"/"+tc.value, func(t *testing.T) {
			altered := make(map[string]json.RawMessage, len(envelope))
			for k, v := range envelope {
				altered[k] = v
			}
			v, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			altered[tc.field] = v
			wrongMessage, err := evidenceJCS(altered)
			if err != nil {
				t.Fatal(err)
			}
			bad := g.Nodes()
			bad[0].signature = ed25519.Sign(evidenceTestKey(1), wrongMessage)
			wrongGraph, err := NewEvidenceGraph(g.SnapshotID(), bad)
			if err != nil {
				t.Fatal(err)
			}
			requireEvidenceError(t, VerifyEvidenceGraph(wrongGraph, evidenceTestTrust(t)))
		})
	}
	// Payload ID is separately covered, in addition to the request_id binding.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(envelope["payload"], &payload); err != nil {
		t.Fatal(err)
	}
	payload["id"] = json.RawMessage(`"` + strings.Repeat("f", 64) + `"`)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope["payload"] = raw
	wrongMessage, err := evidenceJCS(envelope)
	if err != nil {
		t.Fatal(err)
	}
	bad := g.Nodes()
	bad[0].signature = ed25519.Sign(evidenceTestKey(1), wrongMessage)
	requireEvidenceError(t, VerifyEvidenceGraph(EvidenceGraph{g.snapshot, bad}, evidenceTestTrust(t)))
	if node.ID() != g.Nodes()[0].ID() {
		t.Fatal("context tests mutated original")
	}
}

func TestEvidenceGraphMembershipRequiresResigningEveryNode(t *testing.T) {
	g := evidenceTestGraph(t, []EvidenceNodeSpec{evidenceTestSpec("a"), evidenceTestSpec("b")})
	trusted := evidenceTestTrust(t)
	for _, nodes := range [][]EvidenceNode{g.Nodes()[:1], append(g.Nodes(), evidenceTestGraph(t, []EvidenceNodeSpec{evidenceTestSpec("c")}).Nodes()...)} {
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].id < nodes[j].id })
		newSnapshot := evidenceTestSnapshot(t, nodes)
		if newSnapshot == g.SnapshotID() {
			t.Fatal("membership change retained snapshot")
		}
		_, err := NewEvidenceGraph(g.SnapshotID(), nodes)
		requireEvidenceError(t, err)
		changed, err := NewEvidenceGraph(newSnapshot, nodes)
		if err != nil {
			t.Fatal(err)
		}
		requireEvidenceError(t, VerifyEvidenceGraph(changed, trusted))
		specs := make([]EvidenceNodeSpec, len(nodes))
		for i, n := range nodes {
			specs[i] = n.Spec()
		}
		resigned := evidenceTestGraph(t, specs)
		if err := VerifyEvidenceGraph(resigned, trusted); err != nil {
			t.Fatal(err)
		}
		for _, old := range nodes {
			for _, n := range resigned.Nodes() {
				if old.ID() == n.ID() && bytes.Equal(old.Signature(), n.Signature()) {
					t.Fatal("unchanged content reused signature in changed graph")
				}
			}
		}
	}
}

func TestEvidenceGraphRejectsMalformedNodeSpecs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*EvidenceNodeSpec)
	}{
		{"empty subject", func(s *EvidenceNodeSpec) { s.Subject = "" }},
		{"subject whitespace", func(s *EvidenceNodeSpec) { s.Subject = " x" }},
		{"invalid UTF8", func(s *EvidenceNodeSpec) { s.Subject = EvidenceSubjectID(string([]byte{0xff})) }},
		{"control", func(s *EvidenceNodeSpec) { s.Subject = "x\x00y" }},
		{"empty signer", func(s *EvidenceNodeSpec) { s.SignerID = "" }},
		{"invalid signer", func(s *EvidenceNodeSpec) { s.SignerID = EvidenceSignerID(string([]byte{0xff})) }},
		{"empty domain", func(s *EvidenceNodeSpec) { s.DomainID = "" }},
		{"invalid domain", func(s *EvidenceNodeSpec) { s.DomainID = " lab-a" }},
		{"empty digest", func(s *EvidenceNodeSpec) { s.PayloadDigest = "" }},
		{"short digest", func(s *EvidenceNodeSpec) { s.PayloadDigest = "abcd" }},
		{"uppercase digest", func(s *EvidenceNodeSpec) { s.PayloadDigest = Digest(strings.Repeat("A", 64)) }},
		{"nonhex digest", func(s *EvidenceNodeSpec) { s.PayloadDigest = Digest(strings.Repeat("g", 64)) }},
		{"digest prefix", func(s *EvidenceNodeSpec) { s.PayloadDigest = "sha256:" + s.PayloadDigest }},
		{"unknown relation", func(s *EvidenceNodeSpec) { s.Edges[0].Kind = "ENDORSED_BY" }},
		{"empty relation", func(s *EvidenceNodeSpec) { s.Edges[0].Kind = "" }},
		{"malformed target", func(s *EvidenceNodeSpec) { s.Edges[0].Target = "target" }},
		{"uppercase target", func(s *EvidenceNodeSpec) { s.Edges[0].Target = EvidenceNodeID(strings.Repeat("A", 64)) }},
		{"duplicate edge", func(s *EvidenceNodeSpec) { s.Edges = []EvidenceRelation{s.Edges[0], s.Edges[0]} }},
		{"unsorted kinds", func(s *EvidenceNodeSpec) { s.Edges[0], s.Edges[3] = s.Edges[3], s.Edges[0] }},
		{"unsorted targets", func(s *EvidenceNodeSpec) { s.Edges[1], s.Edges[2] = s.Edges[2], s.Edges[1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := evidenceTestDAG(t)[0]
			tc.edit(&spec)
			_, err := EvidenceNodeIDFor(spec)
			requireEvidenceError(t, err)
			_, err = EvidenceNodeSigningBytes(spec, GraphSnapshotID(strings.Repeat("a", 64)))
			requireEvidenceError(t, err)
			_, err = NewEvidenceNode(EvidenceNodeID(strings.Repeat("a", 64)), spec, make([]byte, ed25519.SignatureSize))
			requireEvidenceError(t, err)
		})
	}
	for _, bad := range []string{"", "bad", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		_, err := GraphSnapshotIDFor([]EvidenceNodeID{EvidenceNodeID(bad)})
		requireEvidenceError(t, err)
		_, err = EvidenceNodeSigningBytes(evidenceTestSpec("s"), GraphSnapshotID(bad))
		requireEvidenceError(t, err)
	}
}

func TestEvidenceGraphRejectsMalformedGraphs(t *testing.T) {
	for _, name := range []string{"unsorted nodes", "duplicate nodes", "missing target", "self edge", "two cycle", "three cycle", "disconnected cycle", "wrong ID", "zero node", "wrong snapshot", "zero graph"} {
		t.Run(name, func(t *testing.T) {
			g := evidenceTestGraph(t, evidenceTestDAG(t))
			bad := EvidenceGraph{g.snapshot, g.Nodes()}
			switch name {
			case "unsorted nodes":
				bad.nodes[0], bad.nodes[1] = bad.nodes[1], bad.nodes[0]
			case "duplicate nodes":
				bad.nodes = append(bad.nodes[:1], bad.nodes...)
			case "missing target", "self edge", "two cycle", "three cycle", "disconnected cycle":
				// Deliberately corrupt immutable internals to exercise graph topology
				// independently of hash mismatch (content-addressed cycles would
				// otherwise require infeasible SHA-256 fixed points).
				for i := range bad.nodes {
					bad.nodes[i].spec.Edges = nil
				}
				switch name {
				case "missing target":
					bad.nodes[0].spec.Edges = []EvidenceRelation{{EvidenceDerivedFrom, EvidenceNodeID(strings.Repeat("f", 64))}}
				case "self edge":
					bad.nodes[0].spec.Edges = []EvidenceRelation{{EvidenceDerivedFrom, bad.nodes[0].id}}
				case "two cycle", "disconnected cycle":
					a, b := 0, 1
					if name == "disconnected cycle" {
						a, b = 1, 2
					}
					bad.nodes[a].spec.Edges = []EvidenceRelation{{EvidenceControlledBy, bad.nodes[b].id}}
					bad.nodes[b].spec.Edges = []EvidenceRelation{{EvidenceObservedBy, bad.nodes[a].id}}
				case "three cycle":
					for i := range bad.nodes {
						bad.nodes[i].spec.Edges = []EvidenceRelation{{EvidenceDerivedFrom, bad.nodes[(i+1)%3].id}}
					}
				}
			case "wrong ID":
				bad.nodes[0].id = EvidenceNodeID(strings.Repeat("0", 64))
				bad.snapshot = evidenceTestSnapshot(t, bad.nodes)
			case "zero node":
				bad.nodes[0] = EvidenceNode{}
			case "wrong snapshot":
				bad.snapshot = GraphSnapshotID(strings.Repeat("f", 64))
			case "zero graph":
				bad = EvidenceGraph{}
			}
			_, err := NewEvidenceGraph(bad.snapshot, bad.nodes)
			requireEvidenceError(t, err)
			if strings.Contains(name, "cycle") && !strings.Contains(err.Error(), "cycle") {
				t.Fatalf("cycle check not exercised: %v", err)
			}
			requireEvidenceError(t, VerifyEvidenceGraph(bad, evidenceTestTrust(t)))
		})
	}
	ids := []EvidenceNodeID{EvidenceNodeID(strings.Repeat("b", 64)), EvidenceNodeID(strings.Repeat("a", 64))}
	_, err := GraphSnapshotIDFor(ids)
	requireEvidenceError(t, err)
	_, err = GraphSnapshotIDFor([]EvidenceNodeID{ids[0], ids[0]})
	requireEvidenceError(t, err)
}

func TestEvidenceGraphTrustedSignerDomainAndSignatureFailures(t *testing.T) {
	g := evidenceTestGraph(t, evidenceTestDAG(t))
	for _, name := range []string{"unknown signer", "signer domain", "wrong key", "invalid curve key", "zero snapshot"} {
		t.Run(name, func(t *testing.T) {
			entries := []EvidenceVerifier{
				{"alice", "lab-a", evidenceTestKey(1).Public().(ed25519.PublicKey)},
				{"bob", "lab-b", evidenceTestKey(2).Public().(ed25519.PublicKey)},
			}
			switch name {
			case "unknown signer":
				entries = entries[:1]
			case "signer domain":
				entries[1].DomainID = "lab-a"
			case "wrong key":
				entries[1].PublicKey = evidenceTestKey(3).Public().(ed25519.PublicKey)
			case "invalid curve key":
				entries[1].PublicKey = bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)
			}
			trusted, err := NewEvidenceVerifierSnapshot(entries)
			if err != nil {
				if name == "invalid curve key" {
					requireEvidenceError(t, err)
					return
				}
				t.Fatal(err)
			}
			if name == "zero snapshot" {
				trusted = EvidenceVerifierSnapshot{}
			}
			requireEvidenceError(t, VerifyEvidenceGraph(g, trusted))
		})
	}
	for i := range g.Nodes() {
		for _, length := range []int{0, 63, 64, 65} {
			nodes := g.Nodes()
			nodes[i].signature = make([]byte, length)
			requireEvidenceError(t, VerifyEvidenceGraph(EvidenceGraph{g.snapshot, nodes}, evidenceTestTrust(t)))
			_, err := NewEvidenceNode(nodes[i].id, nodes[i].spec, nodes[i].signature)
			if length != ed25519.SignatureSize {
				requireEvidenceError(t, err)
			} else if err != nil {
				t.Fatal("constructor must not claim signature authenticity", err)
			}
		}
		nodes := g.Nodes()
		nodes[i].signature[17] ^= 0x80
		requireEvidenceError(t, VerifyEvidenceGraph(EvidenceGraph{g.snapshot, nodes}, evidenceTestTrust(t)))
	}
	// A valid signature by bob does not permit a claim to alice's domain.
	spec := evidenceTestSpec("domain impersonation")
	spec.SignerID = "bob"
	claimed := evidenceTestGraph(t, []EvidenceNodeSpec{spec})
	requireEvidenceError(t, VerifyEvidenceGraph(claimed, evidenceTestTrust(t)))
}

func TestEvidenceGraphRejectsMalformedTrustedSnapshot(t *testing.T) {
	for _, name := range []string{"empty", "duplicate ID", "duplicate key", "empty ID", "invalid ID", "empty domain", "invalid domain", "short key", "long key", "nil key"} {
		t.Run(name, func(t *testing.T) {
			entries := []EvidenceVerifier{
				{"alice", "lab-a", evidenceTestKey(1).Public().(ed25519.PublicKey)},
				{"bob", "lab-b", evidenceTestKey(2).Public().(ed25519.PublicKey)},
			}
			switch name {
			case "empty":
				entries = nil
			case "duplicate ID":
				entries[1].SignerID = entries[0].SignerID
			case "duplicate key":
				entries[1].PublicKey = append(ed25519.PublicKey(nil), entries[0].PublicKey...)
			case "empty ID":
				entries[1].SignerID = ""
			case "invalid ID":
				entries[1].SignerID = " bob"
			case "empty domain":
				entries[1].DomainID = ""
			case "invalid domain":
				entries[1].DomainID = EvidenceDomainID(string([]byte{0xff}))
			case "short key":
				entries[1].PublicKey = make([]byte, 31)
			case "long key":
				entries[1].PublicKey = make([]byte, 33)
			case "nil key":
				entries[1].PublicKey = nil
			}
			_, err := NewEvidenceVerifierSnapshot(entries)
			requireEvidenceError(t, err)
		})
	}
}

func TestEvidenceGraphMutationImmutability(t *testing.T) {
	g := evidenceTestGraph(t, evidenceTestDAG(t))
	trusted := evidenceTestTrust(t)
	for _, original := range g.Nodes() {
		spec, sig := original.Spec(), original.Signature()
		node, err := NewEvidenceNode(original.ID(), spec, sig)
		if err != nil {
			t.Fatal(err)
		}
		before, err := EvidenceNodeSigningBytes(node.Spec(), g.SnapshotID())
		if err != nil {
			t.Fatal(err)
		}
		if len(spec.Edges) > 0 {
			spec.Edges[0].Kind = "INVALID"
		}
		spec.Subject = "mutated input"
		sig[0] ^= 1
		outSpec, outSig := node.Spec(), node.Signature()
		if len(outSpec.Edges) > 0 {
			outSpec.Edges[0].Target = "mutated output"
		}
		outSig[1] ^= 1
		after, err := EvidenceNodeSigningBytes(node.Spec(), g.SnapshotID())
		if err != nil || !bytes.Equal(before, after) || !bytes.Equal(node.Signature(), original.Signature()) {
			t.Fatalf("node aliases caller memory: %v", err)
		}
	}
	input := g.Nodes()
	copyGraph, err := NewEvidenceGraph(g.SnapshotID(), input)
	if err != nil {
		t.Fatal(err)
	}
	// Internal fields are reachable only because this is a same-package test.
	input[0].signature[0] ^= 1
	input[0].spec.Subject = "mutated input node"
	input[0] = EvidenceNode{}
	output := copyGraph.Nodes()
	output[0].signature[0] ^= 1
	for i := range output {
		if len(output[i].spec.Edges) > 0 {
			output[i].spec.Edges[0].Kind = "INVALID"
		}
	}
	output[0] = EvidenceNode{}
	if err := VerifyEvidenceGraph(copyGraph, trusted); err != nil {
		t.Fatal("graph aliases node input/output", err)
	}
	pub := evidenceTestKey(1).Public().(ed25519.PublicKey)
	entries := []EvidenceVerifier{{"alice", "lab-a", pub}}
	snapshot, err := NewEvidenceVerifierSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	pub[0] ^= 1
	entries[0].PublicKey[1] ^= 1
	entries[0].DomainID = "mutated"
	entries[0] = EvidenceVerifier{}
	if err := VerifyEvidenceGraph(evidenceTestGraph(t, []EvidenceNodeSpec{evidenceTestSpec("immutable trust")}), snapshot); err != nil {
		t.Fatal("trusted snapshot aliases caller memory", err)
	}
	// Returned signing buffers are detached as well.
	spec := evidenceTestSpec("bytes")
	snapshotID := GraphSnapshotID(strings.Repeat("a", 64))
	before, err := EvidenceNodeSigningBytes(spec, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(before)
	before[0] ^= 1
	after, err := EvidenceNodeSigningBytes(spec, snapshotID)
	if err != nil || sha256.Sum256(after) != hash {
		t.Fatal("signing byte mutation leaked", err)
	}
}

func TestEvidenceGraphRejectsNoncanonicalAndSmallOrderKeys(t *testing.T) {
	for _, encoded := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		for _, sign := range []byte{0, 0x80} {
			key, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			key[31] |= sign
			_, err = NewEvidenceVerifierSnapshot([]EvidenceVerifier{{"alice", "lab-a", key}})
			requireEvidenceError(t, err)
		}
	}
	for i := byte(1); i <= 64; i++ {
		key := evidenceTestKey(i).Public().(ed25519.PublicKey)
		if !evidencePublicKey(key) {
			t.Fatalf("valid fixture public key %d rejected", i)
		}
	}
}

func TestEvidenceGraphRejectsIdentityKeyForgery(t *testing.T) {
	// The identity point is not a valid signing key, even though it is 32 bytes.
	// R=identity,S=0 verifies algebraically for every message under that point.
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	key[0] = 1
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1
	spec := evidenceTestSpec("weak key")
	id := evidenceTestID(t, spec)
	snapshot, err := GraphSnapshotIDFor([]EvidenceNodeID{id})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := NewEvidenceVerifierSnapshot([]EvidenceVerifier{{"alice", "lab-a", key}})
	if err != nil {
		requireEvidenceError(t, err)
		return
	}
	node, err := NewEvidenceNode(id, spec, sig)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewEvidenceGraph(snapshot, []EvidenceNode{node})
	if err != nil {
		t.Fatal(err)
	}
	requireEvidenceError(t, VerifyEvidenceGraph(g, trusted))
}

func TestEvidenceGraphSignatureCoversEdgesNotOnlyContentID(t *testing.T) {
	spec := evidenceTestDAG(t)[0]
	g := evidenceTestGraph(t, evidenceTestDAG(t))
	message, err := EvidenceNodeSigningBytes(spec, g.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(message, &envelope); err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(envelope["payload"], &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "edges")
	shortPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	wrongMessage, err := canonical.Envelope(canonical.NewJCSCodec(), EvidenceSigningDomain, canonical.Context{
		SchemaVersion: EvidenceNodeSchema, Audience: EvidenceGraphAudience,
		RequestID: string(evidenceTestID(t, spec)), Nonce: string(g.SnapshotID()),
	}, shortPayload)
	if err != nil {
		t.Fatal(err)
	}
	nodes := g.Nodes()
	for i := range nodes {
		if nodes[i].ID() == evidenceTestID(t, spec) {
			nodes[i].signature = ed25519.Sign(evidenceTestKey(1), wrongMessage)
		}
	}
	requireEvidenceError(t, VerifyEvidenceGraph(EvidenceGraph{g.snapshot, nodes}, evidenceTestTrust(t)))
}
