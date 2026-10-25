package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	EvidenceSigningDomain canonical.Domain = "paddock.evidence"
	EvidenceNodeSchema                     = "paddock.evidence-node/1"
	EvidenceGraphAudience                  = "evidence-graph"
)

var ErrEvidenceGraph = errors.New("invalid evidence graph")

type EvidenceNodeID string
type GraphSnapshotID string
type EvidenceSubjectID string
type EvidenceSignerID string
type EvidenceDomainID string

type EvidenceRelationKind string

const (
	EvidenceDerivedFrom  EvidenceRelationKind = "DERIVED_FROM"
	EvidenceObservedBy   EvidenceRelationKind = "OBSERVED_BY"
	EvidenceControlledBy EvidenceRelationKind = "CONTROLLED_BY"
)

// EvidenceRelation is an outgoing edge. Canonical order is lexicographic by
// kind, then target; the same target may have different relation kinds.
type EvidenceRelation struct {
	Kind   EvidenceRelationKind `json:"kind"`
	Target EvidenceNodeID       `json:"target"`
}

// EvidenceNodeSpec contains only semantic identity data. PayloadDigest is an
// external SHA-256 reference, never payload bytes or evidence of their existence.
// Edges must already be sorted and unique; malformed ordering is not repaired.
type EvidenceNodeSpec struct {
	Subject       EvidenceSubjectID  `json:"subject"`
	PayloadDigest Digest             `json:"payload_digest"`
	SignerID      EvidenceSignerID   `json:"signer_id"`
	DomainID      EvidenceDomainID   `json:"domain_id"`
	Edges         []EvidenceRelation `json:"edges"`
}

// EvidenceNode is immutable through its public API, including its slice values.
// Its zero value is invalid. A constructed node is not yet trusted: verification
// must authenticate every node in the exact graph with a trusted snapshot.
type EvidenceNode struct {
	id        EvidenceNodeID
	spec      EvidenceNodeSpec
	signature []byte
}

func NewEvidenceNode(id EvidenceNodeID, spec EvidenceNodeSpec, signature []byte) (EvidenceNode, error) {
	want, err := EvidenceNodeIDFor(spec)
	if err != nil {
		return EvidenceNode{}, err
	}
	if id != want || len(signature) != ed25519.SignatureSize {
		return EvidenceNode{}, fmt.Errorf("%w: node ID or signature shape", ErrEvidenceGraph)
	}
	return EvidenceNode{id: id, spec: cloneEvidenceSpec(spec), signature: append([]byte(nil), signature...)}, nil
}

func (n EvidenceNode) ID() EvidenceNodeID     { return n.id }
func (n EvidenceNode) Spec() EvidenceNodeSpec { return cloneEvidenceSpec(n.spec) }
func (n EvidenceNode) Signature() []byte      { return append([]byte(nil), n.signature...) }

func cloneEvidenceSpec(spec EvidenceNodeSpec) EvidenceNodeSpec {
	// Always encode an empty edge set as [], not null, even for a nil input.
	edges := make([]EvidenceRelation, len(spec.Edges))
	copy(edges, spec.Edges)
	spec.Edges = edges
	return spec
}

func evidenceText(s string) bool {
	return s != "" && utf8.ValidString(s) && strings.TrimSpace(s) == s &&
		strings.IndexFunc(s, unicode.IsControl) == -1
}

func validateEvidenceSpec(spec EvidenceNodeSpec) error {
	if !evidenceText(string(spec.Subject)) || !evidenceText(string(spec.SignerID)) ||
		!evidenceText(string(spec.DomainID)) || spec.PayloadDigest.Validate() != nil {
		return fmt.Errorf("%w: subject, signer, domain or payload digest", ErrEvidenceGraph)
	}
	for i, edge := range spec.Edges {
		if edge.Kind != EvidenceDerivedFrom && edge.Kind != EvidenceObservedBy && edge.Kind != EvidenceControlledBy {
			return fmt.Errorf("%w: unknown relation %q", ErrEvidenceGraph, edge.Kind)
		}
		if Digest(edge.Target).Validate() != nil {
			return fmt.Errorf("%w: edge target digest", ErrEvidenceGraph)
		}
		if i > 0 && !evidenceEdgeLess(spec.Edges[i-1], edge) {
			return fmt.Errorf("%w: unsorted or duplicate edges", ErrEvidenceGraph)
		}
	}
	return nil
}

func evidenceEdgeLess(a, b EvidenceRelation) bool {
	return a.Kind < b.Kind || a.Kind == b.Kind && a.Target < b.Target
}

func evidenceJCS(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode record: %v", ErrEvidenceGraph, err)
	}
	b, err := canonical.NewJCSCodec().CanonicalizeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize record: %v", ErrEvidenceGraph, err)
	}
	return b, nil
}

func evidenceHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// EvidenceNodeIDFor hashes JCS of the semantic record, excluding ID/signature.
func EvidenceNodeIDFor(spec EvidenceNodeSpec) (EvidenceNodeID, error) {
	if err := validateEvidenceSpec(spec); err != nil {
		return "", err
	}
	b, err := evidenceJCS(cloneEvidenceSpec(spec))
	if err != nil {
		return "", err
	}
	return EvidenceNodeID(evidenceHash(b)), nil
}

// GraphSnapshotIDFor hashes the exact sorted unique node-ID array. Callers must
// supply strict ascending order; duplicates/unsorted IDs are rejected, not fixed.
// An empty graph has the snapshot SHA256(JCS([])).
func GraphSnapshotIDFor(ids []EvidenceNodeID) (GraphSnapshotID, error) {
	for i, id := range ids {
		if Digest(id).Validate() != nil || i > 0 && ids[i-1] >= id {
			return "", fmt.Errorf("%w: malformed, unsorted or duplicate node IDs", ErrEvidenceGraph)
		}
	}
	values := make([]EvidenceNodeID, len(ids))
	copy(values, ids)
	b, err := evidenceJCS(values)
	if err != nil {
		return "", err
	}
	return GraphSnapshotID(evidenceHash(b)), nil
}

// EvidenceNodeSigningBytes binds the full node record to the exact snapshot.
// There is no clock, nonce consumption, signing key, or external lookup here.
func EvidenceNodeSigningBytes(spec EvidenceNodeSpec, snapshot GraphSnapshotID) ([]byte, error) {
	id, err := EvidenceNodeIDFor(spec)
	if err != nil {
		return nil, err
	}
	if Digest(snapshot).Validate() != nil {
		return nil, fmt.Errorf("%w: snapshot digest", ErrEvidenceGraph)
	}
	payload, err := evidenceJCS(struct {
		EvidenceNodeSpec
		ID EvidenceNodeID `json:"id"`
	}{cloneEvidenceSpec(spec), id})
	if err != nil {
		return nil, err
	}
	b, err := canonical.Envelope(canonical.NewJCSCodec(), EvidenceSigningDomain, canonical.Context{
		SchemaVersion: EvidenceNodeSchema, Audience: EvidenceGraphAudience,
		RequestID: string(id), Nonce: string(snapshot),
	}, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: signing envelope: %v", ErrEvidenceGraph, err)
	}
	return b, nil
}

type EvidenceGraph struct {
	snapshot GraphSnapshotID
	nodes    []EvidenceNode
}

// NewEvidenceGraph checks content addressing, order, closure and acyclicity, not
// authenticity. VerifyEvidenceGraph is still required, even after construction.
func NewEvidenceGraph(snapshot GraphSnapshotID, nodes []EvidenceNode) (EvidenceGraph, error) {
	g := EvidenceGraph{snapshot: snapshot, nodes: cloneEvidenceNodes(nodes)}
	if err := g.validate(); err != nil {
		return EvidenceGraph{}, err
	}
	return g, nil
}

func (g EvidenceGraph) SnapshotID() GraphSnapshotID { return g.snapshot }
func (g EvidenceGraph) Nodes() []EvidenceNode       { return cloneEvidenceNodes(g.nodes) }

func cloneEvidenceNodes(nodes []EvidenceNode) []EvidenceNode {
	out := make([]EvidenceNode, len(nodes))
	for i, n := range nodes {
		out[i] = EvidenceNode{id: n.id, spec: cloneEvidenceSpec(n.spec), signature: n.Signature()}
	}
	return out
}

func (g EvidenceGraph) validate() error {
	ids := make([]EvidenceNodeID, len(g.nodes))
	index := make(map[EvidenceNodeID]int, len(g.nodes))
	for i, n := range g.nodes {
		ids[i] = n.id
		index[n.id] = i
	}
	want, err := GraphSnapshotIDFor(ids)
	if err != nil {
		return err
	}
	if g.snapshot != want {
		return fmt.Errorf("%w: snapshot does not match membership", ErrEvidenceGraph)
	}
	// Validate structure before content hashes so cycle/closure checks also reject
	// adversarial records without assuming that hash fixed points are infeasible.
	indegree := make([]int, len(g.nodes))
	for _, n := range g.nodes {
		if err := validateEvidenceSpec(n.spec); err != nil {
			return err
		}
		for _, edge := range n.spec.Edges {
			target, ok := index[edge.Target]
			if !ok || edge.Target == n.id {
				return fmt.Errorf("%w: missing target or self-edge", ErrEvidenceGraph)
			}
			indegree[target]++
		}
	}
	// Kahn's algorithm avoids recursive stack growth on a long untrusted graph.
	queue := make([]int, 0, len(g.nodes))
	for i, degree := range indegree {
		if degree == 0 {
			queue = append(queue, i)
		}
	}
	for head := 0; head < len(queue); head++ {
		for _, edge := range g.nodes[queue[head]].spec.Edges {
			target := index[edge.Target]
			indegree[target]--
			if indegree[target] == 0 {
				queue = append(queue, target)
			}
		}
	}
	if len(queue) != len(g.nodes) {
		return fmt.Errorf("%w: cycle", ErrEvidenceGraph)
	}
	for _, n := range g.nodes {
		id, err := EvidenceNodeIDFor(n.spec)
		if err != nil {
			return err
		}
		if n.id != id || len(n.signature) != ed25519.SignatureSize {
			return fmt.Errorf("%w: node content ID or signature shape", ErrEvidenceGraph)
		}
	}
	return nil
}

// EvidenceVerifier is trusted caller input, not identity/independence proof.
// DomainID is the expected domain for this signer, not a node-selected key scope.
type EvidenceVerifier struct {
	SignerID  EvidenceSignerID
	DomainID  EvidenceDomainID
	PublicKey ed25519.PublicKey
}

// evidencePublicKey rejects noncanonical Edwards y encodings and all points of
// order dividing 8. crypto/ed25519.Verify alone accepts identity-key forgeries.
// The sign bit is ignored for the torsion check, covering both x signs. The two
// nontrivial y constants are the order-8 points; y=0,1,-1 cover orders 4,1,2.
// Remaining curve/equation validation is performed by the standard verifier.
func evidencePublicKey(key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	var y [ed25519.PublicKeySize]byte
	copy(y[:], key)
	y[31] &= 0x7f
	// y must be strictly less than p=2^255-19 (little-endian ed ff...ff 7f).
	for i := len(y) - 1; i >= 0; i-- {
		limit := byte(0xff)
		if i == 31 {
			limit = 0x7f
		} else if i == 0 {
			limit = 0xed
		}
		if y[i] < limit {
			break
		}
		if y[i] > limit || i == 0 {
			return false
		}
	}
	switch hex.EncodeToString(y[:]) {
	case "0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a":
		return false
	}
	return true
}

type EvidenceVerifierSnapshot struct {
	verifiers map[EvidenceSignerID]EvidenceVerifier
}

// NewEvidenceVerifierSnapshot takes a list so duplicate IDs cannot be silently
// overwritten by map construction. IDs and raw public keys must each be unique,
// including unused entries. It copies every public key and retains no aliases.
func NewEvidenceVerifierSnapshot(entries []EvidenceVerifier) (EvidenceVerifierSnapshot, error) {
	if len(entries) == 0 {
		return EvidenceVerifierSnapshot{}, fmt.Errorf("%w: empty verifier snapshot", ErrEvidenceGraph)
	}
	verifiers := make(map[EvidenceSignerID]EvidenceVerifier, len(entries))
	keys := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !evidenceText(string(entry.SignerID)) || !evidenceText(string(entry.DomainID)) || !evidencePublicKey(entry.PublicKey) {
			return EvidenceVerifierSnapshot{}, fmt.Errorf("%w: verifier identity or key shape", ErrEvidenceGraph)
		}
		if _, exists := verifiers[entry.SignerID]; exists || keys[string(entry.PublicKey)] {
			return EvidenceVerifierSnapshot{}, fmt.Errorf("%w: duplicate verifier ID or key", ErrEvidenceGraph)
		}
		keys[string(entry.PublicKey)] = true
		entry.PublicKey = append(ed25519.PublicKey(nil), entry.PublicKey...)
		verifiers[entry.SignerID] = entry
	}
	return EvidenceVerifierSnapshot{verifiers: verifiers}, nil
}

// VerifyEvidenceGraph is idempotent for the same immutable snapshot. It checks
// every signature and the complete graph, but confers no Trust, Quorum, Scope,
// Authority, real-world identity or independence. It neither resolves artifacts
// nor persists/consumes replay state or manages key custody/rotation.
func VerifyEvidenceGraph(graph EvidenceGraph, trusted EvidenceVerifierSnapshot) error {
	if len(trusted.verifiers) == 0 {
		return fmt.Errorf("%w: missing trusted verifiers", ErrEvidenceGraph)
	}
	if err := graph.validate(); err != nil {
		return err
	}
	for _, node := range graph.nodes {
		verifier, ok := trusted.verifiers[node.spec.SignerID]
		if !ok || verifier.DomainID != node.spec.DomainID {
			return fmt.Errorf("%w: unknown signer or signer-domain mismatch", ErrEvidenceGraph)
		}
		message, err := EvidenceNodeSigningBytes(node.spec, graph.snapshot)
		if err != nil {
			return err
		}
		if !evidencePublicKey(verifier.PublicKey) || !ed25519.Verify(verifier.PublicKey, message, node.signature) {
			return fmt.Errorf("%w: node %s signature", ErrEvidenceGraph, node.id)
		}
	}
	return nil
}
