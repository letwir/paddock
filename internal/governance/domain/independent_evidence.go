package domain

import (
	"errors"
	"fmt"
)

// ErrIndependentEvidence identifies malformed measurement or control-domain
// mapping input. Evidence graph and signature failures retain ErrEvidenceGraph.
var ErrIndependentEvidence = errors.New("invalid independent evidence")

// EvidenceControlDomainID is a caller-trusted label for one control group.
// It is not an identity proof or evidence that the group is independent in the
// real world.
type EvidenceControlDomainID string

// EvidenceControlDomain assigns one evidence signer to one control-domain
// label. Multiple signers may intentionally share the same label.
type EvidenceControlDomain struct {
	SignerID        EvidenceSignerID
	ControlDomainID EvidenceControlDomainID
}

// ControlDomainSnapshot is an immutable caller-trusted signer-to-control-group
// mapping. It is separate from EvidenceVerifierSnapshot: verifier DomainID is
// not a control-domain identity or independence proof.
type ControlDomainSnapshot struct {
	domains map[EvidenceSignerID]EvidenceControlDomainID
}

// NewControlDomainSnapshot validates and copies the supplied mapping. An empty
// mapping is valid and treats all signers as having unknown independence. Input
// order is irrelevant; duplicate signer assignments are rejected.
func NewControlDomainSnapshot(entries []EvidenceControlDomain) (ControlDomainSnapshot, error) {
	domains := make(map[EvidenceSignerID]EvidenceControlDomainID, len(entries))
	for _, entry := range entries {
		if !evidenceText(string(entry.SignerID)) || !evidenceText(string(entry.ControlDomainID)) {
			return ControlDomainSnapshot{}, fmt.Errorf("%w: malformed signer or control domain", ErrIndependentEvidence)
		}
		if _, exists := domains[entry.SignerID]; exists {
			return ControlDomainSnapshot{}, fmt.Errorf("%w: duplicate signer mapping", ErrIndependentEvidence)
		}
		domains[entry.SignerID] = entry.ControlDomainID
	}
	return ControlDomainSnapshot{domains: domains}, nil
}

// CountIndependentEvidence returns the number of distinct mapped control-domain
// labels represented among verified graph nodes for the exact measurement key
// (subject, payload digest). Each label contributes at most one count. Signers
// absent from the trusted mapping are unknown and contribute zero. This function
// deduplicates declared caller-trusted labels; it does not prove that different
// labels correspond to independent real-world actors or organizations.
func CountIndependentEvidence(
	graph EvidenceGraph,
	verifiers EvidenceVerifierSnapshot,
	controlDomains ControlDomainSnapshot,
	subject EvidenceSubjectID,
	payloadDigest Digest,
) (int, error) {
	if !evidenceText(string(subject)) || payloadDigest.Validate() != nil {
		return 0, fmt.Errorf("%w: malformed measurement key", ErrIndependentEvidence)
	}
	if err := VerifyEvidenceGraph(graph, verifiers); err != nil {
		return 0, err
	}

	seen := make(map[EvidenceControlDomainID]struct{})
	for _, node := range graph.Nodes() {
		spec := node.Spec()
		if spec.Subject != subject || spec.PayloadDigest != payloadDigest {
			continue
		}
		domainID, known := controlDomains.domains[spec.SignerID]
		if !known {
			continue
		}
		seen[domainID] = struct{}{}
	}
	return len(seen), nil
}
