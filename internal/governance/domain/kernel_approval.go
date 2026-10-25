package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	KernelSnapshotSchema   = "paddock.kernel-snapshot/1"
	KernelSnapshotSchemaV2 = "paddock.kernel-snapshot/2"
	DomainApprovalSchema   = "paddock.domain-approval/1"
)

var ErrKernelApproval = errors.New("invalid kernel approval")
var capabilityIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$`)

type GovernanceTier string

const (
	TierG0 GovernanceTier = "G0"
	TierG1 GovernanceTier = "G1"
	TierG2 GovernanceTier = "G2"
	TierG3 GovernanceTier = "G3"
)

type KernelSigner struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
}
type TierThreshold struct {
	Tier      GovernanceTier `json:"tier"`
	Threshold int            `json:"threshold"`
}
type IssuerCeiling struct {
	IssuerID     string   `json:"issuer_id"`
	Capabilities []string `json:"capabilities"`
}
type KernelSnapshot struct {
	SchemaVersion         string                 `json:"schema_version"`
	Version               uint64                 `json:"version"`
	Signers               []KernelSigner         `json:"signers"`
	Thresholds            []TierThreshold        `json:"thresholds"`
	Capabilities          []string               `json:"capabilities"`
	IssuerCeilings        []IssuerCeiling        `json:"issuer_ceilings"`
	EvolutionKernelConfig *EvolutionKernelConfig `json:"evolution_kernel_config,omitempty"`
}

func (s KernelSnapshot) CanonicalBytes() ([]byte, error) {
	switch s.SchemaVersion {
	case KernelSnapshotSchema:
		if s.EvolutionKernelConfig != nil || s.Version == 0 || len(s.Signers) == 0 {
			return nil, fmt.Errorf("%w: malformed snapshot header", ErrKernelApproval)
		}
	case KernelSnapshotSchemaV2:
		if err := validateEvolutionKernel(s); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: unsupported snapshot schema", ErrKernelApproval)
	}
	codec := canonical.NewJCSCodec()
	b, e := json.Marshal(s)
	if e != nil {
		return nil, fmt.Errorf("%w: encode snapshot", ErrKernelApproval)
	}
	return codec.CanonicalizeJSON(b)
}
func (s KernelSnapshot) Digest() (Digest, error) {
	b, e := s.CanonicalBytes()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return Digest(hex.EncodeToString(h[:])), nil
}
func DecodeKernelSnapshot(data []byte) (KernelSnapshot, error) {
	// Validate the ORIGINAL bytes before any map/typed decoding can discard
	// duplicate members or round unsafe numbers.
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(data)
	if err != nil {
		return KernelSnapshot{}, fmt.Errorf("%w: snapshot JSON: %v", ErrKernelApproval, err)
	}
	if err := evolutionKernelFields(cb); err != nil {
		return KernelSnapshot{}, fmt.Errorf("%w: snapshot fields: %v", ErrKernelApproval, err)
	}
	// Decode through an alias so UnmarshalJSON cannot recursively re-enter.
	type wireSnapshot KernelSnapshot
	var wire wireSnapshot
	if err := json.Unmarshal(cb, &wire); err != nil {
		return KernelSnapshot{}, fmt.Errorf("%w: snapshot decode: %v", ErrKernelApproval, err)
	}
	s := KernelSnapshot(wire)
	if s.SchemaVersion == KernelSnapshotSchema {
		err = validateKernel(s)
	} else {
		err = validateEvolutionKernel(s)
	}
	if err != nil {
		return KernelSnapshot{}, err
	}
	return s, nil
}

// UnmarshalJSON keeps direct encoding/json callers on the same strict boundary.
// Failed decoding leaves the receiver unchanged.
func (s *KernelSnapshot) UnmarshalJSON(data []byte) error {
	value, err := DecodeKernelSnapshot(data)
	if err != nil {
		return err
	}
	*s = value
	return nil
}

type DomainCandidate struct {
	Bundle                      CanonicalBundle
	Tier                        GovernanceTier
	IssuerID, ProposalID, Nonce string
	CapabilityIDs               []string
}
type ProposalContext struct{ ProposerID string }
type DomainApproval struct {
	SignerID  string `json:"signer_id"`
	Signature []byte `json:"signature"`
}
type ApprovalEvidence struct {
	Accepted        bool
	KernelDigest    Digest
	CandidateDigest Digest
	Tier            GovernanceTier
	Signers         []string
	Reason          string
}

func DomainApprovalSigningBytes(candidate DomainCandidate, kernel Digest, proposer string) ([]byte, error) {
	if candidate.Bundle.Validate() != nil || candidate.Bundle.SchemaVersion() != BundleSchemaVersion || kernel.Validate() != nil || !validTier(candidate.Tier) || validateID(candidate.IssuerID) != nil || validateID(candidate.ProposalID) != nil || validateID(candidate.Nonce) != nil || validateID(proposer) != nil {
		return nil, fmt.Errorf("%w: malformed approval context", ErrKernelApproval)
	}
	payload := struct {
		BundleDigest  Digest         `json:"bundle_digest"`
		KernelDigest  Digest         `json:"kernel_digest"`
		Tier          GovernanceTier `json:"tier"`
		IssuerID      string         `json:"issuer_id"`
		ProposalID    string         `json:"proposal_id"`
		ProposerID    string         `json:"proposer_id"`
		CapabilityIDs []string       `json:"capability_ids"`
	}{
		BundleDigest:  candidate.Bundle.Digest(),
		KernelDigest:  kernel,
		Tier:          candidate.Tier,
		IssuerID:      candidate.IssuerID,
		ProposalID:    candidate.ProposalID,
		ProposerID:    proposer,
		CapabilityIDs: append([]string(nil), candidate.CapabilityIDs...),
	}
	sort.Strings(payload.CapabilityIDs)
	b, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	cb, e := canonical.NewJCSCodec().CanonicalizeJSON(b)
	if e != nil {
		return nil, e
	}
	return canonical.Envelope(canonical.NewJCSCodec(), canonical.DomainApproval, canonical.Context{SchemaVersion: DomainApprovalSchema, Audience: "governance", RequestID: candidate.ProposalID, Nonce: candidate.Nonce}, cb)
}

func VerifyKernelApprovalSignatures(snapshot KernelSnapshot, expectedKernel Digest, tier GovernanceTier, proposer string, message []byte, approvals []DomainApproval) ApprovalEvidence {
	ev := ApprovalEvidence{Tier: tier, Reason: "rejected"}
	kd, err := snapshot.Digest()
	if err != nil {
		ev.Reason = "malformed kernel"
		return ev
	}
	ev.KernelDigest = kd
	if expectedKernel.Validate() != nil || kd != expectedKernel {
		ev.Reason = "kernel digest mismatch"
		return ev
	}
	if err = validateKernel(snapshot); err != nil {
		ev.Reason = "malformed kernel"
		return ev
	}
	if !validTier(tier) {
		ev.Reason = "unsupported tier"
		return ev
	}
	if validateID(proposer) != nil || len(message) == 0 {
		ev.Reason = "invalid proposal context"
		return ev
	}
	threshold := 0
	for _, t := range snapshot.Thresholds {
		if t.Tier == tier {
			threshold = t.Threshold
		}
	}
	keys := map[string]ed25519.PublicKey{}
	for _, s := range snapshot.Signers {
		keys[s.ID] = s.PublicKey
	}
	seen := map[string]bool{}
	for _, a := range approvals {
		k, ok := keys[a.SignerID]
		if !ok || seen[a.SignerID] || a.SignerID == proposer || len(a.Signature) != ed25519.SignatureSize || !ed25519.Verify(k, message, a.Signature) {
			ev.Reason = "invalid signer or signature"
			return ev
		}
		seen[a.SignerID] = true
		ev.Signers = append(ev.Signers, a.SignerID)
	}
	if len(ev.Signers) < threshold {
		ev.Reason = "insufficient quorum"
		return ev
	}
	sort.Strings(ev.Signers)
	ev.Accepted, ev.Reason = true, "accepted"
	return ev
}

func VerifyDomainApproval(snapshot KernelSnapshot, expectedKernel Digest, candidate DomainCandidate, context ProposalContext, approvals []DomainApproval) ApprovalEvidence {
	ev := ApprovalEvidence{Tier: candidate.Tier, CandidateDigest: candidate.Bundle.Digest(), Reason: "rejected"}
	kd, err := snapshot.Digest()
	if err != nil {
		ev.Reason = "malformed kernel"
		return ev
	}
	msg, err := DomainApprovalSigningBytes(candidate, kd, context.ProposerID)
	if err != nil {
		ev.Reason = "invalid proposal context"
		return ev
	}
	ev = VerifyKernelApprovalSignatures(snapshot, expectedKernel, candidate.Tier, context.ProposerID, msg, approvals)
	ev.CandidateDigest = candidate.Bundle.Digest()
	if !ev.Accepted && ev.Reason == "rejected" {
		ev.Reason = "invalid candidate"
	}
	if validateCandidate(candidate, snapshot) != nil {
		ev.Accepted = false
		ev.Reason = "invalid candidate"
	}
	return ev
}
func validateKernel(s KernelSnapshot) error {
	if s.SchemaVersion != KernelSnapshotSchema || s.EvolutionKernelConfig != nil || s.Version == 0 || len(s.Signers) == 0 {
		return ErrKernelApproval
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, x := range s.Signers {
		if validateID(x.ID) != nil || len(x.PublicKey) != ed25519.PublicKeySize || ids[x.ID] || keys[string(x.PublicKey)] {
			return ErrKernelApproval
		}
		ids[x.ID] = true
		keys[string(x.PublicKey)] = true
	}
	thresholds := map[GovernanceTier]bool{}
	for _, t := range s.Thresholds {
		if (t.Tier != TierG0 && t.Tier != TierG1) || thresholds[t.Tier] || t.Threshold < 1 || t.Threshold > len(s.Signers) {
			return ErrKernelApproval
		}
		thresholds[t.Tier] = true
	}
	if len(thresholds) != 2 {
		return ErrKernelApproval
	}
	caps := map[string]bool{}
	for _, c := range s.Capabilities {
		if !capabilityIDPattern.MatchString(c) || caps[c] {
			return ErrKernelApproval
		}
		caps[c] = true
	}
	if len(caps) == 0 {
		return ErrKernelApproval
	}
	issuers := map[string]bool{}
	for _, i := range s.IssuerCeilings {
		if validateID(i.IssuerID) != nil || issuers[i.IssuerID] {
			return ErrKernelApproval
		}
		issuers[i.IssuerID] = true
		seen := map[string]bool{}
		for _, c := range i.Capabilities {
			if !caps[c] || seen[c] {
				return ErrKernelApproval
			}
			seen[c] = true
		}
	}
	return nil
}
func validateCandidate(c DomainCandidate, s KernelSnapshot) error {
	if c.Bundle.Validate() != nil || c.Bundle.SchemaVersion() != BundleSchemaVersion || validateID(c.IssuerID) != nil || validateID(c.ProposalID) != nil || validateID(c.Nonce) != nil {
		return ErrKernelApproval
	}
	var ceiling []string
	found := false
	for _, i := range s.IssuerCeilings {
		if i.IssuerID == c.IssuerID {
			ceiling = i.Capabilities
			found = true
		}
	}
	if !found {
		return ErrKernelApproval
	}
	allowed := map[string]bool{}
	for _, x := range ceiling {
		allowed[x] = true
	}
	seen := map[string]bool{}
	for _, x := range c.CapabilityIDs {
		if !capabilityIDPattern.MatchString(x) || seen[x] || !allowed[x] {
			return ErrKernelApproval
		}
		seen[x] = true
	}
	return nil
}
func validTier(t GovernanceTier) bool { return t == TierG0 || t == TierG1 }
