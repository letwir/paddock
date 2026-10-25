package domain

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/letwir/paddock/internal/canonical"
)

const ActivationCertificateSchema = "paddock.activation-certificate/1"

// ActivationContext must be supplied by the trusted caller from current state,
// not reconstructed from the certificate. Revision zero is a valid initial state.
type ActivationContext struct {
	Scope               ScopeID
	BaseActivationEpoch Epoch
	PolicyDigest        Digest
	KernelDigest        Digest
	IssuerID            string
	IssuerRevision      uint64
}

// ActivationCertificate binds G1 approvals to one exact activation context.
type ActivationCertificate struct {
	ActivationContext
	Approvals []DomainApproval
}

func (c ActivationContext) validate() error {
	if c.Scope.Validate() != nil || !utf8.ValidString(string(c.Scope)) ||
		c.PolicyDigest.Validate() != nil || c.KernelDigest.Validate() != nil ||
		validateID(c.IssuerID) != nil || !utf8.ValidString(c.IssuerID) {
		return fmt.Errorf("%w: malformed activation context", ErrKernelApproval)
	}
	return nil
}

// SigningBytes excludes approvals and uses a certificate-specific schema in the
// approval envelope. Epoch and revision are decimal strings so JCS's IEEE-754
// number limits cannot truncate or reject valid uint64 values.
func (c ActivationCertificate) SigningBytes() ([]byte, error) {
	if err := c.ActivationContext.validate(); err != nil {
		return nil, err
	}
	epoch := strconv.FormatUint(uint64(c.BaseActivationEpoch), 10)
	revision := strconv.FormatUint(c.IssuerRevision, 10)
	payload := struct {
		Scope               ScopeID `json:"scope"`
		BaseActivationEpoch string  `json:"base_activation_epoch"`
		PolicyDigest        Digest  `json:"policy_digest"`
		KernelDigest        Digest  `json:"kernel_digest"`
		IssuerID            string  `json:"issuer_id"`
		IssuerRevision      string  `json:"issuer_revision"`
	}{c.Scope, epoch, c.PolicyDigest, c.KernelDigest, c.IssuerID, revision}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode activation certificate: %v", ErrKernelApproval, err)
	}
	// Context equality is the replay boundary here, not a one-time nonce store.
	return canonical.Envelope(canonical.NewJCSCodec(), canonical.DomainApproval, canonical.Context{
		SchemaVersion: ActivationCertificateSchema,
		Audience:      "governance",
		RequestID:     string(c.Scope),
		Nonce:         epoch + ":" + revision,
	}, b)
}

// VerifyActivationCertificate checks current-context equality and the pinned
// kernel before verifying every supplied signature, even after quorum is met.
// It neither reads current state nor makes activation atomic: callers must bind
// this check to their state transition and recheck if trusted state changes.
func VerifyActivationCertificate(snapshot KernelSnapshot, current ActivationContext, c ActivationCertificate) ApprovalEvidence {
	ev := ApprovalEvidence{Tier: TierG1, CandidateDigest: c.PolicyDigest, Reason: "rejected"}
	if err := current.validate(); err != nil {
		ev.Reason = "invalid current activation context"
		return ev
	}
	message, err := c.SigningBytes()
	if err != nil {
		ev.Reason = "invalid activation certificate"
		return ev
	}
	if c.ActivationContext != current {
		ev.Reason = "activation context mismatch"
		return ev
	}
	kd, err := snapshot.Digest()
	if err != nil {
		ev.Reason = "malformed kernel"
		return ev
	}
	ev.KernelDigest = kd
	if kd != current.KernelDigest {
		ev.Reason = "kernel digest mismatch"
		return ev
	}
	if err := validateKernel(snapshot); err != nil {
		ev.Reason = "malformed kernel"
		return ev
	}
	threshold := 0
	for _, t := range snapshot.Thresholds {
		if t.Tier == TierG1 {
			threshold = t.Threshold
		}
	}
	keys := make(map[string]ed25519.PublicKey, len(snapshot.Signers))
	for _, signer := range snapshot.Signers {
		keys[signer.ID] = signer.PublicKey
	}
	seen := make(map[string]bool, len(c.Approvals))
	for _, approval := range c.Approvals {
		key, ok := keys[approval.SignerID]
		if !ok || seen[approval.SignerID] || len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(key, message, approval.Signature) {
			ev.Reason = "invalid signer or signature"
			return ev
		}
		seen[approval.SignerID] = true
		ev.Signers = append(ev.Signers, approval.SignerID)
	}
	if len(ev.Signers) < threshold {
		ev.Reason = "insufficient quorum"
		return ev
	}
	sort.Strings(ev.Signers)
	ev.Accepted, ev.Reason = true, "accepted"
	return ev
}
