package domain

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	WorkerCredentialDomain canonical.Domain = "paddock.worker-credential-use"
	WorkerCredentialSchema                  = "paddock.worker-credential-use/1"
)

var ErrWorkerCredential = errors.New("worker credential authentication denied")

// CredentialIssuerContext is trusted Issuer state, not Worker input. Issuance
// context and persisted Credential state must match the current shared registry
// read under lock by SafetyGate; neither snapshot alone establishes freshness.
// CeilingDigest pins issuer configuration; it is not a grant of its capabilities.
type CredentialIssuerContext struct {
	IssuerID      string
	Revision      uint64
	CeilingDigest Digest
}

func ValidateCredentialIssuerID(id string) error {
	if validateID(id) != nil || !utf8.ValidString(id) || strings.IndexByte(id, 0) >= 0 {
		return ErrWorkerCredential
	}
	return nil
}

func (c CredentialIssuerContext) Validate() error {
	if ValidateCredentialIssuerID(c.IssuerID) != nil || c.Revision == 0 || c.CeilingDigest.Validate() != nil {
		return ErrWorkerCredential
	}
	return nil
}

// WorkerCredential authenticates one enrolled key and execution tuple. It has
// no Scope, capability, Trust, Root Grant, or Authority. TTL is M10-S05 work.
type WorkerCredential struct {
	ID          string
	Fingerprint WorkerKeyFingerprint
	Lease       AttemptLeaseBinding
	Audience    string
	Issuer      CredentialIssuerContext
	Revoked     bool
}

func ValidateWorkerCredentialID(id string) error {
	if !enrollmentHex(id) {
		return ErrWorkerCredential
	}
	return nil
}

func (c WorkerCredential) Validate() error {
	if ValidateWorkerCredentialID(c.ID) != nil || c.Fingerprint.Validate() != nil || c.Lease.Validate() != nil || ValidateEnrollmentWorkerID(c.Lease.WorkerID) != nil || validateID(c.Audience) != nil || !utf8.ValidString(c.Audience) || c.Issuer.Validate() != nil {
		return ErrWorkerCredential
	}
	for _, id := range []string{string(c.Lease.WorkOrderID), string(c.Lease.AttemptID), string(c.Lease.SessionID)} {
		if !utf8.ValidString(id) {
			return ErrWorkerCredential
		}
	}
	return nil
}

// CredentialRequest is supplied by the trusted action adapter from the actual
// command. RequestDigest is the existing M04-S02 canonical command digest.
// The Gate is authentication-only: identical proofs may be retried; mutations
// must still use the existing command Receipt, never a second nonce ledger.
type CredentialRequest struct {
	CommandID     string
	RequestDigest Digest
	Nonce         string
}

func (r CredentialRequest) Validate() error {
	if validateID(r.CommandID) != nil || !utf8.ValidString(r.CommandID) || r.RequestDigest.Validate() != nil || validateID(r.Nonce) != nil || !utf8.ValidString(r.Nonce) {
		return ErrWorkerCredential
	}
	return nil
}

// WorkerCredentialBinding is mandatory for every high-risk authorization.
// Only ID and signature are accepted from the Worker; all other signing inputs
// are reconstructed from locked state and the trusted action context.
type WorkerCredentialBinding struct {
	ID        string
	Signature []byte
}

func (b WorkerCredentialBinding) Validate() error {
	if ValidateWorkerCredentialID(b.ID) != nil || len(b.Signature) != ed25519.SignatureSize {
		return ErrWorkerCredential
	}
	return nil
}

// SigningBytes binds the current Grant and Scope too: a proof cannot be moved
// to another Root/policy/action even when the execution identity is unchanged.
func (c WorkerCredential) SigningBytes(scope ScopeID, grant Grant, request CredentialRequest) ([]byte, error) {
	if c.Validate() != nil || c.Revoked || scope.Validate() != nil || !utf8.ValidString(string(scope)) || grant.Root.Validate() != nil || !utf8.ValidString(string(grant.Root)) || grant.Policy.SafeBaseline || grant.Policy.Digest.Validate() != nil || request.Validate() != nil {
		return nil, ErrWorkerCredential
	}
	payload, err := json.Marshal(struct {
		CredentialID       string               `json:"credential_id"`
		Fingerprint        WorkerKeyFingerprint `json:"fingerprint"`
		WorkOrderID        WorkOrderID          `json:"work_order_id"`
		WorkerID           WorkerID             `json:"worker_id"`
		SessionID          SessionID            `json:"session_id"`
		AttemptID          AttemptID            `json:"attempt_id"`
		LeaseEpoch         string               `json:"lease_epoch"`
		IssuerID           string               `json:"issuer_id"`
		IssuerRevision     string               `json:"issuer_revision"`
		CeilingDigest      Digest               `json:"ceiling_digest"`
		Scope              ScopeID              `json:"scope_id"`
		Root               RootID               `json:"root_id"`
		PolicyDigest       Digest               `json:"policy_digest"`
		SafeBaseline       bool                 `json:"safe_baseline"`
		AuthorizationEpoch string               `json:"authorization_epoch"`
		SecurityEpoch      string               `json:"security_epoch"`
		RequestDigest      Digest               `json:"request_digest"`
	}{c.ID, c.Fingerprint, c.Lease.WorkOrderID, c.Lease.WorkerID, c.Lease.SessionID, c.Lease.AttemptID, strconv.FormatInt(int64(c.Lease.LeaseEpoch), 10), c.Issuer.IssuerID, strconv.FormatUint(c.Issuer.Revision, 10), c.Issuer.CeilingDigest, scope, grant.Root, grant.Policy.Digest, grant.Policy.SafeBaseline, strconv.FormatUint(uint64(grant.AuthorizationEpoch), 10), strconv.FormatUint(uint64(grant.SecurityEpoch), 10), request.RequestDigest})
	if err != nil {
		return nil, ErrWorkerCredential
	}
	return canonical.Envelope(canonical.NewJCSCodec(), WorkerCredentialDomain, canonical.Context{SchemaVersion: WorkerCredentialSchema, Audience: c.Audience, RequestID: request.CommandID, Nonce: request.Nonce}, payload)
}

func VerifyWorkerCredential(c WorkerCredential, key []byte, scope ScopeID, authorization HighRiskAuthorization, request CredentialRequest, audience string, issuer CredentialIssuerContext) error {
	if c.Validate() != nil || c.Revoked || authorization.Credential.Validate() != nil || c.ID != authorization.Credential.ID || c.Lease != authorization.Lease || c.Audience != audience || issuer.Validate() != nil || c.Issuer != issuer {
		return ErrWorkerCredential
	}
	fingerprint, err := FingerprintWorkerKey(key)
	if err != nil || fingerprint != c.Fingerprint {
		return ErrWorkerCredential
	}
	message, err := c.SigningBytes(scope, authorization.Grant, request)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), message, authorization.Credential.Signature) {
		return ErrWorkerCredential
	}
	return nil
}
