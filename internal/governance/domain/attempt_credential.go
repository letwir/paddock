package domain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	AttemptCredentialSchema = "paddock.attempt-credential/1"
	AttemptCredentialDomain = "paddock.attempt-credential"
)

var (
	ErrAttemptCredentialInvalid = errors.New("invalid attempt credential")
	ErrAttemptCredentialExpired = errors.New("attempt credential expired or not yet valid")
	ErrAttemptCredentialRevoked = errors.New("attempt credential revoked")
	ErrAttemptIssuerCeiling     = errors.New("attempt credential exceeds issuer ceiling")
)

type CredentialIssuerCeiling struct {
	IssuerID            string
	AllowedCapabilities []string
	AllowedAudiences    []string
	MaxTTL              time.Duration
}

// TrustedKeyBinding binds an Ed25519 public key ID to its sole authorized IssuerID.
type TrustedKeyBinding struct {
	IssuerID  string
	PublicKey ed25519.PublicKey
}

type AttemptCredential struct {
	SchemaVersion string    `json:"schema_version"`
	CredentialID  string    `json:"credential_id"`
	IssuerID      string    `json:"issuer_id"`
	KeyID         string    `json:"key_id"`
	WorkerID      string    `json:"worker_id"`
	AttemptID     string    `json:"attempt_id"`
	LeaseEpoch    Epoch     `json:"lease_epoch"`
	Audience      string    `json:"audience"`
	Capabilities  []string  `json:"capabilities"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	SignatureHex  string    `json:"signature_hex,omitempty"`
}

type AttemptCredentialVerifyInput struct {
	ExpectedWorkerID   string
	ExpectedAttemptID  string
	ExpectedLeaseEpoch Epoch
	ExpectedAudience   string
	RequiredCapability string
	TrustedKeys        map[string]TrustedKeyBinding
	IssuerCeilings     map[string]CredentialIssuerCeiling
	RevokedCredentials map[string]bool
	RevokedKeys        map[string]bool
	RevokedIssuers     map[string]bool
	Now                time.Time
}

func canonicalCredentialSigningBytes(c AttemptCredential) ([]byte, error) {
	if c.SchemaVersion != AttemptCredentialSchema ||
		validateID(c.CredentialID) != nil ||
		validateID(c.IssuerID) != nil ||
		validateID(c.KeyID) != nil ||
		validateID(c.WorkerID) != nil ||
		validateID(c.AttemptID) != nil ||
		c.LeaseEpoch == 0 ||
		c.Audience == "" ||
		len(c.Capabilities) == 0 ||
		c.IssuedAt.IsZero() ||
		!c.ExpiresAt.After(c.IssuedAt) {
		return nil, fmt.Errorf("%w: incomplete or invalid credential fields", ErrAttemptCredentialInvalid)
	}
	caps := append([]string(nil), c.Capabilities...)
	sort.Strings(caps)
	for i, capName := range caps {
		if !capabilityIDPattern.MatchString(capName) || (i > 0 && caps[i-1] == capName) {
			return nil, fmt.Errorf("%w: invalid or duplicate capability %q", ErrAttemptCredentialInvalid, capName)
		}
	}
	payload := struct {
		Domain        string   `json:"domain"`
		SchemaVersion string   `json:"schema_version"`
		CredentialID  string   `json:"credential_id"`
		IssuerID      string   `json:"issuer_id"`
		KeyID         string   `json:"key_id"`
		WorkerID      string   `json:"worker_id"`
		AttemptID     string   `json:"attempt_id"`
		LeaseEpoch    Epoch    `json:"lease_epoch"`
		Audience      string   `json:"audience"`
		Capabilities  []string `json:"capabilities"`
		IssuedAt      string   `json:"issued_at"`
		ExpiresAt     string   `json:"expires_at"`
	}{
		Domain:        AttemptCredentialDomain,
		SchemaVersion: c.SchemaVersion,
		CredentialID:  c.CredentialID,
		IssuerID:      c.IssuerID,
		KeyID:         c.KeyID,
		WorkerID:      c.WorkerID,
		AttemptID:     c.AttemptID,
		LeaseEpoch:    c.LeaseEpoch,
		Audience:      c.Audience,
		Capabilities:  caps,
		IssuedAt:      c.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:     c.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	codec := canonical.NewJCSCodec()
	return codec.CanonicalizeJSON(raw)
}

func checkIssuerCeiling(c AttemptCredential, ceiling CredentialIssuerCeiling) error {
	if validateID(ceiling.IssuerID) != nil || ceiling.IssuerID != c.IssuerID {
		return fmt.Errorf("%w: issuer mismatch", ErrAttemptIssuerCeiling)
	}
	if ceiling.MaxTTL <= 0 || c.ExpiresAt.Sub(c.IssuedAt) > ceiling.MaxTTL {
		return fmt.Errorf("%w: ttl exceeds issuer max_ttl", ErrAttemptIssuerCeiling)
	}
	allowedAud := make(map[string]bool, len(ceiling.AllowedAudiences))
	for _, a := range ceiling.AllowedAudiences {
		allowedAud[a] = true
	}
	if !allowedAud[c.Audience] {
		return fmt.Errorf("%w: audience %q outside issuer ceiling", ErrAttemptIssuerCeiling, c.Audience)
	}
	allowedCap := make(map[string]bool, len(ceiling.AllowedCapabilities))
	for _, capName := range ceiling.AllowedCapabilities {
		allowedCap[capName] = true
	}
	for _, capName := range c.Capabilities {
		if !allowedCap[capName] {
			return fmt.Errorf("%w: capability %q exceeds issuer ceiling", ErrAttemptIssuerCeiling, capName)
		}
	}
	return nil
}

// IssueAttemptCredential validates CredentialIssuerCeiling bounds and signs an AttemptCredential.
func IssueAttemptCredential(c AttemptCredential, ceiling CredentialIssuerCeiling, signer ed25519.PrivateKey) (AttemptCredential, error) {
	if c.SchemaVersion == "" {
		c.SchemaVersion = AttemptCredentialSchema
	}
	if len(signer) != ed25519.PrivateKeySize {
		return AttemptCredential{}, fmt.Errorf("%w: invalid signing key", ErrAttemptCredentialInvalid)
	}
	if err := checkIssuerCeiling(c, ceiling); err != nil {
		return AttemptCredential{}, err
	}
	signingBytes, err := canonicalCredentialSigningBytes(c)
	if err != nil {
		return AttemptCredential{}, err
	}
	sig := ed25519.Sign(signer, signingBytes)
	c.SignatureHex = hex.EncodeToString(sig)
	return c, nil
}

// VerifyAttemptCredential enforces revocation, KeyID->IssuerID binding, expiry,
// exact Worker/Attempt/Epoch/Audience bindings, CredentialIssuerCeiling subset
// limits, and Ed25519 cryptographic signature.
func VerifyAttemptCredential(c AttemptCredential, in AttemptCredentialVerifyInput) error {
	if in.Now.IsZero() {
		return fmt.Errorf("%w: evaluation time required", ErrAttemptCredentialInvalid)
	}
	if in.RevokedCredentials[c.CredentialID] || in.RevokedKeys[c.KeyID] || in.RevokedIssuers[c.IssuerID] {
		return fmt.Errorf("%w: credential, key, or issuer revoked", ErrAttemptCredentialRevoked)
	}
	signingBytes, err := canonicalCredentialSigningBytes(c)
	if err != nil {
		return err
	}
	keyBinding, ok := in.TrustedKeys[c.KeyID]
	if !ok || len(keyBinding.PublicKey) != ed25519.PublicKeySize || validateID(keyBinding.IssuerID) != nil {
		return fmt.Errorf("%w: untrusted key_id %q", ErrAttemptCredentialInvalid, c.KeyID)
	}
	if keyBinding.IssuerID != c.IssuerID {
		return fmt.Errorf("%w: key_id %q is bound to issuer %q, not %q", ErrAttemptIssuerCeiling, c.KeyID, keyBinding.IssuerID, c.IssuerID)
	}
	sig, err := hex.DecodeString(c.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(keyBinding.PublicKey, signingBytes, sig) {
		return fmt.Errorf("%w: invalid signature", ErrAttemptCredentialInvalid)
	}
	ceiling, ok := in.IssuerCeilings[c.IssuerID]
	if !ok {
		return fmt.Errorf("%w: unknown issuer %q", ErrAttemptIssuerCeiling, c.IssuerID)
	}
	if err := checkIssuerCeiling(c, ceiling); err != nil {
		return err
	}
	if in.Now.Before(c.IssuedAt) || !in.Now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: now=%s outside [%s, %s)", ErrAttemptCredentialExpired, in.Now.UTC(), c.IssuedAt.UTC(), c.ExpiresAt.UTC())
	}
	if c.WorkerID != in.ExpectedWorkerID ||
		c.AttemptID != in.ExpectedAttemptID ||
		c.LeaseEpoch != in.ExpectedLeaseEpoch ||
		c.Audience != in.ExpectedAudience {
		return fmt.Errorf("%w: binding mismatch", ErrAttemptCredentialInvalid)
	}
	if in.RequiredCapability != "" {
		found := false
		for _, capName := range c.Capabilities {
			if capName == in.RequiredCapability {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: missing required capability %q", ErrAttemptCredentialInvalid, in.RequiredCapability)
		}
	}
	return nil
}
