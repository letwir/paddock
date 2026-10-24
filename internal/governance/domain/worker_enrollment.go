package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	WorkerEnrollmentDomain   canonical.Domain = "paddock.worker-enrollment"
	WorkerEnrollmentSchema                    = "paddock.worker-enrollment/1"
	WorkerEnrollmentAudience                  = "paddock.coordinator"
	WorkerQuarantineTier                      = "Q0"
	WorkerQuarantined                         = "QUARANTINED"
)

var (
	ErrWorkerEnrollment      = errors.New("invalid worker enrollment")
	ErrWorkerEnrollmentProof = errors.New("invalid worker enrollment proof")
	ErrEnrollmentTicket      = errors.New("worker enrollment ticket unavailable")
	ErrWorkerAlreadyEnrolled = errors.New("worker public key already enrolled")
)

// WorkerKeyFingerprint is lowercase SHA-256 hex of the raw 32-byte Ed25519 key,
// not an identity, Scope membership, Trust evidence, or Authority.
type WorkerKeyFingerprint string

func (f WorkerKeyFingerprint) Validate() error {
	if !enrollmentHex(string(f)) {
		return ErrWorkerEnrollment
	}
	return nil
}

func FingerprintWorkerKey(publicKey []byte) (WorkerKeyFingerprint, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrWorkerEnrollmentProof
	}
	digest := sha256.Sum256(publicKey)
	return WorkerKeyFingerprint(hex.EncodeToString(digest[:])), nil
}

// EnrollmentChallenge is an immutable signing-input snapshot. Ticket lifetime
// and admission controls are intentionally deferred to M10-S05.
type EnrollmentChallenge struct {
	ID          string
	Nonce       string
	Fingerprint WorkerKeyFingerprint
	Schema      string
	Audience    string
}

func ValidateEnrollmentChallengeID(id string) error {
	if !enrollmentHex(id) {
		return ErrEnrollmentTicket
	}
	return nil
}

func (c EnrollmentChallenge) Validate() error {
	if !enrollmentHex(c.ID) || !enrollmentHex(c.Nonce) || c.Fingerprint.Validate() != nil ||
		c.Schema != WorkerEnrollmentSchema || c.Audience != WorkerEnrollmentAudience {
		return ErrWorkerEnrollment
	}
	return nil
}

func (c EnrollmentChallenge) SigningBytes(codec *canonical.JCSCodec) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(struct {
		Fingerprint WorkerKeyFingerprint `json:"fingerprint"`
	}{c.Fingerprint})
	if err != nil {
		return nil, fmt.Errorf("encode enrollment fingerprint: %w", err)
	}
	return canonical.Envelope(codec, WorkerEnrollmentDomain, canonical.Context{
		SchemaVersion: c.Schema, Audience: c.Audience, RequestID: c.ID, Nonce: c.Nonce,
	}, payload)
}

// VerifiedWorkerEnrollment can only be produced by successful PoP verification.
// Arrays and value snapshots prevent mutation of caller-owned key/signature bytes.
// This is an in-process guard, not a replacement for the trusted Coordinator/DB boundary.
type VerifiedWorkerEnrollment struct {
	challenge EnrollmentChallenge
	publicKey [ed25519.PublicKeySize]byte
	verified  bool
}

func VerifyWorkerEnrollment(codec *canonical.JCSCodec, challenge EnrollmentChallenge, publicKey, signature []byte) (VerifiedWorkerEnrollment, error) {
	fingerprint, err := FingerprintWorkerKey(publicKey)
	if err != nil || fingerprint != challenge.Fingerprint || len(signature) != ed25519.SignatureSize {
		return VerifiedWorkerEnrollment{}, ErrWorkerEnrollmentProof
	}
	message, err := challenge.SigningBytes(codec)
	if err != nil {
		return VerifiedWorkerEnrollment{}, fmt.Errorf("enrollment signing input: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return VerifiedWorkerEnrollment{}, ErrWorkerEnrollmentProof
	}
	var key [ed25519.PublicKeySize]byte
	copy(key[:], publicKey)
	return VerifiedWorkerEnrollment{challenge: challenge, publicKey: key, verified: true}, nil
}

func (v VerifiedWorkerEnrollment) Validate() error {
	if !v.verified || v.challenge.Validate() != nil {
		return ErrWorkerEnrollmentProof
	}
	return nil
}
func (v VerifiedWorkerEnrollment) Challenge() EnrollmentChallenge         { return v.challenge }
func (v VerifiedWorkerEnrollment) PublicKey() [ed25519.PublicKeySize]byte { return v.publicKey }

// QuarantinedWorker deliberately has no normal Scope, Trust promotion, or
// Authority fields. Enrollment authenticates key possession only.
type QuarantinedWorker struct {
	ID          WorkerID
	Fingerprint WorkerKeyFingerprint
	Tier        string
	State       string
}

func ValidateEnrollmentWorkerID(id WorkerID) error {
	if !strings.HasPrefix(string(id), "worker_") || !enrollmentHex(strings.TrimPrefix(string(id), "worker_")) {
		return ErrWorkerEnrollment
	}
	return nil
}
func (w QuarantinedWorker) Validate() error {
	if ValidateEnrollmentWorkerID(w.ID) != nil || w.Fingerprint.Validate() != nil || w.Tier != WorkerQuarantineTier || w.State != WorkerQuarantined {
		return ErrWorkerEnrollment
	}
	return nil
}

// 256-bit encoding widths are protocol/cryptographic shapes, not admission limits.
func enrollmentHex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
