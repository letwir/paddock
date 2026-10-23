package domain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidBundleSignature = errors.New("invalid bundle signature")

const BundleSchemaVersion = "paddock.bundle/1"

// BundleVerificationKey is trusted resolver metadata; it is deliberately not
// part of CanonicalBundle's signed payload.
type BundleVerificationKey struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
}

// VerifyCanonicalBundle revalidates the JCS identity and verifies the exact
// domain-separated, schema-bound signing envelope using the trusted key metadata.
func VerifyCanonicalBundle(bundle CanonicalBundle, key BundleVerificationKey, signature []byte, now time.Time) (Digest, error) {
	if err := bundle.Validate(); err != nil {
		return "", fmt.Errorf("verify bundle: %w", err)
	}
	if bundle.SchemaVersion() != BundleSchemaVersion {
		return "", fmt.Errorf("verify bundle: unsupported schema version %q", bundle.SchemaVersion())
	}
	if key.KeyID == "" || strings.TrimSpace(key.KeyID) != key.KeyID || len(key.PublicKey) != ed25519.PublicKeySize || key.ValidFrom.IsZero() || key.ValidUntil.IsZero() || !key.ValidFrom.Before(key.ValidUntil) {
		return "", errors.New("verify bundle: malformed trusted key metadata")
	}
	if now.Before(key.ValidFrom) || !now.Before(key.ValidUntil) {
		return "", errors.New("verify bundle: signing key outside validity interval")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, bundle.SigningBytes(), signature) {
		return "", ErrInvalidBundleSignature
	}
	return bundle.Digest(), nil
}
