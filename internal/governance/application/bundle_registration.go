package application

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// BundleSigningKey contains read-only trusted verification metadata external to
// the immutable bundle payload.
type BundleSigningKey struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	ValidFrom  time.Time
	ValidUntil time.Time
}

// BundleKeyResolver is an injected, read-only trust boundary. Implementations
// must not fetch/update keys as a side effect of resolution.
type BundleKeyResolver interface {
	ResolveBundleKey(ctx context.Context, keyID string) (BundleSigningKey, error)
}

type BundleRegistrationService struct {
	transactor port.Transactor
	keys       BundleKeyResolver
}

func NewBundleRegistrationService(transactor port.Transactor, keys BundleKeyResolver) *BundleRegistrationService {
	return &BundleRegistrationService{transactor: transactor, keys: keys}
}

// Register verifies the bundle and signature against trusted key metadata and
// transaction DatabaseTime before performing exactly one persistence call.
func (s *BundleRegistrationService) Register(ctx context.Context, bundle domain.CanonicalBundle, keyID string, signature []byte) (domain.Digest, error) {
	if s == nil || s.transactor == nil || s.keys == nil {
		return "", errors.New("bundle registration service is not initialized")
	}
	if ctx == nil {
		return "", errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if keyID == "" || strings.TrimSpace(keyID) != keyID {
		return "", errors.New("invalid bundle signer key ID")
	}
	var digest domain.Digest
	err := s.transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		var err error
		digest, err = s.RegisterWithin(ctx, tx, bundle, keyID, signature)
		return err
	})
	if err != nil {
		return "", err
	}
	return digest, nil
}

// RegisterWithin verifies and persists the bundle using the caller's transaction.
func (s *BundleRegistrationService) RegisterWithin(ctx context.Context, tx port.GovernanceTx, bundle domain.CanonicalBundle, keyID string, signature []byte) (domain.Digest, error) {
	if s == nil || s.keys == nil {
		return "", errors.New("bundle registration service is not initialized")
	}
	if ctx == nil {
		return "", errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if tx == nil {
		return "", errors.New("nil governance transaction")
	}
	if keyID == "" || strings.TrimSpace(keyID) != keyID {
		return "", errors.New("invalid bundle signer key ID")
	}
	if err := bundle.Validate(); err != nil {
		return "", fmt.Errorf("validate bundle: %w", err)
	}
	if bundle.SchemaVersion() != domain.BundleSchemaVersion {
		return "", fmt.Errorf("unsupported bundle schema version %q", bundle.SchemaVersion())
	}
	key, err := s.keys.ResolveBundleKey(ctx, keyID)
	if err != nil {
		return "", fmt.Errorf("resolve bundle signing key: %w", err)
	}
	now, err := tx.DatabaseTime(ctx)
	if err != nil {
		return "", fmt.Errorf("read transaction database time: %w", err)
	}
	verifiedDigest, err := domain.VerifyCanonicalBundle(bundle, domain.BundleVerificationKey{
		KeyID: key.KeyID, PublicKey: key.PublicKey, ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil,
	}, signature, now)
	if err != nil {
		return "", err
	}
	if key.KeyID != keyID {
		return "", errors.New("resolved bundle signing key ID mismatch")
	}
	if err := tx.InsertPolicyBundle(ctx, bundle, keyID, append([]byte(nil), signature...)); err != nil {
		return "", fmt.Errorf("insert verified policy bundle: %w", err)
	}
	return verifiedDigest, nil
}
