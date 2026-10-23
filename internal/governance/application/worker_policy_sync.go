package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

// WorkerPolicyManifest is an observed policy identity, not an authorization.
// A Worker-supplied value is only a comparison hint; it is never authority.
type WorkerPolicyManifest struct {
	RootID                 domain.RootID
	PolicyDigest           domain.Digest
	RootAuthorizationEpoch domain.Epoch
	SecurityEpoch          domain.Epoch
}

func (m WorkerPolicyManifest) Validate() error {
	if err := m.RootID.Validate(); err != nil {
		return fmt.Errorf("policy manifest root: %w", err)
	}
	if err := m.PolicyDigest.Validate(); err != nil {
		return fmt.Errorf("policy manifest digest: %w", err)
	}
	if m.RootAuthorizationEpoch == 0 || m.SecurityEpoch == 0 {
		return errors.New("policy manifest requires nonzero authorization and security epochs")
	}
	return nil
}

// WorkerPolicySnapshot is a trusted source's consistent, current read of a
// Root's effective manifest and immutable signed bundle. ObservedAt is trusted
// source time (not Worker time), used to check signing-key validity.
type WorkerPolicySnapshot struct {
	Manifest   WorkerPolicyManifest
	Bundle     domain.CanonicalBundle
	KeyID      string
	Signature  []byte
	ObservedAt time.Time
}

// WorkerPolicySource is a read-only Coordinator-side trust boundary. A source
// reads fresh authoritative state for the requested Root, binding the manifest,
// bundle, signing metadata, and time in one consistent observation. Unavailable
// authority, Safe Baseline (which has no bundle), or an inconsistent read returns
// an error; cached or Worker-supplied claims are not a source implementation.
// No concrete storage or transport implementation is supplied here.
type WorkerPolicySource interface {
	ReadCurrentWorkerPolicy(context.Context, domain.RootID) (WorkerPolicySnapshot, error)
}

type WorkerPolicyStatus string

const (
	WorkerPolicyUnknown WorkerPolicyStatus = ""
	WorkerPolicyCurrent WorkerPolicyStatus = "CURRENT"
	WorkerPolicyStale   WorkerPolicyStatus = "STALE"
)

// WorkerPolicySyncResult holds only a verified in-memory pull result. Its zero
// value is unsynchronized. ObservedStatus describes the input manifest BEFORE
// synchronization; Manifest and Bundle describe the verified replacement.
// This is neither an installation acknowledgement nor durable Worker state.
type WorkerPolicySyncResult struct {
	observedStatus WorkerPolicyStatus
	manifest       WorkerPolicyManifest
	bundle         domain.CanonicalBundle
}

func (r WorkerPolicySyncResult) ObservedStatus() WorkerPolicyStatus { return r.observedStatus }
func (r WorkerPolicySyncResult) Manifest() WorkerPolicyManifest     { return r.manifest }
func (r WorkerPolicySyncResult) Bundle() domain.CanonicalBundle     { return r.bundle }
func (r WorkerPolicySyncResult) Synchronized() bool {
	return r.observedStatus == WorkerPolicyCurrent || r.observedStatus == WorkerPolicyStale
}

type WorkerPolicySyncService struct {
	source WorkerPolicySource
	keys   BundleKeyResolver
}

func NewWorkerPolicySyncService(source WorkerPolicySource, keys BundleKeyResolver) *WorkerPolicySyncService {
	return &WorkerPolicySyncService{source: source, keys: keys}
}

// Sync compares the observed tuple against an authoritative pull and returns a
// synchronized snapshot only after verifying the bundle's signature, digest,
// and Root/epoch binding. Even an equal tuple needs a verified bundle: a Worker
// claim alone cannot establish possession or integrity. All failures return the
// zero result, without changing the caller's manifest or retaining prior state.
//
// Synchronization is distribution, not authorization, and is current only as of
// the source observation. Conditional local computation still requires the
// existing OfflineGrant/OfflineSession. Online/high-risk effects still require
// the existing fresh DB-backed authorizer; this result cannot bypass that gate.
func (s *WorkerPolicySyncService) Sync(ctx context.Context, observed WorkerPolicyManifest) (WorkerPolicySyncResult, error) {
	if s == nil || !portPresent(s.source) || !portPresent(s.keys) {
		return WorkerPolicySyncResult{}, errors.New("worker policy sync service is not initialized")
	}
	if ctx == nil {
		return WorkerPolicySyncResult{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return WorkerPolicySyncResult{}, err
	}
	if err := observed.Validate(); err != nil {
		return WorkerPolicySyncResult{}, err
	}

	snapshot, err := s.source.ReadCurrentWorkerPolicy(ctx, observed.RootID)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return WorkerPolicySyncResult{}, ctxErr
	}
	if err != nil {
		return WorkerPolicySyncResult{}, fmt.Errorf("read current worker policy: %w", err)
	}
	if err := snapshot.Manifest.Validate(); err != nil {
		return WorkerPolicySyncResult{}, fmt.Errorf("current worker policy: %w", err)
	}
	if snapshot.Manifest.RootID != observed.RootID {
		return WorkerPolicySyncResult{}, errors.New("current worker policy root mismatch")
	}
	if snapshot.ObservedAt.IsZero() || snapshot.KeyID == "" || strings.TrimSpace(snapshot.KeyID) != snapshot.KeyID {
		return WorkerPolicySyncResult{}, errors.New("invalid current worker policy verification metadata")
	}
	if err := snapshot.Bundle.Validate(); err != nil {
		return WorkerPolicySyncResult{}, fmt.Errorf("current worker policy bundle: %w", err)
	}
	if snapshot.Bundle.SchemaVersion() != domain.BundleSchemaVersion {
		return WorkerPolicySyncResult{}, errors.New("unsupported current worker policy bundle schema")
	}
	if snapshot.Bundle.Digest() != snapshot.Manifest.PolicyDigest {
		return WorkerPolicySyncResult{}, errors.New("current worker policy bundle digest mismatch")
	}
	// Take ownership of mutable signature bytes before crossing another port.
	signature := append([]byte(nil), snapshot.Signature...)
	key, err := s.keys.ResolveBundleKey(ctx, snapshot.KeyID)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return WorkerPolicySyncResult{}, ctxErr
	}
	if err != nil {
		return WorkerPolicySyncResult{}, fmt.Errorf("resolve worker policy bundle key: %w", err)
	}
	if key.KeyID != snapshot.KeyID {
		return WorkerPolicySyncResult{}, errors.New("worker policy bundle key ID mismatch")
	}
	digest, err := domain.VerifyCanonicalBundle(snapshot.Bundle, domain.BundleVerificationKey{
		KeyID: key.KeyID, PublicKey: key.PublicKey, ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil,
	}, signature, snapshot.ObservedAt)
	if err != nil {
		return WorkerPolicySyncResult{}, fmt.Errorf("verify current worker policy bundle: %w", err)
	}
	if digest != snapshot.Manifest.PolicyDigest {
		return WorkerPolicySyncResult{}, errors.New("verified worker policy bundle digest mismatch")
	}
	if err := ctx.Err(); err != nil {
		return WorkerPolicySyncResult{}, err
	}

	status := WorkerPolicyStale
	if observed == snapshot.Manifest {
		status = WorkerPolicyCurrent
	}
	return WorkerPolicySyncResult{observedStatus: status, manifest: snapshot.Manifest, bundle: snapshot.Bundle}, nil
}
