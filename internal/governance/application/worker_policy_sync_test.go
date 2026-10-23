package application

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type workerPolicySourceFake struct {
	snapshot WorkerPolicySnapshot
	err      error
	calls    int
	root     domain.RootID
	onRead   func()
}

func (f *workerPolicySourceFake) ReadCurrentWorkerPolicy(_ context.Context, root domain.RootID) (WorkerPolicySnapshot, error) {
	f.calls++
	f.root = root
	if f.onRead != nil {
		f.onRead()
	}
	return f.snapshot, f.err
}

type workerPolicyKeysFake struct {
	key       BundleSigningKey
	err       error
	calls     int
	keyID     string
	onResolve func()
}

func (f *workerPolicyKeysFake) ResolveBundleKey(_ context.Context, keyID string) (BundleSigningKey, error) {
	f.calls++
	f.keyID = keyID
	if f.onResolve != nil {
		f.onResolve()
	}
	return f.key, f.err
}

func workerPolicySyncFixture(t *testing.T) (*workerPolicySourceFake, *workerPolicyKeysFake) {
	t.Helper()
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"deny-dangerous"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic local test-only key; no credential access or external service.
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	source := &workerPolicySourceFake{snapshot: WorkerPolicySnapshot{
		Manifest: WorkerPolicyManifest{
			RootID: "root-a", PolicyDigest: bundle.Digest(), RootAuthorizationEpoch: 42, SecurityEpoch: 4,
		},
		Bundle: bundle, KeyID: "bundle-key", Signature: ed25519.Sign(private, bundle.SigningBytes()), ObservedAt: now,
	}}
	keys := &workerPolicyKeysFake{key: BundleSigningKey{
		KeyID: "bundle-key", PublicKey: private.Public().(ed25519.PublicKey),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}}
	return source, keys
}

func TestWorkerPolicySyncEqualAndStaleManifests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*WorkerPolicyManifest)
		status WorkerPolicyStatus
	}{
		{"equal", func(*WorkerPolicyManifest) {}, WorkerPolicyCurrent},
		{"old digest", func(m *WorkerPolicyManifest) { m.PolicyDigest = domain.Digest(strings.Repeat("a", 64)) }, WorkerPolicyStale},
		{"old root epoch", func(m *WorkerPolicyManifest) { m.RootAuthorizationEpoch-- }, WorkerPolicyStale},
		{"old security epoch", func(m *WorkerPolicyManifest) { m.SecurityEpoch-- }, WorkerPolicyStale},
		{"worker claims future root epoch", func(m *WorkerPolicyManifest) { m.RootAuthorizationEpoch++ }, WorkerPolicyStale},
		{"worker claims future security epoch", func(m *WorkerPolicyManifest) { m.SecurityEpoch++ }, WorkerPolicyStale},
		{"all changed", func(m *WorkerPolicyManifest) {
			m.PolicyDigest = domain.Digest(strings.Repeat("b", 64))
			m.RootAuthorizationEpoch--
			m.SecurityEpoch--
		}, WorkerPolicyStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, keys := workerPolicySyncFixture(t)
			observed := source.snapshot.Manifest
			tc.change(&observed)
			before := observed
			service := NewWorkerPolicySyncService(source, keys)
			result, err := service.Sync(context.Background(), observed)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Synchronized() || result.ObservedStatus() != tc.status || result.Manifest() != source.snapshot.Manifest {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Bundle().Digest() != source.snapshot.Bundle.Digest() || result.Bundle().Validate() != nil {
				t.Fatal("result did not contain the verified immutable bundle")
			}
			if observed != before || source.calls != 1 || source.root != observed.RootID || keys.calls != 1 || keys.keyID != source.snapshot.KeyID {
				t.Fatal("input changed, or comparison bypassed the authoritative source/key resolver")
			}
			// The result is a value snapshot; callers cannot mutate its manifest or
			// CanonicalBundle through returned values or byte-slice accessors.
			manifest := result.Manifest()
			manifest.RootAuthorizationEpoch++
			bytes := result.Bundle().CanonicalBytes()
			bytes[0] = '!'
			if result.Manifest() != source.snapshot.Manifest || result.Bundle().Validate() != nil {
				t.Fatal("result leaked mutable manifest/bundle state")
			}
			// Applying the returned snapshot makes the next comparison current,
			// but still requires another fresh read and signature verification.
			next, err := service.Sync(context.Background(), result.Manifest())
			if err != nil || !next.Synchronized() || next.ObservedStatus() != WorkerPolicyCurrent || source.calls != 2 || keys.calls != 2 {
				t.Fatalf("repeated sync = %+v, %v", next, err)
			}
		})
	}
}

func TestWorkerPolicySyncRejectsInvalidObservedManifest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*WorkerPolicyManifest)
	}{
		{"empty root", func(m *WorkerPolicyManifest) { m.RootID = "" }},
		{"padded root", func(m *WorkerPolicyManifest) { m.RootID = " root-a" }},
		{"unicode padded root", func(m *WorkerPolicyManifest) { m.RootID = "root-a\u00a0" }},
		{"empty digest", func(m *WorkerPolicyManifest) { m.PolicyDigest = "" }},
		{"short digest", func(m *WorkerPolicyManifest) { m.PolicyDigest = "ab" }},
		{"uppercase digest", func(m *WorkerPolicyManifest) { m.PolicyDigest = domain.Digest(strings.Repeat("A", 64)) }},
		{"nonhex digest", func(m *WorkerPolicyManifest) { m.PolicyDigest = domain.Digest(strings.Repeat("z", 64)) }},
		{"zero root epoch", func(m *WorkerPolicyManifest) { m.RootAuthorizationEpoch = 0 }},
		{"zero security epoch", func(m *WorkerPolicyManifest) { m.SecurityEpoch = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, keys := workerPolicySyncFixture(t)
			observed := source.snapshot.Manifest
			tc.change(&observed)
			before := observed
			result, err := NewWorkerPolicySyncService(source, keys).Sync(context.Background(), observed)
			assertWorkerPolicySyncFailure(t, result, err)
			if observed != before || source.calls != 0 || keys.calls != 0 {
				t.Fatal("invalid input changed state or reached a source")
			}
		})
	}
}

func TestWorkerPolicySyncFailsClosedForSourceAndBundleFailures(t *testing.T) {
	unavailable := errors.New("source unavailable")
	keyUnavailable := errors.New("key unavailable")
	for _, tc := range []struct {
		name   string
		change func(*workerPolicySourceFake, *workerPolicyKeysFake)
		cause  error
	}{
		{"unavailable source", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.err = unavailable }, unavailable},
		{"canceled source error", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.err = context.Canceled }, context.Canceled},
		{"deadline source error", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.err = context.DeadlineExceeded }, context.DeadlineExceeded},
		{"source root mismatch", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Manifest.RootID = "root-b" }, nil},
		{"empty source root", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Manifest.RootID = "" }, nil},
		{"padded source root", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Manifest.RootID = "root-a " }, nil},
		{"malformed source digest", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Manifest.PolicyDigest = "invalid" }, nil},
		{"bundle digest mismatch", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) {
			s.snapshot.Manifest.PolicyDigest = domain.Digest(strings.Repeat("a", 64))
		}, nil},
		{"zero source root epoch", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) {
			s.snapshot.Manifest.RootAuthorizationEpoch = 0
		}, nil},
		{"zero source security epoch", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Manifest.SecurityEpoch = 0 }, nil},
		{"zero source time", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.ObservedAt = time.Time{} }, nil},
		{"empty source key ID", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.KeyID = "" }, nil},
		{"padded source key ID", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.KeyID = " bundle-key" }, nil},
		{"invalid canonical bundle", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Bundle = domain.CanonicalBundle{} }, nil},
		{"unsupported bundle schema", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) {
			bundle, err := domain.NewCanonicalBundle("paddock.bundle/unsupported", s.snapshot.Bundle.CanonicalBytes())
			if err != nil {
				t.Fatal(err)
			}
			s.snapshot.Bundle = bundle
			private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			s.snapshot.Signature = ed25519.Sign(private, bundle.SigningBytes())
		}, nil},
		{"different valid signed bundle", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) {
			bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"different"}`))
			if err != nil {
				t.Fatal(err)
			}
			s.snapshot.Bundle = bundle
			private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			s.snapshot.Signature = ed25519.Sign(private, bundle.SigningBytes())
		}, nil},
		{"missing signature", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Signature = nil }, domain.ErrInvalidBundleSignature},
		{"short signature", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Signature = []byte("unsupported") }, domain.ErrInvalidBundleSignature},
		{"tampered signature", func(s *workerPolicySourceFake, _ *workerPolicyKeysFake) { s.snapshot.Signature[0] ^= 1 }, domain.ErrInvalidBundleSignature},
		{"key resolver unavailable", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) { k.err = keyUnavailable }, keyUnavailable},
		{"resolved key ID mismatch", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) { k.key.KeyID = "other-key" }, nil},
		{"malformed public key", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) { k.key.PublicKey = []byte("bad") }, nil},
		{"wrong public key", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) {
			seed := make([]byte, ed25519.SeedSize)
			seed[0] = 1
			k.key.PublicKey = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		}, domain.ErrInvalidBundleSignature},
		{"missing key validity", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) { k.key.ValidFrom = time.Time{} }, nil},
		{"invalid key interval", func(_ *workerPolicySourceFake, k *workerPolicyKeysFake) { k.key.ValidUntil = k.key.ValidFrom }, nil},
		{"key not yet valid", func(s *workerPolicySourceFake, k *workerPolicyKeysFake) {
			s.snapshot.ObservedAt = k.key.ValidFrom.Add(-time.Nanosecond)
		}, nil},
		{"expired key", func(s *workerPolicySourceFake, k *workerPolicyKeysFake) { s.snapshot.ObservedAt = k.key.ValidUntil }, nil},
	} {
		// Equal observations never bypass validation; stale observations are not
		// upgraded on any failure either, even after an earlier successful sync.
		for _, stale := range []bool{false, true} {
			name := tc.name + "/equal"
			if stale {
				name = tc.name + "/stale"
			}
			t.Run(name, func(t *testing.T) {
				source, keys := workerPolicySyncFixture(t)
				observed := source.snapshot.Manifest
				if stale {
					observed.RootAuthorizationEpoch--
				}
				service := NewWorkerPolicySyncService(source, keys)
				prior, err := service.Sync(context.Background(), observed)
				if err != nil || !prior.Synchronized() {
					t.Fatalf("initial sync failed: %v", err)
				}
				priorManifest, priorDigest := prior.Manifest(), prior.Bundle().Digest()
				tc.change(source, keys)
				beforeObserved, beforeSource := observed, source.snapshot
				beforeSignature := append([]byte(nil), source.snapshot.Signature...)
				result, err := service.Sync(context.Background(), observed)
				assertWorkerPolicySyncFailure(t, result, err)
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Fatalf("cause lost: %v; want %v", err, tc.cause)
				}
				if observed != beforeObserved || !reflect.DeepEqual(source.snapshot, beforeSource) || !reflect.DeepEqual(source.snapshot.Signature, beforeSignature) {
					t.Fatal("failure mutated caller/source state")
				}
				if prior.Manifest() != priorManifest || prior.Bundle().Digest() != priorDigest || prior.Bundle().Validate() != nil {
					t.Fatal("failure mutated previously returned snapshot")
				}
			})
		}
	}
}

func TestWorkerPolicySyncMissingDependenciesAndContext(t *testing.T) {
	for _, name := range []string{
		"nil service", "nil source", "typed nil source", "nil keys", "typed nil keys", "nil context", "canceled context", "expired context",
	} {
		t.Run(name, func(t *testing.T) {
			source, keys := workerPolicySyncFixture(t)
			service := NewWorkerPolicySyncService(source, keys)
			ctx := context.Background()
			var cause error
			switch name {
			case "nil service":
				service = nil
			case "nil source":
				service.source = nil
			case "typed nil source":
				service.source = (*workerPolicySourceFake)(nil)
			case "nil keys":
				service.keys = nil
			case "typed nil keys":
				service.keys = (*workerPolicyKeysFake)(nil)
			case "nil context":
				ctx = nil
			case "canceled context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				cause = context.Canceled
			case "expired context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(1, 0))
				defer cancel()
				cause = context.DeadlineExceeded
			}
			result, err := service.Sync(ctx, source.snapshot.Manifest)
			assertWorkerPolicySyncFailure(t, result, err)
			if cause != nil && !errors.Is(err, cause) {
				t.Fatalf("context cause lost: %v", err)
			}
			if source.calls != 0 || keys.calls != 0 {
				t.Fatal("invalid initialization/context reached a source")
			}
		})
	}
}

func TestWorkerPolicySyncCancellationDuringPull(t *testing.T) {
	for _, stage := range []string{"source", "key resolver"} {
		t.Run(stage, func(t *testing.T) {
			source, keys := workerPolicySyncFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "source" {
				source.onRead = cancel
			} else {
				keys.onResolve = cancel
			}
			result, err := NewWorkerPolicySyncService(source, keys).Sync(ctx, source.snapshot.Manifest)
			assertWorkerPolicySyncFailure(t, result, err)
			if !errors.Is(err, context.Canceled) || stage == "source" && keys.calls != 0 {
				t.Fatalf("cancellation not enforced before further work: %v", err)
			}
		})
	}
}

func TestWorkerPolicySyncCopiesSignatureBeforeResolvingKey(t *testing.T) {
	source, keys := workerPolicySyncFixture(t)
	keys.onResolve = func() { source.snapshot.Signature[0] ^= 1 }
	result, err := NewWorkerPolicySyncService(source, keys).Sync(context.Background(), source.snapshot.Manifest)
	if err != nil || !result.Synchronized() {
		t.Fatalf("resolver changed the already-pulled signature: %v", err)
	}
}

func assertWorkerPolicySyncFailure(t *testing.T, result WorkerPolicySyncResult, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected failure")
	}
	if result.Synchronized() || result.ObservedStatus() != WorkerPolicyUnknown || result.Manifest() != (WorkerPolicyManifest{}) || !reflect.DeepEqual(result, WorkerPolicySyncResult{}) {
		t.Fatalf("failure exposed synchronized/current or partial state: %+v", result)
	}
}
