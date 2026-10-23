package application

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type bundleResolverFake struct {
	key   BundleSigningKey
	err   error
	calls *[]string
}

func TestBundleRegistrationWithinRejectsCallerTransactionInputsWithoutNesting(t *testing.T) {
	from := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nil transaction", "nil context", "cancelled", "invalid key ID", "expired", "resolved key ID mismatch"} {
		t.Run(name, func(t *testing.T) {
			calls := []string{}
			tx := &bundleTxFake{now: from, calls: &calls}
			var callerTx port.GovernanceTx = tx
			ctx := context.Background()
			keyID, resolvedID := "key-1", "key-1"
			switch name {
			case "nil transaction":
				callerTx = nil
			case "nil context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalid key ID":
				keyID = " key-1 "
			case "expired":
				tx.now = from.Add(time.Hour)
			case "resolved key ID mismatch":
				resolvedID = "other-key"
			}
			resolver := bundleResolverFake{calls: &calls, key: BundleSigningKey{KeyID: resolvedID, PublicKey: key.Public().(ed25519.PublicKey), ValidFrom: from, ValidUntil: from.Add(time.Hour)}}
			svc := NewBundleRegistrationService(bundleTransactorFake{tx: tx, calls: &calls}, resolver)
			if _, err := svc.RegisterWithin(ctx, callerTx, bundle, keyID, ed25519.Sign(key, bundle.SigningBytes())); err == nil {
				t.Fatal("invalid caller input accepted")
			}
			want := []string{}
			if name == "expired" || name == "resolved key ID mismatch" {
				want = []string{"resolve:key-1", "time"}
			}
			if tx.inserts != 0 || !reflect.DeepEqual(calls, want) {
				t.Fatalf("inserts=%d calls=%v want=%v", tx.inserts, calls, want)
			}
		})
	}
}

func (f bundleResolverFake) ResolveBundleKey(_ context.Context, id string) (BundleSigningKey, error) {
	*f.calls = append(*f.calls, "resolve:"+id)
	return f.key, f.err
}

type bundleTxFake struct {
	port.GovernanceTx
	now     time.Time
	timeErr error
	calls   *[]string
	inserts int
}

func (f *bundleTxFake) DatabaseTime(context.Context) (time.Time, error) {
	*f.calls = append(*f.calls, "time")
	return f.now, f.timeErr
}
func (f *bundleTxFake) InsertPolicyBundle(_ context.Context, _ domain.CanonicalBundle, _ string, _ []byte) error {
	*f.calls = append(*f.calls, "insert")
	f.inserts++
	return nil
}

type bundleTransactorFake struct {
	tx    port.GovernanceTx
	calls *[]string
}

func (f bundleTransactorFake) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	*f.calls = append(*f.calls, "begin")
	err := fn(f.tx)
	*f.calls = append(*f.calls, "end")
	return err
}
func TestBundleRegistrationOrdersVerificationBeforeSingleInsert(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(time.Hour)
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, bundle.SigningBytes())
	for _, tc := range []struct {
		name                string
		resolveErr, timeErr error
		now                 time.Time
		keyID               string
		signature           []byte
		tamper              bool
		wantCalls           []string
		wantInsert          int
	}{
		{"valid", nil, nil, from, "key-1", sig, false, []string{"begin", "resolve:key-1", "time", "insert", "end"}, 1},
		{"resolver error", errors.New("resolver failed"), nil, from, "key-1", sig, false, []string{"begin", "resolve:key-1", "end"}, 0},
		{"time error", nil, errors.New("clock failed"), from, "key-1", sig, false, []string{"begin", "resolve:key-1", "time", "end"}, 0},
		{"expired", nil, nil, until, "key-1", sig, false, []string{"begin", "resolve:key-1", "time", "end"}, 0},
		{"bad signature", nil, nil, from, "key-1", []byte("dummy"), false, []string{"begin", "resolve:key-1", "time", "end"}, 0},
		{"bad key id", nil, nil, from, "key-1", sig, false, []string{"begin", "resolve:key-1", "time", "end"}, 0},
		{"changed bundle", nil, nil, from, "key-1", sig, true, []string{"begin", "resolve:key-1", "time", "end"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []string{}
			tx := &bundleTxFake{now: tc.now, timeErr: tc.timeErr, calls: &calls}
			kid := "key-1"
			if tc.name == "bad key id" {
				kid = "different"
			}
			resolver := bundleResolverFake{key: BundleSigningKey{KeyID: kid, PublicKey: pub, ValidFrom: from, ValidUntil: until}, err: tc.resolveErr, calls: &calls}
			candidate := bundle
			if tc.tamper {
				candidate, err = domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"tampered"}`))
				if err != nil {
					t.Fatal(err)
				}
			}
			svc := NewBundleRegistrationService(bundleTransactorFake{tx: tx, calls: &calls}, resolver)
			got, err := svc.Register(context.Background(), candidate, tc.keyID, tc.signature)
			if (err == nil) != (tc.wantInsert == 1) {
				t.Fatalf("digest=%q error=%v", got, err)
			}
			if tx.inserts != tc.wantInsert {
				t.Fatalf("insert calls=%d want %d", tx.inserts, tc.wantInsert)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("calls=%v want %v", calls, tc.wantCalls)
			}
			if err == nil && got != bundle.Digest() {
				t.Fatalf("digest=%q want %q", got, bundle.Digest())
			}
		})
	}
}

func TestBundleRegistrationWithinUsesCallerTransaction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, bundle.SigningBytes())
	for _, tc := range []struct {
		name                 string
		resolveErr, timeErr  error
		tamper, badSignature bool
		want                 []string
	}{
		{"success", nil, nil, false, false, []string{"resolve:key-1", "time", "insert"}},
		{"resolver error", errors.New("resolver failed"), nil, false, false, []string{"resolve:key-1"}},
		{"time error", nil, errors.New("clock failed"), false, false, []string{"resolve:key-1", "time"}},
		{"signature error", nil, nil, false, true, []string{"resolve:key-1", "time"}},
		{"bundle error", nil, nil, true, false, []string{"resolve:key-1", "time"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []string{}
			tx := &bundleTxFake{now: from, timeErr: tc.timeErr, calls: &calls}
			candidate := bundle
			if tc.tamper {
				candidate, err = domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"rule":"changed"}`))
				if err != nil {
					t.Fatal(err)
				}
			}
			// A rejection fixture must not contaminate subsequent cases.
			signature := sig
			if tc.badSignature {
				signature = []byte("bad")
			}
			resolver := bundleResolverFake{key: BundleSigningKey{KeyID: "key-1", PublicKey: pub, ValidFrom: from, ValidUntil: from.Add(time.Hour)}, err: tc.resolveErr, calls: &calls}
			// A configured standalone transactor makes accidental nesting visible
			// in the call sequence instead of merely failing a nil dependency.
			svc := NewBundleRegistrationService(bundleTransactorFake{tx: tx, calls: &calls}, resolver)
			got, err := svc.RegisterWithin(context.Background(), tx, candidate, "key-1", signature)
			if (err == nil) != (tc.name == "success") {
				t.Fatalf("error=%v", err)
			}
			if tx.inserts != boolInt(tc.name == "success") {
				t.Fatalf("inserts=%d", tx.inserts)
			}
			if !reflect.DeepEqual(calls, tc.want) {
				t.Fatalf("calls=%v want %v", calls, tc.want)
			}
			if err == nil && got != bundle.Digest() {
				t.Fatalf("digest=%q want %q", got, bundle.Digest())
			}
		})
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
