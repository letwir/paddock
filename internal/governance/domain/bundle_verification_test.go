package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestVerifyCanonicalBundleAndFailures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(time.Hour)
	bundle, err := NewCanonicalBundle(BundleSchemaVersion, []byte(`{"policy":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, bundle.SigningBytes())
	key := BundleVerificationKey{KeyID: "test-key", PublicKey: pub, ValidFrom: from, ValidUntil: until}
	got, err := VerifyCanonicalBundle(bundle, key, sig, from)
	if err != nil || got != bundle.Digest() {
		t.Fatalf("valid at valid_from: digest=%q err=%v", got, err)
	}
	if _, err := VerifyCanonicalBundle(bundle, key, sig, until); err == nil {
		t.Fatal("valid_until must be exclusive")
	}
	if _, err := VerifyCanonicalBundle(bundle, key, sig, from.Add(-time.Nanosecond)); err == nil {
		t.Fatal("not-yet-valid key accepted")
	}

	badDigest := bundle
	badDigest.digest = "0000000000000000000000000000000000000000000000000000000000000000"
	badSigning := bundle
	badSigning.signing = append([]byte(nil), bundle.signing...)
	badSigning.signing[0] ^= 1
	badPayload := bundle
	badPayload.payload = []byte(`{"policy":"allow"}`)
	wrongSchema, err := NewCanonicalBundle("paddock.bundle/2", []byte(`{"policy":"deny"}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongSchemaSig := ed25519.Sign(priv, wrongSchema.SigningBytes())
	wrongDomain := bundle
	wrongDomain.signing = []byte(`{"domain":"paddock.approval"}`)
	cases := []struct {
		name string
		b    CanonicalBundle
		k    BundleVerificationKey
		sig  []byte
		now  time.Time
	}{
		{"changed digest", badDigest, key, sig, from}, {"changed signing bytes", badSigning, key, sig, from}, {"changed payload", badPayload, key, sig, from},
		{"wrong schema", wrongSchema, key, wrongSchemaSig, from}, {"wrong domain", wrongDomain, key, sig, from}, {"empty signature", bundle, key, nil, from}, {"dummy signature", bundle, key, []byte("dummy"), from},
		{"wrong signer", bundle, BundleVerificationKey{KeyID: "other", PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), ValidFrom: from, ValidUntil: until}, sig, from},
		{"empty key id", bundle, BundleVerificationKey{PublicKey: pub, ValidFrom: from, ValidUntil: until}, sig, from},
		{"wrong key length", bundle, BundleVerificationKey{KeyID: "test-key", PublicKey: pub[:10], ValidFrom: from, ValidUntil: until}, sig, from},
		{"zero validity", bundle, BundleVerificationKey{KeyID: "test-key", PublicKey: pub, ValidUntil: until}, sig, from},
		{"reversed validity", bundle, BundleVerificationKey{KeyID: "test-key", PublicKey: pub, ValidFrom: until, ValidUntil: from}, sig, from},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyCanonicalBundle(tc.b, tc.k, tc.sig, tc.now); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
	if _, err := VerifyCanonicalBundle(bundle, key, ed25519.Sign(priv, []byte("not the envelope")), from); !errors.Is(err, ErrInvalidBundleSignature) {
		t.Fatalf("wrong bytes error=%v", err)
	}
}
