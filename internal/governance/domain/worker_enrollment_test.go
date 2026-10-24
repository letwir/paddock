package domain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
)

func enrollmentFixture(t *testing.T) (EnrollmentChallenge, ed25519.PrivateKey) {
	t.Helper()
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	fingerprint, err := FingerprintWorkerKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return EnrollmentChallenge{ID: strings.Repeat("1", 64), Nonce: strings.Repeat("2", 64), Fingerprint: fingerprint, Schema: WorkerEnrollmentSchema, Audience: WorkerEnrollmentAudience}, key
}

func TestWorkerEnrollmentGoldenEnvelope(t *testing.T) {
	c, key := enrollmentFixture(t)
	if c.Fingerprint != "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9" {
		t.Fatal("noncanonical fingerprint")
	}
	codec := canonical.NewJCSCodec()
	message, err := c.SigningBytes(codec)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"audience":"paddock.coordinator","domain":"paddock.worker-enrollment","nonce":"` + c.Nonce + `","payload":{"fingerprint":"` + string(c.Fingerprint) + `"},"request_id":"` + c.ID + `","schema_version":"paddock.worker-enrollment/1"}`
	if string(message) != expected {
		t.Fatalf("wrong JCS envelope: %s", message)
	}
	publicKey := key.Public().(ed25519.PublicKey)
	proof, err := VerifyWorkerEnrollment(codec, c, publicKey, ed25519.Sign(key, message))
	if err != nil || proof.Validate() != nil || proof.Challenge() != c {
		t.Fatalf("valid proof failed: %v", err)
	}
	original := proof.PublicKey()
	publicKey[0] ^= 1
	copyOfKey := proof.PublicKey()
	copyOfKey[1] ^= 1
	if proof.PublicKey() != original {
		t.Fatal("verified proof retained mutable key bytes")
	}
}

func TestWorkerEnrollmentProofBindsEveryContextField(t *testing.T) {
	c, key := enrollmentFixture(t)
	codec := canonical.NewJCSCodec()
	payload := []byte(`{"fingerprint":"` + string(c.Fingerprint) + `"}`)
	base := canonical.Context{SchemaVersion: c.Schema, Audience: c.Audience, RequestID: c.ID, Nonce: c.Nonce}
	for _, field := range []string{"domain", "schema", "audience", "id", "nonce", "fingerprint"} {
		t.Run(field, func(t *testing.T) {
			ctx, d, p := base, WorkerEnrollmentDomain, payload
			switch field {
			case "domain":
				d = canonical.DomainApproval
			case "schema":
				ctx.SchemaVersion = "paddock.worker-enrollment/2"
			case "audience":
				ctx.Audience = "another.cluster"
			case "id":
				ctx.RequestID = strings.Repeat("3", 64)
			case "nonce":
				ctx.Nonce = strings.Repeat("4", 64)
			case "fingerprint":
				p = []byte(`{"fingerprint":"` + strings.Repeat("a", 64) + `"}`)
			}
			message, err := canonical.Envelope(codec, d, ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyWorkerEnrollment(codec, c, key.Public().(ed25519.PublicKey), ed25519.Sign(key, message))
			if !errors.Is(err, ErrWorkerEnrollmentProof) {
				t.Fatalf("unbound %s: %v", field, err)
			}
		})
	}
}

func TestWorkerEnrollmentRejectsMalformedAndMismatchedProof(t *testing.T) {
	c, key := enrollmentFixture(t)
	codec := canonical.NewJCSCodec()
	message, err := c.SigningBytes(codec)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, signature := key.Public().(ed25519.PublicKey), ed25519.Sign(key, message)
	for _, tc := range []struct {
		name     string
		pub, sig []byte
	}{
		{"short key", publicKey[:31], signature}, {"short signature", publicKey, signature[:63]},
		{"wrong key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey), signature},
		{"wrong signature", publicKey, make([]byte, 64)}, {"missing", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyWorkerEnrollment(codec, c, tc.pub, tc.sig); !errors.Is(err, ErrWorkerEnrollmentProof) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := VerifyWorkerEnrollment(nil, c, publicKey, signature); !errors.Is(err, canonical.ErrNoCodec) {
		t.Fatalf("nil codec: %v", err)
	}
	if (VerifiedWorkerEnrollment{}).Validate() == nil {
		t.Fatal("zero proof accepted")
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 64) + "\n"} {
		if WorkerKeyFingerprint(bad).Validate() == nil || ValidateEnrollmentChallengeID(bad) == nil {
			t.Fatal("accepted noncanonical shape")
		}
	}
	for _, field := range []string{"id", "nonce", "fingerprint", "schema", "audience"} {
		bad := c
		switch field {
		case "id":
			bad.ID = ""
		case "nonce":
			bad.Nonce = ""
		case "fingerprint":
			bad.Fingerprint = ""
		case "schema":
			bad.Schema = "other"
		case "audience":
			bad.Audience = "other"
		}
		if _, err := bad.SigningBytes(codec); err == nil {
			t.Fatalf("accepted malformed %s", field)
		}
	}
}

func TestEnrollmentOnlyCreatesOpaqueQ0Identity(t *testing.T) {
	c, _ := enrollmentFixture(t)
	w := QuarantinedWorker{ID: WorkerID("worker_" + strings.Repeat("a", 64)), Fingerprint: c.Fingerprint, Tier: WorkerQuarantineTier, State: WorkerQuarantined}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"identity", "tier", "state", "fingerprint"} {
		bad := w
		switch field {
		case "identity":
			bad.ID = WorkerID(c.Fingerprint)
		case "tier":
			bad.Tier = "Q1"
		case "state":
			bad.State = "ACTIVE"
		case "fingerprint":
			bad.Fingerprint = "bad"
		}
		if bad.Validate() == nil {
			t.Fatalf("accepted unsafe %s", field)
		}
	}
}
