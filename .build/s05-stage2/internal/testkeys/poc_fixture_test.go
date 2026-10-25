package testkeys

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type pocVector struct {
	Name         string `json:"name"`
	TestOnly     bool   `json:"test_only"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

type lifecycleFixture struct {
	TestOnly         bool              `json:"test_only"`
	VerifyAt         string            `json:"verify_at"`
	ValidUntil       string            `json:"valid_until"`
	ExpiredAt        string            `json:"expired_at"`
	Fingerprints     map[string]string `json:"fingerprints"`
	Cases            []lifecycleCase   `json:"cases"`
	ProductionStatus string            `json:"production_status"`
}

type lifecycleCase struct {
	Name                 string `json:"name"`
	ActiveFingerprint    string `json:"active_fingerprint"`
	CandidateFingerprint string `json:"candidate_fingerprint"`
	At                   string `json:"at"`
	Revoked              bool   `json:"revoked"`
	Accepted             bool   `json:"accepted"`
}

func readHexFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return decoded
}

func TestRFC8032Ed25519PublicVectorAndTampering(t *testing.T) {
	const fixtureDir = "../../testdata/poc-trust/"

	publicKey := readHexFixture(t, fixtureDir+"ed25519-public.hex")
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	vectorData, err := os.ReadFile(fixtureDir + "vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector pocVector
	if err := json.Unmarshal(vectorData, &vector); err != nil {
		t.Fatalf("decode vector JSON: %v", err)
	}
	if !vector.TestOnly {
		t.Fatal("vector is not marked test-only")
	}
	message, err := hex.DecodeString(vector.MessageHex)
	if err != nil {
		t.Fatalf("decode message: %v", err)
	}
	signature, err := hex.DecodeString(vector.SignatureHex)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(signature), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		t.Fatal("RFC 8032 public test vector did not verify")
	}

	tamperedSignature := append([]byte(nil), signature...)
	tamperedSignature[0] ^= 0x01
	if ed25519.Verify(ed25519.PublicKey(publicKey), message, tamperedSignature) {
		t.Fatal("accepted tampered signature")
	}

	tamperedMessage := append(message, 0x00)
	if ed25519.Verify(ed25519.PublicKey(publicKey), tamperedMessage, signature) {
		t.Fatal("accepted signature for tampered message")
	}
}

// lifecycleAllowed is intentionally a pure fixture policy helper; it has no
// clock, storage, key-management, or operational lifecycle behavior.
func lifecycleAllowed(activeFingerprint, candidateFingerprint string, at, validFrom, validUntil time.Time, revoked bool) bool {
	return candidateFingerprint == activeFingerprint && !revoked && !at.Before(validFrom) && at.Before(validUntil)
}

func validSHA256Fingerprint(fingerprint string) bool {
	if !strings.HasPrefix(fingerprint, "sha256:") {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(fingerprint, "sha256:"))
	return err == nil && len(digest) == 32
}

func TestPOCKeyLifecyclePolicyFixture(t *testing.T) {
	const fixturePath = "../../testdata/poc-trust/key-lifecycle.json"
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read lifecycle fixture: %v", err)
	}
	var fixture lifecycleFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode lifecycle fixture: %v", err)
	}
	if !fixture.TestOnly {
		t.Fatal("lifecycle fixture is not marked test-only")
	}
	if !strings.Contains(fixture.ProductionStatus, "O-002") || !strings.Contains(fixture.ProductionStatus, "remain open") {
		t.Fatalf("production status must keep O-002 open: %q", fixture.ProductionStatus)
	}
	verifyAt, err := time.Parse(time.RFC3339, fixture.VerifyAt)
	if err != nil {
		t.Fatalf("parse verify_at: %v", err)
	}
	validUntil, err := time.Parse(time.RFC3339, fixture.ValidUntil)
	if err != nil {
		t.Fatalf("parse valid_until: %v", err)
	}
	expiredAt, err := time.Parse(time.RFC3339, fixture.ExpiredAt)
	if err != nil {
		t.Fatalf("parse expired_at: %v", err)
	}
	if validUntil.Year() != 2031 || verifyAt.Year() != 2030 || expiredAt.Year() != 2029 {
		t.Fatalf("unexpected fixed lifecycle timestamps: verify=%s valid_until=%s expired=%s", verifyAt, validUntil, expiredAt)
	}
	for label, fingerprint := range fixture.Fingerprints {
		if !validSHA256Fingerprint(fingerprint) {
			t.Fatalf("fingerprint %q must be sha256 plus 64 hex characters: %q", label, fingerprint)
		}
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			activeFingerprint, ok := fixture.Fingerprints[tc.ActiveFingerprint]
			if !ok {
				t.Fatalf("unknown active fingerprint label %q", tc.ActiveFingerprint)
			}
			candidateFingerprint, ok := fixture.Fingerprints[tc.CandidateFingerprint]
			if !ok {
				t.Fatalf("unknown candidate fingerprint label %q", tc.CandidateFingerprint)
			}
			at := map[string]time.Time{"verify_at": verifyAt, "expired_at": expiredAt}[tc.At]
			if at.IsZero() {
				t.Fatalf("unknown timestamp label %q", tc.At)
			}
			got := lifecycleAllowed(activeFingerprint, candidateFingerprint, at, verifyAt, validUntil, tc.Revoked)
			if got != tc.Accepted {
				t.Errorf("lifecycleAllowed(active=%s, candidate=%s, at=%s, revoked=%t) = %t, want %t", activeFingerprint, candidateFingerprint, at, tc.Revoked, got, tc.Accepted)
			}
		})
	}
}
