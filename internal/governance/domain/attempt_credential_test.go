package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestAttemptCredentialBindingsCeilingExpiryStolenAndRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen2 failed: %v", err)
	}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	ceiling := CredentialIssuerCeiling{
		IssuerID:            "issuer_coord_01",
		AllowedCapabilities: []string{"cap.read", "cap.compute"},
		AllowedAudiences:    []string{"paddock.worker"},
		MaxTTL:              15 * time.Minute,
	}
	highCeiling := CredentialIssuerCeiling{
		IssuerID:            "issuer_admin_high",
		AllowedCapabilities: []string{"cap.read", "cap.compute", "cap.admin"},
		AllowedAudiences:    []string{"paddock.worker"},
		MaxTTL:              15 * time.Minute,
	}

	cred, err := IssueAttemptCredential(AttemptCredential{
		CredentialID: "cred_01",
		IssuerID:     "issuer_coord_01",
		KeyID:        "key_01",
		WorkerID:     "worker_a",
		AttemptID:    "att_100",
		LeaseEpoch:   7,
		Audience:     "paddock.worker",
		Capabilities: []string{"cap.read", "cap.compute"},
		IssuedAt:     now,
		ExpiresAt:    now.Add(10 * time.Minute),
	}, ceiling, priv)
	if err != nil {
		t.Fatalf("IssueAttemptCredential failed: %v", err)
	}

	baseIn := AttemptCredentialVerifyInput{
		ExpectedWorkerID:   "worker_a",
		ExpectedAttemptID:  "att_100",
		ExpectedLeaseEpoch: 7,
		ExpectedAudience:   "paddock.worker",
		RequiredCapability: "cap.compute",
		TrustedKeys: map[string]TrustedKeyBinding{
			"key_01":    {IssuerID: "issuer_coord_01", PublicKey: pub},
			"key_other": {IssuerID: "issuer_admin_high", PublicKey: otherPub},
		},
		IssuerCeilings: map[string]CredentialIssuerCeiling{
			"issuer_coord_01":   ceiling,
			"issuer_admin_high": highCeiling,
		},
		Now: now.Add(5 * time.Minute),
	}
	if err := VerifyAttemptCredential(cred, baseIn); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}

	// Cross-issuer key substitution: low-authority issuer key_01 claims IssuerID=issuer_admin_high.
	impersonated, err := IssueAttemptCredential(AttemptCredential{
		CredentialID: "cred_impersonate",
		IssuerID:     "issuer_admin_high",
		KeyID:        "key_01",
		WorkerID:     "worker_a",
		AttemptID:    "att_100",
		LeaseEpoch:   7,
		Audience:     "paddock.worker",
		Capabilities: []string{"cap.admin"},
		IssuedAt:     now,
		ExpiresAt:    now.Add(10 * time.Minute),
	}, highCeiling, priv)
	if err != nil {
		t.Fatalf("issue impersonated failed: %v", err)
	}
	if err := VerifyAttemptCredential(impersonated, baseIn); !errors.Is(err, ErrAttemptIssuerCeiling) {
		t.Fatalf("expected ErrAttemptIssuerCeiling when key_01 impersonates issuer_admin_high, got %v", err)
	}
	_ = otherPriv

	// Issuance above ceiling fails closed.
	if _, err := IssueAttemptCredential(AttemptCredential{
		CredentialID: "cred_escalate",
		IssuerID:     "issuer_coord_01",
		KeyID:        "key_01",
		WorkerID:     "worker_a",
		AttemptID:    "att_100",
		LeaseEpoch:   7,
		Audience:     "paddock.worker",
		Capabilities: []string{"cap.admin"},
		IssuedAt:     now,
		ExpiresAt:    now.Add(10 * time.Minute),
	}, ceiling, priv); !errors.Is(err, ErrAttemptIssuerCeiling) {
		t.Fatalf("expected ErrAttemptIssuerCeiling, got %v", err)
	}

	// Expiry boundary & pre-issuance fail.
	expired := baseIn
	expired.Now = cred.ExpiresAt
	if err := VerifyAttemptCredential(cred, expired); !errors.Is(err, ErrAttemptCredentialExpired) {
		t.Fatalf("expected ErrAttemptCredentialExpired at boundary, got %v", err)
	}
	early := baseIn
	early.Now = now.Add(-1 * time.Second)
	if err := VerifyAttemptCredential(cred, early); !errors.Is(err, ErrAttemptCredentialExpired) {
		t.Fatalf("expected ErrAttemptCredentialExpired before IssuedAt, got %v", err)
	}

	// Stolen credential replayed by wrong Worker / Attempt / Epoch / Audience / Key fails.
	wrongWorker := baseIn
	wrongWorker.ExpectedWorkerID = "worker_b"
	if err := VerifyAttemptCredential(cred, wrongWorker); !errors.Is(err, ErrAttemptCredentialInvalid) {
		t.Fatalf("expected binding mismatch on wrong worker, got %v", err)
	}
	wrongAttempt := baseIn
	wrongAttempt.ExpectedAttemptID = "att_999"
	if err := VerifyAttemptCredential(cred, wrongAttempt); !errors.Is(err, ErrAttemptCredentialInvalid) {
		t.Fatalf("expected binding mismatch on wrong attempt, got %v", err)
	}
	staleEpoch := baseIn
	staleEpoch.ExpectedLeaseEpoch = 8
	if err := VerifyAttemptCredential(cred, staleEpoch); !errors.Is(err, ErrAttemptCredentialInvalid) {
		t.Fatalf("expected binding mismatch on stale epoch, got %v", err)
	}
	wrongAudience := baseIn
	wrongAudience.ExpectedAudience = "paddock.admin"
	if err := VerifyAttemptCredential(cred, wrongAudience); !errors.Is(err, ErrAttemptCredentialInvalid) {
		t.Fatalf("expected binding mismatch on wrong audience, got %v", err)
	}
	wrongKey := baseIn
	wrongKey.TrustedKeys = map[string]TrustedKeyBinding{
		"key_01": {IssuerID: "issuer_coord_01", PublicKey: otherPub},
	}
	if err := VerifyAttemptCredential(cred, wrongKey); !errors.Is(err, ErrAttemptCredentialInvalid) {
		t.Fatalf("expected signature failure on wrong key, got %v", err)
	}

	// Shrunken runtime issuer ceiling rejects previously valid broader capability.
	narrowed := baseIn
	narrowed.IssuerCeilings = map[string]CredentialIssuerCeiling{
		"issuer_coord_01": {
			IssuerID:            "issuer_coord_01",
			AllowedCapabilities: []string{"cap.read"},
			AllowedAudiences:    []string{"paddock.worker"},
			MaxTTL:              15 * time.Minute,
		},
	}
	if err := VerifyAttemptCredential(cred, narrowed); !errors.Is(err, ErrAttemptIssuerCeiling) {
		t.Fatalf("expected ErrAttemptIssuerCeiling after runtime ceiling reduction, got %v", err)
	}

	// Revocation by CredentialID, KeyID, and IssuerID all reject.
	revCred := baseIn
	revCred.RevokedCredentials = map[string]bool{"cred_01": true}
	if err := VerifyAttemptCredential(cred, revCred); !errors.Is(err, ErrAttemptCredentialRevoked) {
		t.Fatalf("expected ErrAttemptCredentialRevoked, got %v", err)
	}
	revKey := baseIn
	revKey.RevokedKeys = map[string]bool{"key_01": true}
	if err := VerifyAttemptCredential(cred, revKey); !errors.Is(err, ErrAttemptCredentialRevoked) {
		t.Fatalf("expected ErrAttemptCredentialRevoked by key, got %v", err)
	}
	revIssuer := baseIn
	revIssuer.RevokedIssuers = map[string]bool{"issuer_coord_01": true}
	if err := VerifyAttemptCredential(cred, revIssuer); !errors.Is(err, ErrAttemptCredentialRevoked) {
		t.Fatalf("expected ErrAttemptCredentialRevoked by issuer, got %v", err)
	}
}
