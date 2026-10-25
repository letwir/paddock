package domain

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/letwir/paddock/internal/canonical"
	"strings"
	"testing"
)

func credentialFixture(t *testing.T) (WorkerCredential, HighRiskAuthorization, CredentialRequest, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	fp, err := FingerprintWorkerKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	c := WorkerCredential{ID: strings.Repeat("1", 64), Fingerprint: fp, Lease: AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: WorkerID("worker_" + strings.Repeat("2", 64)), SessionID: "session", LeaseEpoch: 1}, Audience: "coordinator", Issuer: CredentialIssuerContext{IssuerID: "issuer", Revision: 1, CeilingDigest: Digest(strings.Repeat("a", 64))}}
	a := HighRiskAuthorization{Grant: Grant{Root: "root", Policy: PolicyBinding{Digest: Digest(strings.Repeat("b", 64))}, AuthorizationEpoch: 3, SecurityEpoch: 7}, Lease: c.Lease}
	request, err := NewCanonicalRequest("command", "nonce", []byte(`{"operation":"fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	r := CredentialRequest{CommandID: "command", RequestDigest: request.Digest(), Nonce: "nonce"}
	message, err := c.SigningBytes("scope", a.Grant, r)
	if err != nil {
		t.Fatal(err)
	}
	a.Credential = WorkerCredentialBinding{ID: c.ID, Signature: ed25519.Sign(key, message)}
	return c, a, r, key
}

func TestWorkerCredentialProofDeterministicAndRetryable(t *testing.T) {
	c, a, r, key := credentialFixture(t)
	first, err := c.SigningBytes("scope", a.Grant, r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.SigningBytes("scope", a.Grant, r)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unstable proof encoding")
	}
	for _, field := range []string{`"domain":"paddock.worker-credential-use"`, `"schema_version":"paddock.worker-credential-use/1"`, `"issuer_revision":"1"`, `"lease_epoch":"1"`} {
		if !bytes.Contains(first, []byte(field)) {
			t.Fatalf("missing canonical binding %s", field)
		}
	}
	for i := 0; i < 2; i++ {
		if err := VerifyWorkerCredential(c, key.Public().(ed25519.PublicKey), "scope", a, r, c.Audience, c.Issuer); err != nil {
			t.Fatal(err)
		}
	}
	// Decimal strings preserve all uint64 bits rather than JCS float rounding.
	c.Issuer.Revision = ^uint64(0)
	if _, err := c.SigningBytes("scope", a.Grant, r); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCredentialProofRejectsEveryChangedBinding(t *testing.T) {
	for name, mutate := range map[string]func(*WorkerCredential, *HighRiskAuthorization, *CredentialRequest, *string, *CredentialIssuerContext, *[]byte, *ScopeID){
		"revoked": func(c *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			c.Revoked = true
		},
		"id": func(c *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			c.ID = strings.Repeat("3", 64)
		},
		"fingerprint": func(c *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			c.Fingerprint = WorkerKeyFingerprint(strings.Repeat("f", 64))
		},
		"worker": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Lease.WorkerID = "other"
		},
		"session": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Lease.SessionID = "other"
		},
		"attempt": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Lease.AttemptID = "other"
		},
		"work": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Lease.WorkOrderID = "other"
		},
		"lease epoch": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Lease.LeaseEpoch++
		},
		"audience": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, s *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			*s = "other"
		},
		"issuer id": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, i *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			i.IssuerID = "other"
		},
		"issuer revision": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, i *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			i.Revision++
		},
		"issuer ceiling": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, i *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			i.CeilingDigest = Digest(strings.Repeat("c", 64))
		},
		"issuer unavailable": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, i *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			*i = CredentialIssuerContext{}
		},
		"command": func(_ *WorkerCredential, _ *HighRiskAuthorization, r *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			r.CommandID = "other"
		},
		"request digest": func(_ *WorkerCredential, _ *HighRiskAuthorization, r *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			r.RequestDigest = Digest(strings.Repeat("e", 64))
		},
		"nonce": func(_ *WorkerCredential, _ *HighRiskAuthorization, r *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			r.Nonce = "other"
		},
		"root": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Grant.Root = "other"
		},
		"policy": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Grant.Policy.Digest = Digest(strings.Repeat("e", 64))
		},
		"root epoch": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Grant.AuthorizationEpoch++
		},
		"security epoch": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Grant.SecurityEpoch++
		},
		"scope": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, s *ScopeID) {
			*s = "other"
		},
		"key": func(_ *WorkerCredential, _ *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, k *[]byte, _ *ScopeID) {
			*k = bytes.Repeat([]byte{0}, 32)
		},
		"bad signature": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Credential.Signature[0] ^= 1
		},
		"missing proof": func(_ *WorkerCredential, a *HighRiskAuthorization, _ *CredentialRequest, _ *string, _ *CredentialIssuerContext, _ *[]byte, _ *ScopeID) {
			a.Credential = WorkerCredentialBinding{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, a, r, key := credentialFixture(t)
			audience, issuer, scope := c.Audience, c.Issuer, ScopeID("scope")
			pub := []byte(key.Public().(ed25519.PublicKey))
			mutate(&c, &a, &r, &audience, &issuer, &pub, &scope)
			if err := VerifyWorkerCredential(c, pub, scope, a, r, audience, issuer); !errors.Is(err, ErrWorkerCredential) {
				t.Fatal("changed binding accepted")
			}
		})
	}
}

func TestWorkerCredentialCannotReuseEnrollmentSignature(t *testing.T) {
	c, a, r, key := credentialFixture(t)
	challenge := EnrollmentChallenge{ID: c.ID, Nonce: strings.Repeat("9", 64), Fingerprint: c.Fingerprint, Schema: WorkerEnrollmentSchema, Audience: WorkerEnrollmentAudience}
	message, err := challenge.SigningBytes(canonical.NewJCSCodec())
	if err != nil {
		t.Fatal(err)
	}
	a.Credential.Signature = ed25519.Sign(key, message)
	if VerifyWorkerCredential(c, key.Public().(ed25519.PublicKey), "scope", a, r, c.Audience, c.Issuer) == nil {
		t.Fatal("enrollment proof crossed domain")
	}
}

func TestWorkerCredentialCanonicalInputRejectsMalformedAndChangedSnapshots(t *testing.T) {
	for _, name := range []string{"id", "fingerprint", "worker", "audience", "revision", "ceiling", "utf8 lease", "utf8 scope", "utf8 root", "safe baseline"} {
		t.Run(name, func(t *testing.T) {
			c, a, r, _ := credentialFixture(t)
			scope := ScopeID("scope")
			switch name {
			case "id":
				c.ID = "bad"
			case "fingerprint":
				c.Fingerprint = "bad"
			case "worker":
				c.Lease.WorkerID = "worker"
			case "audience":
				c.Audience = ""
			case "revision":
				c.Issuer.Revision = 0
			case "ceiling":
				c.Issuer.CeilingDigest = ""
			case "utf8 lease":
				c.Lease.SessionID = SessionID(string([]byte{255}))
			case "utf8 scope":
				scope = ScopeID(string([]byte{255}))
			case "utf8 root":
				a.Grant.Root = RootID(string([]byte{255}))
			case "safe baseline":
				a.Grant.Policy = PolicyBinding{SafeBaseline: true}
			}
			if _, err := c.SigningBytes(scope, a.Grant, r); err == nil {
				t.Fatal("malformed signing context accepted")
			}
		})
	}
	for _, name := range []string{"work", "attempt", "worker", "session", "epoch", "audience", "issuer", "revision", "ceiling"} {
		t.Run("signed snapshot/"+name, func(t *testing.T) {
			c, a, r, key := credentialFixture(t)
			switch name {
			case "work":
				c.Lease.WorkOrderID = "other"
			case "attempt":
				c.Lease.AttemptID = "other"
			case "worker":
				c.Lease.WorkerID = WorkerID("worker_" + strings.Repeat("e", 64))
			case "session":
				c.Lease.SessionID = "other"
			case "epoch":
				c.Lease.LeaseEpoch++
			case "audience":
				c.Audience = "other"
			case "issuer":
				c.Issuer.IssuerID = "other"
			case "revision":
				c.Issuer.Revision++
			case "ceiling":
				c.Issuer.CeilingDigest = Digest(strings.Repeat("e", 64))
			}
			a.Lease = c.Lease
			if err := VerifyWorkerCredential(c, key.Public().(ed25519.PublicKey), "scope", a, r, c.Audience, c.Issuer); !errors.Is(err, ErrWorkerCredential) {
				t.Fatal("signature did not bind changed snapshot")
			}
		})
	}
}
