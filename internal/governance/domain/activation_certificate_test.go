package domain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Seeds are fixed public test fixtures, never operational keys or entropy reads.
func activationFixture(t *testing.T) (KernelSnapshot, ActivationCertificate, []ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	s := KernelSnapshot{
		SchemaVersion: KernelSnapshotSchema, Version: 1,
		Thresholds:     []TierThreshold{{Tier: TierG0, Threshold: 1}, {Tier: TierG1, Threshold: 2}},
		Capabilities:   []string{"work.read"},
		IssuerCeilings: []IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"work.read"}}},
	}
	for i, id := range []string{"signer-a", "signer-b", "signer-c"} {
		keys[i] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize))
		s.Signers = append(s.Signers, KernelSigner{ID: id, PublicKey: keys[i].Public().(ed25519.PublicKey)})
	}
	kd, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c := ActivationCertificate{ActivationContext: ActivationContext{
		Scope: "scope-a", BaseActivationEpoch: 41,
		PolicyDigest: Digest(strings.Repeat("a", 64)), KernelDigest: kd,
		IssuerID: "issuer", IssuerRevision: 7,
	}}
	signActivation(t, s, &c, keys, 0, 1)
	return s, c, keys
}

func signActivation(t *testing.T, s KernelSnapshot, c *ActivationCertificate, keys []ed25519.PrivateKey, indices ...int) {
	t.Helper()
	message, err := c.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	c.Approvals = nil
	for _, i := range indices {
		c.Approvals = append(c.Approvals, DomainApproval{
			SignerID: s.Signers[i].ID, Signature: ed25519.Sign(keys[i], message),
		})
	}
}

func TestActivationCertificateBinding(t *testing.T) {
	changes := []struct {
		name   string
		change func(*ActivationContext)
	}{
		{"scope", func(c *ActivationContext) { c.Scope = "scope-b" }},
		{"base epoch", func(c *ActivationContext) { c.BaseActivationEpoch++ }},
		{"policy digest", func(c *ActivationContext) { c.PolicyDigest = Digest(strings.Repeat("b", 64)) }},
		{"kernel digest", func(c *ActivationContext) { c.KernelDigest = Digest(strings.Repeat("c", 64)) }},
		{"issuer ID", func(c *ActivationContext) { c.IssuerID = "other-issuer" }},
		{"issuer revision", func(c *ActivationContext) { c.IssuerRevision++ }},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			s, original, _ := activationFixture(t)
			current := original.ActivationContext
			if ev := VerifyActivationCertificate(s, current, original); !ev.Accepted {
				t.Fatalf("valid certificate rejected: %+v", ev)
			}
			message, err := original.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			changed := original
			tc.change(&changed.ActivationContext)
			changedMessage, err := changed.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(message, changedMessage) || ed25519.Verify(s.Signers[0].PublicKey, changedMessage, original.Approvals[0].Signature) {
				t.Fatal("signature did not bind changed field")
			}
			if ev := VerifyActivationCertificate(s, current, changed); ev.Accepted || ev.Reason != "activation context mismatch" {
				t.Fatalf("tampered certificate: %+v", ev)
			}
			// A valid approval becomes stale when trusted state changes, without
			// changing the certificate or its still-cryptographically-valid signatures.
			if ev := VerifyActivationCertificate(s, changed.ActivationContext, original); ev.Accepted || ev.Reason != "activation context mismatch" {
				t.Fatalf("stale certificate: %+v", ev)
			}
			if ev := VerifyActivationCertificate(s, changed.ActivationContext, changed); ev.Accepted {
				t.Fatalf("editing both contexts reused old signatures: %+v", ev)
			}
		})
	}
}

func TestActivationCertificateQuorum(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*ActivationCertificate)
		accept bool
	}{
		{"exact G1 quorum", func(c *ActivationCertificate) { c.Approvals = c.Approvals[:2] }, true},
		{"above quorum", func(c *ActivationCertificate) {}, true},
		{"G0 quorum is insufficient", func(c *ActivationCertificate) { c.Approvals = c.Approvals[:1] }, false},
		{"no signatures", func(c *ActivationCertificate) { c.Approvals = nil }, false},
		{"duplicate after quorum", func(c *ActivationCertificate) { c.Approvals[2] = c.Approvals[0] }, false},
		{"unknown after quorum", func(c *ActivationCertificate) { c.Approvals[2].SignerID = "unknown" }, false},
		{"empty signer", func(c *ActivationCertificate) { c.Approvals[2].SignerID = "" }, false},
		{"missing signature", func(c *ActivationCertificate) { c.Approvals[2].Signature = nil }, false},
		{"short signature", func(c *ActivationCertificate) { c.Approvals[2].Signature = c.Approvals[2].Signature[:63] }, false},
		{"long signature", func(c *ActivationCertificate) { c.Approvals[2].Signature = append(c.Approvals[2].Signature, 0) }, false},
		{"corrupt signature after quorum", func(c *ActivationCertificate) { c.Approvals[2].Signature[0] ^= 1 }, false},
		{"wrong signer key", func(c *ActivationCertificate) { c.Approvals[2].Signature = c.Approvals[0].Signature }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c, keys := activationFixture(t)
			signActivation(t, s, &c, keys, 2, 0, 1)
			tc.edit(&c)
			before := append([]DomainApproval(nil), c.Approvals...)
			ev := VerifyActivationCertificate(s, c.ActivationContext, c)
			if ev.Accepted != tc.accept || ev.Tier != TierG1 || ev.Reason == "" {
				t.Fatalf("accept=%v: %+v", tc.accept, ev)
			}
			if !reflect.DeepEqual(c.Approvals, before) {
				t.Fatal("verification mutated approvals")
			}
			if tc.accept {
				want := []string{"signer-a", "signer-b", "signer-c"}
				if len(c.Approvals) == 2 {
					want = []string{"signer-a", "signer-c"}
				}
				if !reflect.DeepEqual(ev.Signers, want) || ev.KernelDigest != c.KernelDigest || ev.CandidateDigest != c.PolicyDigest {
					t.Fatalf("incorrect evidence: %+v", ev)
				}
			}
		})
	}
}

func TestActivationCertificateUint64Boundaries(t *testing.T) {
	for _, revision := range []uint64{0, 1, 1<<53 - 1, 1 << 53, 1<<53 + 1, ^uint64(0) - 1, ^uint64(0)} {
		s, c, keys := activationFixture(t)
		c.IssuerRevision = revision
		c.BaseActivationEpoch = Epoch(revision)
		signActivation(t, s, &c, keys, 0, 1)
		if ev := VerifyActivationCertificate(s, c.ActivationContext, c); !ev.Accepted {
			t.Fatalf("revision/epoch %d rejected: %+v", revision, ev)
		}
		message, err := c.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Payload struct {
				Revision uint64 `json:"issuer_revision,string"`
				Epoch    uint64 `json:"base_activation_epoch,string"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(message, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Payload.Revision != revision || envelope.Payload.Epoch != revision {
			t.Fatalf("uint64 lost precision: %s", message)
		}
		current := c.ActivationContext
		current.IssuerRevision ^= 1
		if ev := VerifyActivationCertificate(s, current, c); ev.Accepted {
			t.Fatalf("different revision accepted at boundary %d", revision)
		}
	}
}

func TestActivationCertificateG1ThresholdBoundaries(t *testing.T) {
	for threshold := 1; threshold <= 3; threshold++ {
		for count := 0; count <= 3; count++ {
			t.Run(fmt.Sprintf("threshold=%d/signatures=%d", threshold, count), func(t *testing.T) {
				s, c, keys := activationFixture(t)
				s.Thresholds[1].Threshold = threshold
				kd, err := s.Digest()
				if err != nil {
					t.Fatal(err)
				}
				c.KernelDigest = kd
				signActivation(t, s, &c, keys, []int{0, 1, 2}[:count]...)
				ev := VerifyActivationCertificate(s, c.ActivationContext, c)
				if ev.Accepted != (count >= threshold) {
					t.Fatalf("threshold=%d, signatures=%d: %+v", threshold, count, ev)
				}
			})
		}
	}
}

func TestActivationCertificateMalformedContext(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ActivationContext)
	}{
		{"empty scope", func(c *ActivationContext) { c.Scope = "" }},
		{"padded scope", func(c *ActivationContext) { c.Scope = " scope" }},
		{"invalid scope UTF8", func(c *ActivationContext) { c.Scope = ScopeID(string([]byte{0xff})) }},
		{"empty issuer", func(c *ActivationContext) { c.IssuerID = "" }},
		{"padded issuer", func(c *ActivationContext) { c.IssuerID = "issuer " }},
		{"invalid issuer UTF8", func(c *ActivationContext) { c.IssuerID = string([]byte{0xff}) }},
		{"empty policy digest", func(c *ActivationContext) { c.PolicyDigest = "" }},
		{"uppercase policy digest", func(c *ActivationContext) { c.PolicyDigest = Digest(strings.Repeat("A", 64)) }},
		{"nonhex policy digest", func(c *ActivationContext) { c.PolicyDigest = Digest(strings.Repeat("z", 64)) }},
		{"short kernel digest", func(c *ActivationContext) { c.KernelDigest = "a" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c, _ := activationFixture(t)
			current := c.ActivationContext
			tc.edit(&c.ActivationContext)
			if _, err := c.SigningBytes(); !errors.Is(err, ErrKernelApproval) {
				t.Fatalf("malformed context signing error = %v", err)
			}
			if ev := VerifyActivationCertificate(s, current, c); ev.Accepted {
				t.Fatalf("malformed certificate accepted: %+v", ev)
			}
			if ev := VerifyActivationCertificate(s, c.ActivationContext, c); ev.Accepted || ev.Reason != "invalid current activation context" {
				t.Fatalf("malformed current context accepted: %+v", ev)
			}
		})
	}
}

func TestActivationCertificateKernelValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*KernelSnapshot)
	}{
		{"missing G1", func(s *KernelSnapshot) { s.Thresholds = s.Thresholds[:1] }},
		{"zero G1", func(s *KernelSnapshot) { s.Thresholds[1].Threshold = 0 }},
		{"impossible G1", func(s *KernelSnapshot) { s.Thresholds[1].Threshold = 4 }},
		{"duplicate G1", func(s *KernelSnapshot) { s.Thresholds = append(s.Thresholds, s.Thresholds[1]) }},
		{"duplicate signer", func(s *KernelSnapshot) { s.Signers[2] = s.Signers[0] }},
		{"duplicate public key", func(s *KernelSnapshot) { s.Signers[2].PublicKey = s.Signers[0].PublicKey }},
		{"malformed public key", func(s *KernelSnapshot) { s.Signers[2].PublicKey = []byte{1} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c, keys := activationFixture(t)
			tc.edit(&s)
			kd, err := s.Digest()
			if err != nil {
				t.Fatal(err)
			}
			c.KernelDigest = kd // Even a pinned malformed snapshot is rejected.
			signActivation(t, s, &c, keys, 0, 1)
			if ev := VerifyActivationCertificate(s, c.ActivationContext, c); ev.Accepted || ev.Reason != "malformed kernel" {
				t.Fatalf("malformed kernel: %+v", ev)
			}
		})
	}
	for _, s := range []KernelSnapshot{{}, {SchemaVersion: "wrong", Version: 1}} {
		_, c, _ := activationFixture(t)
		if ev := VerifyActivationCertificate(s, c.ActivationContext, c); ev.Accepted || ev.Reason != "malformed kernel" {
			t.Fatalf("bad kernel header: %+v", ev)
		}
	}
}

func TestActivationCertificateCurrentKernelPinAndRecheck(t *testing.T) {
	s, c, keys := activationFixture(t)
	current := c.ActivationContext
	if ev := VerifyActivationCertificate(s, current, c); !ev.Accepted {
		t.Fatalf("initial verification: %+v", ev)
	}
	// The caller's snapshot changes after approval, while its previously trusted
	// digest remains unchanged. A fresh verification must recompute the digest.
	s.Version++
	if ev := VerifyActivationCertificate(s, current, c); ev.Accepted || ev.Reason != "kernel digest mismatch" {
		t.Fatalf("substituted snapshot accepted: %+v", ev)
	}
	kd, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	current.KernelDigest = kd
	if ev := VerifyActivationCertificate(s, current, c); ev.Accepted || ev.Reason != "activation context mismatch" {
		t.Fatalf("old approval accepted after current kernel change: %+v", ev)
	}
	c.ActivationContext = current
	if ev := VerifyActivationCertificate(s, current, c); ev.Accepted {
		t.Fatalf("old signatures accepted with rewritten kernel digest: %+v", ev)
	}
	signActivation(t, s, &c, keys, 0, 1)
	if ev := VerifyActivationCertificate(s, current, c); !ev.Accepted {
		t.Fatalf("fresh kernel approval: %+v", ev)
	}
	// An issuer update between an earlier check and use invalidates that check's
	// certificate. The pure verifier does not cache an earlier Accepted result.
	current.IssuerRevision++
	if ev := VerifyActivationCertificate(s, current, c); ev.Accepted {
		t.Fatalf("stale approval accepted on recheck: %+v", ev)
	}
	c.ActivationContext = current
	signActivation(t, s, &c, keys, 0, 1)
	if ev := VerifyActivationCertificate(s, current, c); !ev.Accepted {
		t.Fatalf("fresh issuer revision approval: %+v", ev)
	}
}

func TestActivationCertificateSigningSeparation(t *testing.T) {
	s, c, keys := activationFixture(t)
	message, err := c.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	c.Approvals = nil
	repeated, err := c.SigningBytes()
	if err != nil || !bytes.Equal(message, repeated) {
		t.Fatalf("signing bytes depend on approvals or are unstable: %v", err)
	}
	for _, replacement := range []string{DomainApprovalSchema, RolloutTransitionApprovalSchema} {
		other := bytes.Replace(message, []byte(ActivationCertificateSchema), []byte(replacement), 1)
		if bytes.Equal(message, other) {
			t.Fatal("certificate schema not bound")
		}
		c.Approvals = []DomainApproval{
			{SignerID: s.Signers[0].ID, Signature: ed25519.Sign(keys[0], other)},
			{SignerID: s.Signers[1].ID, Signature: ed25519.Sign(keys[1], other)},
		}
		if ev := VerifyActivationCertificate(s, c.ActivationContext, c); ev.Accepted {
			t.Fatalf("cross-schema signature accepted for %s", replacement)
		}
	}
}
