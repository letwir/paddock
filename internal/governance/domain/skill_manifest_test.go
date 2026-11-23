package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSkillManifestRuntimesDigestPinAndAuthoritySeparation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []SkillRuntimeKind{
		SkillRuntimeInstruction,
		SkillRuntimeWASM,
		SkillRuntimeNative,
		SkillRuntimeScript,
		SkillRuntimeContainer,
	} {
		sb := SandboxWasmWASI
		if kind == SkillRuntimeInstruction {
			sb = SandboxNone
		}
		m := SkillManifest{
			SchemaVersion:   SkillManifestSchema,
			SkillID:         "skill." + string(kind),
			Version:         "1.0.0",
			RuntimeKind:     kind,
			ContentDigest:   digestOf('a'),
			RequiredSandbox: sb,
			Provenance: SkillProvenance{
				BuilderID:      "builder-1",
				SourceRevision: "rev-1",
				BuildDigest:    digestOf('b'),
			},
			RequestedPermissions: []string{"cap.read"},
		}
		msg, err := m.SigningBytes()
		if err != nil {
			t.Fatalf("runtime %s signing bytes: %v", kind, err)
		}
		sig := ed25519.Sign(priv, msg)
		// Grant matches request -> admitted.
		adm, err := VerifySkillManifest(m, sig, pub, m.ContentDigest, []string{"cap.read"})
		if err != nil || len(adm.GrantedPermissions) != 1 {
			t.Fatalf("runtime %s admission failed: %v", kind, err)
		}
		// Manifest requests permission NOT in grantedAuthority -> rejected even with valid signature!
		if _, err := VerifySkillManifest(m, sig, pub, m.ContentDigest, nil); !errors.Is(err, ErrInvalidSkillManifest) {
			t.Fatalf("manifest self-granted permissions for %s", kind)
		}
		// Digest pin mismatch rejected.
		if _, err := VerifySkillManifest(m, sig, pub, digestOf('c'), []string{"cap.read"}); !errors.Is(err, ErrInvalidSkillManifest) {
			t.Fatalf("digest mismatch accepted for %s", kind)
		}
		// Tampered signature rejected.
		badSig := append([]byte(nil), sig...)
		badSig[0] ^= 0xff
		if _, err := VerifySkillManifest(m, badSig, pub, m.ContentDigest, []string{"cap.read"}); !errors.Is(err, ErrInvalidSkillManifest) {
			t.Fatalf("tampered signature accepted for %s", kind)
		}
	}
}
