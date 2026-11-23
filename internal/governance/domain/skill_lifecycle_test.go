package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSkillLifecycleBuilderCannotSelfPublishAndRevokeBlocksDispatch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := SkillManifest{
		SchemaVersion:   SkillManifestSchema,
		SkillID:         "skill.naya.lint",
		Version:         "1.0.0",
		RuntimeKind:     SkillRuntimeWASM,
		ContentDigest:   digestOf('a'),
		RequiredSandbox: SandboxWasmWASI,
		Provenance: SkillProvenance{
			BuilderID:      "naya-builder",
			SourceRevision: "rev-1",
			BuildDigest:    digestOf('b'),
		},
		RequestedPermissions: []string{"cap.read"},
	}
	msg, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, msg)

	staged, err := StageSkill(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := CanDispatchSkill(staged); !errors.Is(err, ErrSkillLifecycle) {
		t.Fatalf("staged skill should not be dispatchable: %v", err)
	}
	if _, err := VerifyStagedSkill(staged, "naya-builder", sig, pub, []string{"cap.read"}); !errors.Is(err, ErrSkillLifecycle) {
		t.Fatal("builder self-verified its own skill")
	}
	verified, err := VerifyStagedSkill(staged, "verifier-1", sig, pub, []string{"cap.read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishVerifiedSkill(verified, "naya-builder"); !errors.Is(err, ErrSkillLifecycle) {
		t.Fatal("builder self-published its own skill")
	}
	published, err := PublishVerifiedSkill(verified, "publisher-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateSkill(published); !errors.Is(err, ErrSkillLifecycle) {
		t.Fatal("published skill bypassed canary into active")
	}
	if err := CanDispatchSkill(published); !errors.Is(err, ErrSkillLifecycle) {
		t.Fatal("published skill dispatched before entering canary")
	}
	canary, err := CanarySkill(published)
	if err != nil {
		t.Fatal(err)
	}
	active, err := ActivateSkill(canary)
	if err != nil {
		t.Fatal(err)
	}
	if err := CanDispatchSkill(active); err != nil {
		t.Fatalf("active skill dispatch failed: %v", err)
	}
	revoked, err := RevokeSkill(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := CanDispatchSkill(revoked); !errors.Is(err, ErrSkillRevoked) {
		t.Fatalf("revoked skill remained dispatchable: %v", err)
	}
}
