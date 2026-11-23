package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCrossRootSharingAccessControlAndRevocation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := SkillManifest{
		SchemaVersion:        SkillManifestSchema,
		SkillID:              "skill.shared",
		Version:              "1.0.0",
		RuntimeKind:          SkillRuntimeWASM,
		ContentDigest:        digestOf('a'),
		RequiredSandbox:      SandboxWasmWASI,
		Provenance:           SkillProvenance{BuilderID: "naya", SourceRevision: "rev-1", BuildDigest: digestOf('b')},
		RequestedPermissions: []string{"cap.read"},
	}
	msg, _ := m.SigningBytes()
	sig := ed25519.Sign(priv, msg)
	staged, _ := StageSkill(m)
	verified, _ := VerifyStagedSkill(staged, "verifier-1", sig, pub, []string{"cap.read"})
	published, _ := PublishVerifiedSkill(verified, "publisher-1")
	canary, _ := CanarySkill(published)
	active, _ := ActivateSkill(canary)

	auth := AuthorityState{
		Scope:                "scope-1",
		Mode:                 ScopeActive,
		DatabaseAvailable:    true,
		ScopeActivationEpoch: 1,
		SecurityEpoch:        1,
		Roots: map[RootID]RootAuthority{
			"root-b": {AuthorizationEpoch: 1, Policy: PolicyBinding{Digest: digestOf('c')}},
		},
	}

	grant, err := AuthorizeCrossRootSkillRead(CrossRootShareRequest{
		ProducerRoot:      "root-a",
		ConsumerRoot:      "root-b",
		Skill:             active,
		PinnedDigest:      m.ContentDigest,
		ConsumerAuthority: auth,
		AllowedConsumers:  map[RootID]bool{"root-b": true},
	})
	if err != nil || !grant.NoExecutionDependencyEdge || grant.PinnedDigest != m.ContentDigest {
		t.Fatalf("authorized cross-root share failed: %+v err=%v", grant, err)
	}

	// Cross-root execution dependency edge remains forbidden by WorkOrder DAG rules.
	crossDepErr := ValidateDependencies(
		[]WorkOrder{{ID: "wo-a", RootID: "root-a"}, {ID: "wo-b", RootID: "root-b"}},
		[]Dependency{{WorkOrderID: "wo-b", DependsOnID: "wo-a"}},
	)
	if crossDepErr == nil {
		t.Fatal("cross-root execution dependency was allowed")
	}

	// Revocation immediately blocks subsequent cross-root read.
	revoked, _ := RevokeSkill(active)
	if _, err := AuthorizeCrossRootSkillRead(CrossRootShareRequest{
		ProducerRoot:      "root-a",
		ConsumerRoot:      "root-b",
		Skill:             revoked,
		PinnedDigest:      m.ContentDigest,
		ConsumerAuthority: auth,
		AllowedConsumers:  map[RootID]bool{"root-b": true},
	}); !errors.Is(err, ErrCrossRootShareDenied) {
		t.Fatal("revoked skill remained readable cross-root")
	}

	// Missing consumer ACL fails closed.
	if _, err := AuthorizeCrossRootSkillRead(CrossRootShareRequest{
		ProducerRoot:      "root-a",
		ConsumerRoot:      "root-b",
		Skill:             active,
		PinnedDigest:      m.ContentDigest,
		ConsumerAuthority: auth,
		AllowedConsumers:  map[RootID]bool{},
	}); !errors.Is(err, ErrCrossRootShareDenied) {
		t.Fatal("unauthorized consumer root allowed")
	}
}
