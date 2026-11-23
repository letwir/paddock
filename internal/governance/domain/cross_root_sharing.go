package domain

import (
	"errors"
	"fmt"
)

var ErrCrossRootShareDenied = errors.New("cross-root artifact/skill sharing denied")

type CrossRootShareRequest struct {
	ProducerRoot      RootID
	ConsumerRoot      RootID
	Skill             SkillLifecycleRecord
	PinnedDigest      Digest
	ConsumerAuthority AuthorityState
	AllowedConsumers  map[RootID]bool
	RevokedDigests    map[Digest]bool
}

// CrossRootSkillGrant authorizes immutable read access to a verified,
// digest-pinned Skill across Roots without creating an execution dependency edge.
type CrossRootSkillGrant struct {
	ProducerRoot              RootID
	ConsumerRoot              RootID
	SkillID                   string
	Version                   string
	PinnedDigest              Digest
	NoExecutionDependencyEdge bool
}

// AuthorizeCrossRootSkillRead re-checks skill lifecycle/revocation, digest pin,
// consumer read authority, and explicit consumer ACL on every read without
// introducing cross-Root execution dependencies.
func AuthorizeCrossRootSkillRead(req CrossRootShareRequest) (CrossRootSkillGrant, error) {
	if req.ProducerRoot.Validate() != nil || req.ConsumerRoot.Validate() != nil || req.PinnedDigest.Validate() != nil {
		return CrossRootSkillGrant{}, fmt.Errorf("%w: invalid root or digest", ErrCrossRootShareDenied)
	}
	if err := CanDispatchSkill(req.Skill); err != nil {
		return CrossRootSkillGrant{}, fmt.Errorf("%w: %v", ErrCrossRootShareDenied, err)
	}
	if req.Skill.Manifest.ContentDigest != req.PinnedDigest || req.RevokedDigests[req.PinnedDigest] {
		return CrossRootSkillGrant{}, fmt.Errorf("%w: digest mismatch or revoked", ErrCrossRootShareDenied)
	}
	if _, err := EffectivePolicy(req.ConsumerAuthority, req.ConsumerRoot); err != nil {
		return CrossRootSkillGrant{}, fmt.Errorf("%w: consumer authority denied: %v", ErrCrossRootShareDenied, err)
	}
	if !req.AllowedConsumers[req.ConsumerRoot] {
		return CrossRootSkillGrant{}, fmt.Errorf("%w: consumer root %s lacks read ACL", ErrCrossRootShareDenied, req.ConsumerRoot)
	}
	return CrossRootSkillGrant{
		ProducerRoot:              req.ProducerRoot,
		ConsumerRoot:              req.ConsumerRoot,
		SkillID:                   req.Skill.Manifest.SkillID,
		Version:                   req.Skill.Manifest.Version,
		PinnedDigest:              req.PinnedDigest,
		NoExecutionDependencyEdge: true,
	}, nil
}
