package domain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

var (
	ErrSkillLifecycle = errors.New("invalid skill lifecycle transition")
	ErrSkillRevoked   = errors.New("skill has been revoked")
)

type SkillLifecycleState string

const (
	SkillStaged    SkillLifecycleState = "STAGED"
	SkillVerified  SkillLifecycleState = "VERIFIED"
	SkillPublished SkillLifecycleState = "PUBLISHED"
	SkillCanary    SkillLifecycleState = "CANARY"
	SkillActive    SkillLifecycleState = "ACTIVE"
	SkillRevoked   SkillLifecycleState = "REVOKED"
)

type SkillLifecycleRecord struct {
	Manifest           SkillManifest
	State              SkillLifecycleState
	BuilderID          string
	VerifierID         string
	PublisherID        string
	GrantedPermissions []string
}

func StageSkill(manifest SkillManifest) (SkillLifecycleRecord, error) {
	if err := manifest.Validate(); err != nil {
		return SkillLifecycleRecord{}, err
	}
	return SkillLifecycleRecord{
		Manifest:  manifest,
		State:     SkillStaged,
		BuilderID: manifest.Provenance.BuilderID,
	}, nil
}

// VerifyStagedSkill enforces independent verification: the Builder cannot verify
// or self-sign its own SKILL.
func VerifyStagedSkill(
	rec SkillLifecycleRecord,
	verifierID string,
	manifestSig []byte,
	verifierPubKey ed25519.PublicKey,
	grantedAuthority []string,
) (SkillLifecycleRecord, error) {
	if rec.State != SkillStaged || validateID(verifierID) != nil {
		return rec, fmt.Errorf("%w: skill must be STAGED", ErrSkillLifecycle)
	}
	if verifierID == rec.BuilderID {
		return rec, fmt.Errorf("%w: builder %s cannot self-verify skill", ErrSkillLifecycle, rec.BuilderID)
	}
	adm, err := VerifySkillManifest(rec.Manifest, manifestSig, verifierPubKey, rec.Manifest.ContentDigest, grantedAuthority)
	if err != nil {
		return rec, err
	}
	rec.State = SkillVerified
	rec.VerifierID = verifierID
	rec.GrantedPermissions = adm.GrantedPermissions
	return rec, nil
}

// PublishVerifiedSkill transitions VERIFIED -> PUBLISHED while forbidding the
// Builder from self-publishing its own artifact.
func PublishVerifiedSkill(rec SkillLifecycleRecord, publisherID string) (SkillLifecycleRecord, error) {
	if rec.State != SkillVerified || validateID(publisherID) != nil {
		return rec, fmt.Errorf("%w: skill must be VERIFIED before publish", ErrSkillLifecycle)
	}
	if publisherID == rec.BuilderID {
		return rec, fmt.Errorf("%w: builder %s cannot self-publish skill", ErrSkillLifecycle, rec.BuilderID)
	}
	rec.State = SkillPublished
	rec.PublisherID = publisherID
	return rec, nil
}

func CanarySkill(rec SkillLifecycleRecord) (SkillLifecycleRecord, error) {
	if rec.State != SkillPublished {
		return rec, fmt.Errorf("%w: skill must be PUBLISHED before canary", ErrSkillLifecycle)
	}
	rec.State = SkillCanary
	return rec, nil
}

func ActivateSkill(rec SkillLifecycleRecord) (SkillLifecycleRecord, error) {
	if rec.State != SkillCanary {
		return rec, fmt.Errorf("%w: skill must pass CANARY before activation", ErrSkillLifecycle)
	}
	rec.State = SkillActive
	return rec, nil
}

func RevokeSkill(rec SkillLifecycleRecord) (SkillLifecycleRecord, error) {
	if rec.State == "" || rec.State == SkillRevoked {
		return rec, fmt.Errorf("%w: already revoked or uninitialized", ErrSkillLifecycle)
	}
	rec.State = SkillRevoked
	return rec, nil
}

// CanDispatchSkill fails closed for REVOKED, STAGED, VERIFIED, or pre-Canary PUBLISHED skills.
func CanDispatchSkill(rec SkillLifecycleRecord) error {
	if rec.State == SkillRevoked {
		return ErrSkillRevoked
	}
	switch rec.State {
	case SkillCanary, SkillActive:
		return nil
	default:
		return fmt.Errorf("%w: state %s is not dispatchable", ErrSkillLifecycle, rec.State)
	}
}
