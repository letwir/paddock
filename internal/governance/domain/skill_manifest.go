package domain

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/letwir/paddock/internal/canonical"
)

var ErrInvalidSkillManifest = errors.New("invalid skill manifest")

const (
	SkillManifestSchema        = "paddock.skill-manifest/1"
	SkillManifestSigningDomain = canonical.Domain("paddock.skill-manifest")
)

type SkillRuntimeKind string

const (
	SkillRuntimeInstruction SkillRuntimeKind = "instruction"
	SkillRuntimeWASM        SkillRuntimeKind = "wasm"
	SkillRuntimeNative      SkillRuntimeKind = "native"
	SkillRuntimeScript      SkillRuntimeKind = "script"
	SkillRuntimeContainer   SkillRuntimeKind = "container"
)

func (k SkillRuntimeKind) Validate() error {
	switch k {
	case SkillRuntimeInstruction, SkillRuntimeWASM, SkillRuntimeNative, SkillRuntimeScript, SkillRuntimeContainer:
		return nil
	default:
		return fmt.Errorf("%w: unknown runtime kind %q", ErrInvalidSkillManifest, k)
	}
}

type SkillProvenance struct {
	BuilderID      string `json:"builder_id"`
	SourceRevision string `json:"source_revision"`
	BuildDigest    Digest `json:"build_digest"`
}

// SkillManifest pins the artifact digest, provenance, runtime kind, and
// requested permissions. RequestedPermissions are NEVER self-granted authority.
type SkillManifest struct {
	SchemaVersion        string           `json:"schema_version"`
	SkillID              string           `json:"skill_id"`
	Version              string           `json:"version"`
	RuntimeKind          SkillRuntimeKind `json:"runtime_kind"`
	ContentDigest        Digest           `json:"content_digest"`
	RequiredSandbox      SandboxKind      `json:"required_sandbox"`
	Provenance           SkillProvenance  `json:"provenance"`
	RequestedPermissions []string         `json:"requested_permissions"`
}

func (m SkillManifest) Validate() error {
	if m.SchemaVersion != SkillManifestSchema ||
		validateID(m.SkillID) != nil ||
		validateID(m.Version) != nil ||
		m.RuntimeKind.Validate() != nil ||
		m.ContentDigest.Validate() != nil ||
		m.RequiredSandbox.Validate() != nil ||
		validateID(m.Provenance.BuilderID) != nil ||
		validateID(m.Provenance.SourceRevision) != nil ||
		m.Provenance.BuildDigest.Validate() != nil {
		return fmt.Errorf("%w: malformed manifest fields", ErrInvalidSkillManifest)
	}
	if m.RuntimeKind != SkillRuntimeInstruction && !m.RequiredSandbox.IsIsolationBoundary() {
		return fmt.Errorf("%w: executable runtime %s requires an isolation boundary", ErrInvalidSkillManifest, m.RuntimeKind)
	}
	seen := map[string]bool{}
	for _, p := range m.RequestedPermissions {
		if !capabilityIDPattern.MatchString(p) || seen[p] {
			return fmt.Errorf("%w: invalid or duplicate requested permission %q", ErrInvalidSkillManifest, p)
		}
		seen[p] = true
	}
	return nil
}

func (m SkillManifest) SigningBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	copyPerms := append([]string(nil), m.RequestedPermissions...)
	sort.Strings(copyPerms)
	m.RequestedPermissions = copyPerms
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	cb, err := canonical.NewJCSCodec().CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	return canonical.Envelope(
		canonical.NewJCSCodec(),
		SkillManifestSigningDomain,
		canonical.Context{
			SchemaVersion: m.SchemaVersion,
			Audience:      "skill-registry",
			RequestID:     m.SkillID + "@" + m.Version,
			Nonce:         string(m.ContentDigest),
		},
		cb,
	)
}

type VerifiedSkillAdmission struct {
	Manifest               SkillManifest
	GrantedPermissions     []string
	DeniedRequestedPerms   []string
	RequestedExceedsGrants bool
}

// VerifySkillManifest authenticates the JCS-signed manifest and computes the
// separation between manifest-requested permissions and explicitly granted authority.
// If the manifest requests any permission not in grantedAuthority, it fails closed.
func VerifySkillManifest(
	manifest SkillManifest,
	signature []byte,
	signerPubKey ed25519.PublicKey,
	expectedContentDigest Digest,
	grantedAuthority []string,
) (VerifiedSkillAdmission, error) {
	if expectedContentDigest.Validate() != nil || manifest.ContentDigest != expectedContentDigest {
		return VerifiedSkillAdmission{}, fmt.Errorf("%w: content digest pin mismatch", ErrInvalidSkillManifest)
	}
	msg, err := manifest.SigningBytes()
	if err != nil {
		return VerifiedSkillAdmission{}, err
	}
	if !evidencePublicKey(signerPubKey) || len(signature) != ed25519.SignatureSize || !ed25519.Verify(signerPubKey, msg, signature) {
		return VerifiedSkillAdmission{}, fmt.Errorf("%w: signature verification failed", ErrInvalidSkillManifest)
	}

	allowed := map[string]bool{}
	for _, g := range grantedAuthority {
		allowed[g] = true
	}
	var granted, denied []string
	for _, req := range manifest.RequestedPermissions {
		if allowed[req] {
			granted = append(granted, req)
		} else {
			denied = append(denied, req)
		}
	}
	sort.Strings(granted)
	sort.Strings(denied)
	if len(denied) > 0 {
		return VerifiedSkillAdmission{
			Manifest:               manifest,
			GrantedPermissions:     granted,
			DeniedRequestedPerms:   denied,
			RequestedExceedsGrants: true,
		}, fmt.Errorf("%w: requested permissions %v exceed explicit authority grants", ErrInvalidSkillManifest, denied)
	}
	return VerifiedSkillAdmission{
		Manifest:           manifest,
		GrantedPermissions: granted,
	}, nil
}
