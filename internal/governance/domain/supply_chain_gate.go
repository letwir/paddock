package domain

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrPromptPromotionDenied  = errors.New("untrusted artifact cannot be promoted to instruction")
	ErrSupplyChainGateBlocked = errors.New("supply chain gate rejected dependency")
)

type ArtifactTrustClass string

const (
	ArtifactUntrustedData       ArtifactTrustClass = "UNTRUSTED_DATA"
	ArtifactTrustedControlInput ArtifactTrustClass = "TRUSTED_CONTROL"
)

// UntrustedArtifactInput models Worker/external output entering Steward/NAYA/Verifier.
type UntrustedArtifactInput struct {
	ArtifactID    string
	ContentDigest Digest
	TrustClass    ArtifactTrustClass
	PayloadText   string
	AttemptRole   string
}

var injectionMarkers = []string{
	"ignore previous instructions",
	"ignore all previous",
	"<|im_start|>",
	"system:",
	"grant_authority",
	"override_kernel",
	"bypass_verifier",
}

// ValidateArtifactDataBoundary enforces that untrusted artifacts stay isolated
// as data, allowlists only safe data roles, and flags prompt-injection overrides.
func ValidateArtifactDataBoundary(in UntrustedArtifactInput) error {
	if validateID(in.ArtifactID) != nil || in.ContentDigest.Validate() != nil {
		return fmt.Errorf("%w: malformed artifact metadata", ErrPromptPromotionDenied)
	}
	if in.TrustClass != ArtifactUntrustedData {
		return fmt.Errorf("%w: worker artifact cannot carry trust class %q", ErrPromptPromotionDenied, in.TrustClass)
	}
	role := strings.ToLower(strings.TrimSpace(in.AttemptRole))
	if role != "" && role != "data" && role != "untrusted_data" {
		return fmt.Errorf("%w: disallowed artifact role %q", ErrPromptPromotionDenied, in.AttemptRole)
	}
	lower := strings.ToLower(in.PayloadText)
	for _, marker := range injectionMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("%w: prompt injection marker detected (%s)", ErrPromptPromotionDenied, marker)
		}
	}
	return nil
}

// DependencyPin records pinned module/skill provenance, SHA-256 digest, and SBOM reference.
type DependencyPin struct {
	ModulePath        string
	Version           string
	PinnedSHA256      Digest
	SBOMDigest        Digest
	ProvenanceBuilder string
	Revoked           bool
}

// VerifySupplyChainGate enforces unique module pins, exact digest pinning, SBOM
// presence, trusted observed builder provenance, and non-revocation.
func VerifySupplyChainGate(expectedPins []DependencyPin, observed []DependencyPin, trustedBuilders map[string]bool) error {
	if len(expectedPins) == 0 {
		return fmt.Errorf("%w: empty dependency pin manifest", ErrSupplyChainGateBlocked)
	}
	expSeen := make(map[string]bool, len(expectedPins))
	for _, exp := range expectedPins {
		if validateID(exp.ModulePath) != nil || validateID(exp.Version) != nil {
			return fmt.Errorf("%w: malformed expected dependency", ErrSupplyChainGateBlocked)
		}
		if expSeen[exp.ModulePath] {
			return fmt.Errorf("%w: duplicate expected pin %s", ErrSupplyChainGateBlocked, exp.ModulePath)
		}
		expSeen[exp.ModulePath] = true
	}

	obsMap := make(map[string]DependencyPin, len(observed))
	for _, o := range observed {
		if validateID(o.ModulePath) != nil || validateID(o.Version) != nil {
			return fmt.Errorf("%w: malformed observed dependency", ErrSupplyChainGateBlocked)
		}
		if _, dup := obsMap[o.ModulePath]; dup {
			return fmt.Errorf("%w: duplicate dependency %s", ErrSupplyChainGateBlocked, o.ModulePath)
		}
		obsMap[o.ModulePath] = o
	}

	for _, exp := range expectedPins {
		if exp.Revoked {
			return fmt.Errorf("%w: expected pin %s is revoked", ErrSupplyChainGateBlocked, exp.ModulePath)
		}
		if exp.PinnedSHA256.Validate() != nil || exp.SBOMDigest.Validate() != nil || !trustedBuilders[exp.ProvenanceBuilder] {
			return fmt.Errorf("%w: invalid pin/SBOM/builder for %s", ErrSupplyChainGateBlocked, exp.ModulePath)
		}
		obs, ok := obsMap[exp.ModulePath]
		if !ok {
			return fmt.Errorf("%w: missing dependency %s", ErrSupplyChainGateBlocked, exp.ModulePath)
		}
		if obs.Revoked ||
			obs.Version != exp.Version ||
			obs.PinnedSHA256 != exp.PinnedSHA256 ||
			obs.SBOMDigest != exp.SBOMDigest ||
			obs.ProvenanceBuilder != exp.ProvenanceBuilder ||
			!trustedBuilders[obs.ProvenanceBuilder] {
			return fmt.Errorf("%w: dependency tampering, untrusted provenance, or revocation detected for %s", ErrSupplyChainGateBlocked, exp.ModulePath)
		}
	}
	for mod := range obsMap {
		if !expSeen[mod] {
			return fmt.Errorf("%w: unpinned extra dependency %s", ErrSupplyChainGateBlocked, mod)
		}
	}
	return nil
}
