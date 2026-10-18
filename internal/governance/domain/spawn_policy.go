package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/letwir/paddock/internal/canonical"
)

var ErrInvalidSpawnPolicy = errors.New("invalid spawn policy")

type SpawnPolicy struct {
	MaxSpawnDepth           int       `json:"max_spawn_depth"`
	MaxTotalDescendants     int       `json:"max_total_descendants"`
	MaxLiveChildren         int       `json:"max_live_children"`
	MaxAttemptsPerWorkOrder int       `json:"max_attempts_per_work_order"`
	RootDeadline            time.Time `json:"root_deadline"`
	MaxRepeatFingerprint    int       `json:"max_repeat_fingerprint"`
}

func (p SpawnPolicy) Validate() error {
	if p.MaxSpawnDepth <= 0 || p.MaxTotalDescendants <= 0 || p.MaxLiveChildren <= 0 || p.MaxAttemptsPerWorkOrder <= 0 || p.MaxRepeatFingerprint <= 0 || p.RootDeadline.IsZero() || p.RootDeadline.Location() == nil {
		return ErrInvalidSpawnPolicy
	}
	return nil
}

type SemanticNode struct {
	ID               string   `json:"-"`
	Title            string   `json:"title"`
	Goal             string   `json:"goal"`
	Acceptance       string   `json:"acceptance"`
	DefinitionDigest string   `json:"definition_digest"`
	PolicyDigest     string   `json:"policy_digest"`
	Dependencies     []string `json:"-"`
}

// SemanticFingerprints validates the complete dependency DAG before calculating
// recursively-derived fingerprints. IDs are lookup keys only and never enter JCS.
func SemanticFingerprints(nodes []SemanticNode) (map[string]string, error) {
	byID := make(map[string]SemanticNode, len(nodes))
	for _, n := range nodes {
		if n.ID == "" {
			return nil, fmt.Errorf("%w: empty node ID", ErrInvalidSpawnPolicy)
		}
		if _, ok := byID[n.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate node ID", ErrInvalidSpawnPolicy)
		}
		byID[n.ID] = n
	}
	edges := map[string]bool{}
	for _, n := range nodes {
		for _, dep := range n.Dependencies {
			if _, ok := byID[dep]; !ok {
				return nil, fmt.Errorf("%w: unknown dependency", ErrInvalidSpawnPolicy)
			}
			key := n.ID + "\x00" + dep
			if edges[key] {
				return nil, fmt.Errorf("%w: duplicate dependency", ErrInvalidSpawnPolicy)
			}
			edges[key] = true
		}
	}
	state := map[string]uint8{}
	result := map[string]string{}
	var visit func(string) (string, error)
	visit = func(id string) (string, error) {
		if state[id] == 1 {
			return "", fmt.Errorf("%w: dependency cycle", ErrInvalidSpawnPolicy)
		}
		if state[id] == 2 {
			return result[id], nil
		}
		state[id] = 1
		n := byID[id]
		deps := make([]string, 0, len(n.Dependencies))
		for _, dep := range n.Dependencies {
			f, e := visit(dep)
			if e != nil {
				return "", e
			}
			deps = append(deps, f)
		}
		sort.Strings(deps)
		raw, e := json.Marshal(struct {
			Title                  string   `json:"title"`
			Goal                   string   `json:"goal"`
			Acceptance             string   `json:"acceptance"`
			DefinitionDigest       string   `json:"definition_digest"`
			PolicyDigest           string   `json:"policy_digest"`
			DependencyFingerprints []string `json:"dependency_fingerprints"`
		}{n.Title, n.Goal, n.Acceptance, n.DefinitionDigest, n.PolicyDigest, deps})
		if e != nil {
			return "", e
		}
		canonicalBytes, e := canonical.NewJCSCodec().CanonicalizeJSON(raw)
		if e != nil {
			return "", e
		}
		sum := sha256.Sum256(canonicalBytes)
		result[id] = hex.EncodeToString(sum[:])
		state[id] = 2
		return result[id], nil
	}
	for id := range byID {
		if _, e := visit(id); e != nil {
			return nil, e
		}
	}
	return result, nil
}
