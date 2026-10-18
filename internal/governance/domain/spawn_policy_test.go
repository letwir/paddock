package domain

import (
	"testing"
	"time"
)

func TestSpawnPolicyRequiresFinitePositiveLimits(t *testing.T) {
	p := SpawnPolicy{1, 2, 1, 1, time.Now(), 1}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.MaxLiveChildren = 0
	if p.Validate() == nil {
		t.Fatal("accepted unlimited live children")
	}
}
func TestSemanticFingerprintsIgnoreIDsAndSortDependencies(t *testing.T) {
	a := SemanticNode{ID: "a", Title: "a"}
	b := SemanticNode{ID: "b", Title: "b", Dependencies: []string{"a"}}
	x, e := SemanticFingerprints([]SemanticNode{a, b})
	if e != nil {
		t.Fatal(e)
	}
	a.ID = "other"
	b.ID = "else"
	b.Dependencies = []string{"other"}
	y, e := SemanticFingerprints([]SemanticNode{a, b})
	if e != nil || x["b"] != y["else"] {
		t.Fatalf("identity affected fingerprint: %v", e)
	}
}
func TestSemanticFingerprintsRejectBadDAG(t *testing.T) {
	for _, nodes := range [][]SemanticNode{{{ID: "a", Dependencies: []string{"missing"}}}, {{ID: "a", Dependencies: []string{"a"}}}, {{ID: "a", Dependencies: []string{"b"}}, {ID: "b", Dependencies: []string{"a"}}}} {
		if _, e := SemanticFingerprints(nodes); e == nil {
			t.Fatal("accepted invalid DAG")
		}
	}
}
