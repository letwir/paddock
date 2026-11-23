package application

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
)

func TestNayaSkillLifecycleWithinBudgetAndVerifierGate(t *testing.T) {
	pubVer, privVer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBuilder, privBuilder, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := domain.SkillManifest{
		SchemaVersion:   domain.SkillManifestSchema,
		SkillID:         "skill.naya.parse",
		Version:         "1.0.0",
		RuntimeKind:     domain.SkillRuntimeWASM,
		ContentDigest:   domain.Digest(strings.Repeat("a", 64)),
		RequiredSandbox: domain.SandboxWasmWASI,
		Provenance: domain.SkillProvenance{
			BuilderID:      "naya-1",
			SourceRevision: "rev-1",
			BuildDigest:    domain.Digest(strings.Repeat("b", 64)),
		},
		RequestedPermissions: []string{"cap.parse"},
	}
	msg, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(privVer, msg)

	topID := domain.WorkOrderID("wo-root")
	existingOrders := []domain.WorkOrder{
		{ID: topID, RootID: "root-a"},
		{ID: "wo-parent", ParentID: &topID, RootID: "root-a"},
	}

	need := NayaSkillNeed{
		RootID:               "root-a",
		ParentWorkOrderID:    "wo-parent",
		ParentState:          WorkOrderReady,
		ParentRequiredSkills: []string{"skill.naya.parse"},
		AvailableSkills:      map[string]domain.SkillLifecycleRecord{},
		ExistingOrders:       existingOrders,
		ChildWorkOrderID:     "wo-naya-child",
		MissingSkillID:       "skill.naya.parse",
		BuilderID:            "naya-1",
		VerifierID:           "verifier-1",
		PublisherID:          "publisher-1",
		TrustedVerifierKeys: map[string]ed25519.PublicKey{
			"verifier-1": pubVer,
			"naya-1":     pubBuilder,
		},
		AllocationID:  "alloc-1",
		ChildBudgetID: "acct-child-1",
		EstimatedCost: 40,
		ActualCost:    30,
		ParentBudget: domain.BudgetAccount{
			ID:       "acct-1",
			Key:      domain.BudgetKey{RootID: "root-a", ResourceKind: string(domain.ResourceTokens), UnitCode: "token"},
			Counters: domain.BudgetCounters{Granted: 100, Spent: 20},
		},
		MaxSpawnDepth:     2,
		Manifest:          m,
		ManifestSignature: sig,
		GrantedAuthority:  []string{"cap.parse"},
	}

	res, err := ExecuteNayaSkillLifecycle(need)
	if err != nil {
		t.Fatalf("valid NAYA lifecycle failed: %v", err)
	}
	if res.ParentState != WorkOrderReady || res.ChildState != WorkOrderDone || res.RemainingBudget != 50 ||
		res.UpdatedParentBudget.Counters.Spent != 50 || res.SettledAllocation.State != domain.BudgetAllocationSettled {
		t.Fatalf("unexpected NAYA workflow result: %+v", res)
	}

	// Re-using the UPDATED parent budget (Remaining=50) for a second child costing 60 fails closed.
	second := need
	second.ParentBudget = res.UpdatedParentBudget
	second.ChildWorkOrderID = "wo-naya-child-2"
	second.AllocationID = "alloc-2"
	second.ChildBudgetID = "acct-child-2"
	second.EstimatedCost = 60
	second.ActualCost = 50
	if _, err := ExecuteNayaSkillLifecycle(second); !errors.Is(err, ErrNayaDispatchDenied) {
		t.Fatal("exhausted updated parent budget allowed second child")
	}

	// Pre-existing reverse dependency (child -> parent) must fail full-DAG cycle check.
	cyclic := need
	cyclic.ExistingOrders = append(append([]domain.WorkOrder(nil), existingOrders...), domain.WorkOrder{ID: "wo-existing", ParentID: &topID, RootID: "root-a"})
	cyclic.ExistingDeps = []domain.Dependency{{WorkOrderID: "wo-naya-child", DependsOnID: "wo-parent"}}
	if _, err := ExecuteNayaSkillLifecycle(cyclic); !errors.Is(err, ErrNayaDispatchDenied) {
		t.Fatal("DAG cycle through existing dependency was not rejected")
	}

	// Builder signing with builder key under a different verifier label fails closed.
	forgedVerifier := need
	forgedVerifier.VerifierID = "fake-verifier"
	forgedVerifier.TrustedVerifierKeys = map[string]ed25519.PublicKey{
		"fake-verifier": pubBuilder,
		"naya-1":        pubBuilder,
	}
	forgedVerifier.ManifestSignature = ed25519.Sign(privBuilder, msg)
	if _, err := ExecuteNayaSkillLifecycle(forgedVerifier); !errors.Is(err, ErrNayaDispatchDenied) {
		t.Fatal("builder key under aliased verifier label was accepted")
	}

	// No missing skill -> fail closed (do not spawn unnecessary child).
	alreadyHas := need
	alreadyHas.AvailableSkills = map[string]domain.SkillLifecycleRecord{"skill.naya.parse": res.SkillRecord}
	if _, err := ExecuteNayaSkillLifecycle(alreadyHas); !errors.Is(err, ErrNayaDispatchDenied) {
		t.Fatal("spawned NAYA child even when skill was already dispatchable")
	}

	// Multiple missing skills (A and B): generating only A keeps parent BLOCKED.
	multiMissing := need
	multiMissing.ParentRequiredSkills = []string{"skill.naya.parse", "skill.naya.other"}
	multiRes, err := ExecuteNayaSkillLifecycle(multiMissing)
	if err != nil {
		t.Fatalf("multi-skill NAYA run failed: %v", err)
	}
	if multiRes.ParentState != WorkOrderBlocked {
		t.Fatalf("parent resumed READY while second required skill remained missing: %+v", multiRes.ParentState)
	}

	// Completed or unknown parent state cannot be resurrected to READY.
	for _, badState := range []WorkOrderExecutionState{WorkOrderDone, "UNKNOWN"} {
		badParent := need
		badParent.ParentState = badState
		if _, err := ExecuteNayaSkillLifecycle(badParent); !errors.Is(err, ErrNayaDispatchDenied) {
			t.Fatalf("invalid parent state %q was accepted", badState)
		}
	}
}
