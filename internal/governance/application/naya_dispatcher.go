package application

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/governance/domain"
)

var ErrNayaDispatchDenied = errors.New("naya child skill dispatch denied")

type WorkOrderExecutionState string

const (
	WorkOrderReady   WorkOrderExecutionState = "READY"
	WorkOrderBlocked WorkOrderExecutionState = "BLOCKED"
	WorkOrderDone    WorkOrderExecutionState = "DONE"
)

// NayaSkillNeed captures the existing Root WorkOrder graph, parent skill gap,
// parent escrow budget, and trusted verifier keyring needed to run a bounded
// NAYA child-skill generation lifecycle.
type NayaSkillNeed struct {
	RootID               domain.RootID
	ParentWorkOrderID    domain.WorkOrderID
	ParentState          WorkOrderExecutionState
	ParentRequiredSkills []string
	AvailableSkills      map[string]domain.SkillLifecycleRecord
	ExistingOrders       []domain.WorkOrder
	ExistingDeps         []domain.Dependency
	ChildWorkOrderID     domain.WorkOrderID
	MissingSkillID       string
	BuilderID            string
	VerifierID           string
	PublisherID          string
	TrustedVerifierKeys  map[string]ed25519.PublicKey
	AllocationID         string
	ChildBudgetID        string
	EstimatedCost        domain.BudgetAmount
	ActualCost           domain.BudgetAmount
	ParentBudget         domain.BudgetAccount
	MaxSpawnDepth        int
	Manifest             domain.SkillManifest
	ManifestSignature    []byte
	GrantedAuthority     []string
}

type NayaWorkflowResult struct {
	UpdatedOrders       []domain.WorkOrder
	UpdatedDeps         []domain.Dependency
	ChildOrder          domain.WorkOrder
	ChildState          WorkOrderExecutionState
	ParentState         WorkOrderExecutionState
	Dependency          domain.Dependency
	SkillRecord         domain.SkillLifecycleRecord
	UpdatedParentBudget domain.BudgetAccount
	SettledAllocation   domain.BudgetAllocation
	RemainingBudget     domain.BudgetAmount
}

func computeOrderDepth(orders []domain.WorkOrder, target domain.WorkOrderID, root domain.RootID) (int, error) {
	byID := make(map[domain.WorkOrderID]domain.WorkOrder, len(orders))
	for _, o := range orders {
		byID[o.ID] = o
	}
	cur, ok := byID[target]
	if !ok || cur.RootID != root {
		return 0, fmt.Errorf("%w: parent work order %q not found in root %q", ErrNayaDispatchDenied, target, root)
	}
	depth := 0
	seen := map[domain.WorkOrderID]bool{}
	for cur.ParentID != nil {
		if seen[cur.ID] {
			return 0, fmt.Errorf("%w: ownership cycle at %q", ErrNayaDispatchDenied, cur.ID)
		}
		seen[cur.ID] = true
		parent, ok := byID[*cur.ParentID]
		if !ok {
			return 0, fmt.Errorf("%w: missing ancestor %q", ErrNayaDispatchDenied, *cur.ParentID)
		}
		depth++
		cur = parent
	}
	return depth, nil
}

// ExecuteNayaSkillLifecycle detects a genuine missing-skill dependency on the
// parent WorkOrder, inserts a child NAYA WorkOrder into the full existing Tree/DAG
// within MaxSpawnDepth, escrows and settles BudgetAccount counters, verifies the
// manifest using a trusted verifier keyring (excluding Builder), publishes/canaries
// the skill, and transitions the parent from BLOCKED back to READY.
func ExecuteNayaSkillLifecycle(need NayaSkillNeed) (NayaWorkflowResult, error) {
	if need.RootID.Validate() != nil || need.ParentWorkOrderID.Validate() != nil || need.ChildWorkOrderID.Validate() != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: invalid work order or root ID", ErrNayaDispatchDenied)
	}
	if need.ParentState != WorkOrderReady && need.ParentState != WorkOrderBlocked {
		return NayaWorkflowResult{}, fmt.Errorf("%w: invalid parent state %q", ErrNayaDispatchDenied, need.ParentState)
	}
	if need.MaxSpawnDepth < 1 {
		return NayaWorkflowResult{}, fmt.Errorf("%w: invalid max spawn depth", ErrNayaDispatchDenied)
	}
	if need.EstimatedCost <= 0 || need.ActualCost < 0 || need.ActualCost > need.EstimatedCost {
		return NayaWorkflowResult{}, fmt.Errorf("%w: invalid estimated/actual cost", ErrNayaDispatchDenied)
	}
	if need.ParentBudget.Key.RootID != string(need.RootID) {
		return NayaWorkflowResult{}, fmt.Errorf("%w: budget root %q != work order root %q", ErrNayaDispatchDenied, need.ParentBudget.Key.RootID, need.RootID)
	}
	if err := need.ParentBudget.Validate(); err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}

	// 1. Missing-skill detection: verify ParentRequiredSkills actually has a missing/undispatchable skill matching MissingSkillID.
	missingSet := map[string]bool{}
	for _, reqSkill := range need.ParentRequiredSkills {
		rec, ok := need.AvailableSkills[reqSkill]
		if !ok || domain.CanDispatchSkill(rec) != nil {
			missingSet[reqSkill] = true
		}
	}
	if !missingSet[need.MissingSkillID] || need.Manifest.SkillID != need.MissingSkillID {
		return NayaWorkflowResult{}, fmt.Errorf("%w: skill %q is not missing or manifest ID mismatches", ErrNayaDispatchDenied, need.MissingSkillID)
	}

	// 2. Depth & full-DAG insertion validation against existing WorkOrders/Dependencies.
	parentDepth, err := computeOrderDepth(need.ExistingOrders, need.ParentWorkOrderID, need.RootID)
	if err != nil {
		return NayaWorkflowResult{}, err
	}
	if parentDepth+1 > need.MaxSpawnDepth {
		return NayaWorkflowResult{}, fmt.Errorf("%w: child depth %d exceeds MaxSpawnDepth %d", ErrNayaDispatchDenied, parentDepth+1, need.MaxSpawnDepth)
	}
	parentID := need.ParentWorkOrderID
	childOrder := domain.WorkOrder{ID: need.ChildWorkOrderID, ParentID: &parentID, RootID: need.RootID}
	nextOrders := append(append([]domain.WorkOrder(nil), need.ExistingOrders...), childOrder)
	if err := domain.ValidateWorkOrderTree(nextOrders); err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}
	dep := domain.Dependency{WorkOrderID: need.ParentWorkOrderID, DependsOnID: need.ChildWorkOrderID}
	nextDeps := append(append([]domain.Dependency(nil), need.ExistingDeps...), dep)
	if err := domain.ValidateDependencies(nextOrders, nextDeps); err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}

	// 3. Real Escrow delegation on ParentBudget.
	escrowedParent, childBudget, allocation, err := need.ParentBudget.Delegate(
		need.AllocationID,
		need.ChildBudgetID,
		need.ParentBudget.Key,
		need.EstimatedCost,
	)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: budget delegation failed: %v", ErrNayaDispatchDenied, err)
	}

	// Parent enters BLOCKED while waiting for NAYA child WorkOrder.
	parentState := WorkOrderBlocked

	// 4. Verify Builder identity consistency and trusted Verifier key binding.
	if need.BuilderID == "" || need.BuilderID != need.Manifest.Provenance.BuilderID {
		return NayaWorkflowResult{}, fmt.Errorf("%w: builder ID mismatch with manifest provenance", ErrNayaDispatchDenied)
	}
	if need.VerifierID == need.BuilderID || need.PublisherID == need.BuilderID {
		return NayaWorkflowResult{}, fmt.Errorf("%w: builder cannot act as verifier or publisher", ErrNayaDispatchDenied)
	}
	verifierPubKey, ok := need.TrustedVerifierKeys[need.VerifierID]
	if !ok || len(verifierPubKey) != ed25519.PublicKeySize {
		return NayaWorkflowResult{}, fmt.Errorf("%w: untrusted verifier %q", ErrNayaDispatchDenied, need.VerifierID)
	}
	if builderPub, hasBuilder := need.TrustedVerifierKeys[need.BuilderID]; hasBuilder && bytes.Equal(builderPub, verifierPubKey) {
		return NayaWorkflowResult{}, fmt.Errorf("%w: verifier shares builder public key", ErrNayaDispatchDenied)
	}

	// 5. Stage -> Independent Verify -> Publish -> Canary.
	staged, err := domain.StageSkill(need.Manifest)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}
	verified, err := domain.VerifyStagedSkill(staged, need.VerifierID, need.ManifestSignature, verifierPubKey, need.GrantedAuthority)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}
	published, err := domain.PublishVerifiedSkill(verified, need.PublisherID)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}
	canary, err := domain.CanarySkill(published)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}
	if err := domain.CanDispatchSkill(canary); err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}

	// 6. Reserve, settle actual cost, close child budget, and settle parent escrow.
	childReserved, err := childBudget.Reserve(need.ActualCost)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: child reserve failed: %v", ErrNayaDispatchDenied, err)
	}
	childSettled, err := childReserved.SettleReservation(need.ActualCost, need.ActualCost)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: child settle failed: %v", ErrNayaDispatchDenied, err)
	}
	childClosed, err := childSettled.CloseChild(false)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: child close failed: %v", ErrNayaDispatchDenied, err)
	}
	finalParentBudget, settledAlloc, err := escrowedParent.SettleAllocation(childClosed, allocation, false)
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: parent settle failed: %v", ErrNayaDispatchDenied, err)
	}
	remaining, err := finalParentBudget.Counters.Available()
	if err != nil {
		return NayaWorkflowResult{}, fmt.Errorf("%w: %v", ErrNayaDispatchDenied, err)
	}

	// Only transition parent BLOCKED -> READY if ALL required skills are now dispatchable.
	updatedSkills := make(map[string]domain.SkillLifecycleRecord, len(need.AvailableSkills)+1)
	for k, v := range need.AvailableSkills {
		updatedSkills[k] = v
	}
	updatedSkills[need.MissingSkillID] = canary
	allReady := true
	for _, reqSkill := range need.ParentRequiredSkills {
		rec, ok := updatedSkills[reqSkill]
		if !ok || domain.CanDispatchSkill(rec) != nil {
			allReady = false
			break
		}
	}
	childState := WorkOrderDone
	if parentState == WorkOrderBlocked && childState == WorkOrderDone && allReady {
		parentState = WorkOrderReady
	}

	return NayaWorkflowResult{
		UpdatedOrders:       nextOrders,
		UpdatedDeps:         nextDeps,
		ChildOrder:          childOrder,
		ChildState:          childState,
		ParentState:         parentState,
		Dependency:          dep,
		SkillRecord:         canary,
		UpdatedParentBudget: finalParentBudget,
		SettledAllocation:   settledAlloc,
		RemainingBudget:     remaining,
	}, nil
}
