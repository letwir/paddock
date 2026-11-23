package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/letwir/paddock/internal/governance/domain"
)

var ErrStewardRejected = errors.New("steward proposal rejected")

// StewardPlanner is the untrusted/LLM or mock decomposition producer.
// It can only emit raw proposal JSON; it holds no DB or authority handles.
type StewardPlanner interface {
	ProposeDecomposition(ctx context.Context, prompt string) ([]byte, error)
}

// StewardProposalDraft is a single proposed WorkOrder in a decomposition.
// Lease, Authority, Epoch, and DONE status cannot be expressed here.
type StewardProposalDraft struct {
	LocalID              string   `json:"local_id"`
	ParentLocalID        string   `json:"parent_local_id,omitempty"`
	Title                string   `json:"title"`
	DependsOnLocalIDs    []string `json:"depends_on_local_ids,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
}

// StewardProposalPayload is the strict schema accepted from StewardPlanner.
type StewardProposalPayload struct {
	SchemaVersion string                 `json:"schema_version"`
	RootID        domain.RootID          `json:"root_id"`
	Orders        []StewardProposalDraft `json:"orders"`
}

const StewardProposalSchemaVersion = "paddock.steward-proposal/1"

// StewardSubmission is the validated, non-authoritative proposal handed to
// Coordinator intake. Status is always forced to "PROPOSED".
type StewardSubmission struct {
	RootID       domain.RootID
	InitialState string
	Orders       []domain.WorkOrder
	Dependencies []domain.Dependency
	Drafts       []StewardProposalDraft
}

type StewardReceipt struct {
	ProposalID string
	State      string
	OrderCount int
}

// StewardProposalStore is a deliberately narrow write seam: it accepts only
// unprivileged WorkOrder proposals and exposes zero Lease/Authority/DONE APIs.
type StewardProposalStore interface {
	SubmitProposal(ctx context.Context, submission StewardSubmission) (StewardReceipt, error)
}

type StewardAdapter struct {
	planner StewardPlanner
	store   StewardProposalStore
}

func NewStewardAdapter(planner StewardPlanner, store StewardProposalStore) (*StewardAdapter, error) {
	if planner == nil || store == nil {
		return nil, fmt.Errorf("%w: uninitialized steward dependencies", ErrStewardRejected)
	}
	return &StewardAdapter{planner: planner, store: store}, nil
}

// ProposeWorkOrders converts untrusted Steward/LLM output into a validated,
// acyclic WorkOrder proposal without ever permitting Lease, Authority, or DONE writes.
func (a *StewardAdapter) ProposeWorkOrders(ctx context.Context, userGoal string) (StewardReceipt, error) {
	if a == nil || a.planner == nil || a.store == nil {
		return StewardReceipt{}, fmt.Errorf("%w: adapter not initialized", ErrStewardRejected)
	}
	if ctx == nil || strings.TrimSpace(userGoal) == "" {
		return StewardReceipt{}, fmt.Errorf("%w: invalid goal or context", ErrStewardRejected)
	}
	raw, err := a.planner.ProposeDecomposition(ctx, userGoal)
	if err != nil {
		return StewardReceipt{}, fmt.Errorf("%w: planner failed: %v", ErrStewardRejected, err)
	}

	var payload StewardProposalPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return StewardReceipt{}, fmt.Errorf("%w: disallowed or malformed proposal JSON: %v", ErrStewardRejected, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return StewardReceipt{}, fmt.Errorf("%w: trailing JSON data", ErrStewardRejected)
	}
	if payload.SchemaVersion != StewardProposalSchemaVersion || payload.RootID.Validate() != nil || len(payload.Orders) == 0 {
		return StewardReceipt{}, fmt.Errorf("%w: invalid proposal header or empty orders", ErrStewardRejected)
	}

	orders := make([]domain.WorkOrder, 0, len(payload.Orders))
	for _, d := range payload.Orders {
		if strings.TrimSpace(d.LocalID) == "" || strings.TrimSpace(d.Title) == "" {
			return StewardReceipt{}, fmt.Errorf("%w: empty order ID or title", ErrStewardRejected)
		}
		woID := domain.WorkOrderID(d.LocalID)
		var parentPtr *domain.WorkOrderID
		if d.ParentLocalID != "" {
			pid := domain.WorkOrderID(d.ParentLocalID)
			parentPtr = &pid
		}
		orders = append(orders, domain.WorkOrder{
			ID:       woID,
			ParentID: parentPtr,
			RootID:   payload.RootID,
		})
	}
	if err := domain.ValidateWorkOrderTree(orders); err != nil {
		return StewardReceipt{}, fmt.Errorf("%w: invalid ownership tree: %v", ErrStewardRejected, err)
	}

	var deps []domain.Dependency
	for _, d := range payload.Orders {
		for _, depID := range d.DependsOnLocalIDs {
			deps = append(deps, domain.Dependency{
				WorkOrderID: domain.WorkOrderID(d.LocalID),
				DependsOnID: domain.WorkOrderID(depID),
			})
		}
	}
	if err := domain.ValidateDependencies(orders, deps); err != nil {
		return StewardReceipt{}, fmt.Errorf("%w: invalid execution DAG: %v", ErrStewardRejected, err)
	}

	return a.store.SubmitProposal(ctx, StewardSubmission{
		RootID:       payload.RootID,
		InitialState: "PROPOSED",
		Orders:       orders,
		Dependencies: deps,
		Drafts:       append([]StewardProposalDraft(nil), payload.Orders...),
	})
}
