package domain

import (
	"fmt"
	"math"
)

// WorkOrderGraph is the complete persisted scheduling graph for one Root.
// Ownership (ParentID) and execution ordering (Dependencies) are independent.
type WorkOrderGraph struct {
	Orders       []WorkOrder
	Dependencies []Dependency
	Attempts     []Attempt
}

// Validate rejects malformed ownership trees, cyclic/cross-Root execution DAGs,
// and attempts that are not uniquely attributable to an order and sequence.
func (g WorkOrderGraph) Validate() error {
	if len(g.Orders) == 0 {
		return fmt.Errorf("work order graph must contain at least one order")
	}
	rootID := g.Orders[0].RootID
	for _, order := range g.Orders[1:] {
		if order.RootID != rootID {
			return fmt.Errorf("work order graph mixes Roots %q and %q", rootID, order.RootID)
		}
	}
	if err := ValidateWorkOrderTree(g.Orders); err != nil {
		return fmt.Errorf("validate work order tree: %w", err)
	}
	if err := ValidateDependencies(g.Orders, g.Dependencies); err != nil {
		return fmt.Errorf("validate work order dependencies: %w", err)
	}

	orders := make(map[WorkOrderID]struct{}, len(g.Orders))
	for _, order := range g.Orders {
		orders[order.ID] = struct{}{}
	}
	attemptIDs := make(map[string]struct{}, len(g.Attempts))
	attemptNumbers := make(map[WorkOrderID]map[uint64]struct{})
	for _, attempt := range g.Attempts {
		if err := attempt.Validate(); err != nil {
			return fmt.Errorf("validate attempt: %w", err)
		}
		if _, ok := orders[attempt.WorkOrderID]; !ok {
			return fmt.Errorf("attempt %q references unknown work order %q", attempt.ID, attempt.WorkOrderID)
		}
		if _, ok := attemptIDs[attempt.ID]; ok {
			return fmt.Errorf("duplicate attempt ID %q", attempt.ID)
		}
		attemptIDs[attempt.ID] = struct{}{}
		if attemptNumbers[attempt.WorkOrderID] == nil {
			attemptNumbers[attempt.WorkOrderID] = make(map[uint64]struct{})
		}
		if _, ok := attemptNumbers[attempt.WorkOrderID][attempt.Number]; ok {
			return fmt.Errorf("duplicate attempt number %d for work order %q", attempt.Number, attempt.WorkOrderID)
		}
		attemptNumbers[attempt.WorkOrderID][attempt.Number] = struct{}{}
		if attempt.Number > math.MaxInt64 {
			return fmt.Errorf("attempt number %d exceeds PostgreSQL bigint range", attempt.Number)
		}
	}
	return nil
}
