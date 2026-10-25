package domain

import "fmt"

type WorkOrderID string

func (id WorkOrderID) Validate() error { return validateID(string(id)) }

// validateWorkOrders checks identity and root values shared by both tree and
// execution-DAG validation. It intentionally does not inspect ParentID.
func validateWorkOrders(orders []WorkOrder) (map[WorkOrderID]WorkOrder, map[RootID]struct{}, error) {
	byID := make(map[WorkOrderID]WorkOrder, len(orders))
	roots := make(map[RootID]struct{}, len(orders))
	for _, order := range orders {
		if err := order.ID.Validate(); err != nil {
			return nil, nil, err
		}
		if err := order.RootID.Validate(); err != nil {
			return nil, nil, err
		}
		if _, exists := byID[order.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate work order ID %q", order.ID)
		}
		byID[order.ID] = order
		roots[order.RootID] = struct{}{}
	}
	return byID, roots, nil
}

// Validate checks the identity and sequence number of this execution attempt.
func (a Attempt) Validate() error {
	if err := validateID(a.ID); err != nil {
		return fmt.Errorf("invalid attempt ID: %w", err)
	}
	if err := a.WorkOrderID.Validate(); err != nil {
		return fmt.Errorf("invalid attempt work order ID: %w", err)
	}
	if a.Number == 0 {
		return fmt.Errorf("attempt number must be greater than zero")
	}
	return nil
}

// WorkOrder describes ownership separately from execution ordering. A nil
// ParentID identifies the root WorkOrder; RootID is shared by its descendants.
type WorkOrder struct {
	ID       WorkOrderID
	ParentID *WorkOrderID
	RootID   RootID
}

// Attempt identifies one execution try for a WorkOrder. It is a value, not a
// mutable execution policy or lease.
type Attempt struct {
	ID          string
	WorkOrderID WorkOrderID
	Number      uint64
}

// Dependency is an execution edge: WorkOrderID cannot execute until DependsOnID
// is complete. It does not express ownership.
type Dependency struct {
	WorkOrderID WorkOrderID
	DependsOnID WorkOrderID
}

// ValidateWorkOrderTree checks unique IDs, parent membership, root membership,
// and that every ownership chain terminates at its declared root.
func ValidateWorkOrderTree(orders []WorkOrder) error {
	byID, roots, err := validateWorkOrders(orders)
	if err != nil {
		return err
	}
	topLevel := make(map[RootID]WorkOrderID)
	for _, order := range orders {
		if order.ParentID == nil {
			if _, exists := topLevel[order.RootID]; exists {
				return fmt.Errorf("multiple top-level work orders for root %q", order.RootID)
			}
			topLevel[order.RootID] = order.ID
			continue
		}
		parent, ok := byID[*order.ParentID]
		if !ok {
			return fmt.Errorf("parent %q of work order %q not found", *order.ParentID, order.ID)
		}
		if parent.RootID != order.RootID {
			return fmt.Errorf("parent %q and work order %q have different roots", parent.ID, order.ID)
		}
	}
	for root := range roots {
		if _, exists := topLevel[root]; !exists {
			return fmt.Errorf("root %q has no top-level work order", root)
		}
	}
	// Following parent pointers detects cycles and disconnected ownership chains.
	for _, order := range orders {
		seen := make(map[WorkOrderID]bool)
		current := order
		for current.ParentID != nil {
			if seen[current.ID] {
				return fmt.Errorf("ownership cycle at %q", current.ID)
			}
			seen[current.ID] = true
			current = byID[*current.ParentID]
		}
		if rootID, exists := topLevel[order.RootID]; !exists || current.ID != rootID {
			return fmt.Errorf("work order %q does not descend from declared root %q", order.ID, order.RootID)
		}
	}
	return nil
}

// ValidateDependencies checks that execution edges reference known WorkOrders,
// remain within one Root, and form a DAG. Independent WorkOrders are allowed.
func ValidateDependencies(orders []WorkOrder, dependencies []Dependency) error {
	byID, _, err := validateWorkOrders(orders)
	if err != nil {
		return err
	}
	adj := make(map[WorkOrderID][]WorkOrderID, len(orders))
	seenEdges := make(map[Dependency]bool, len(dependencies))
	for _, edge := range dependencies {
		from, fromOK := byID[edge.WorkOrderID]
		to, toOK := byID[edge.DependsOnID]
		if !fromOK || !toOK {
			return fmt.Errorf("dependency references unknown work order")
		}
		if edge.WorkOrderID == edge.DependsOnID {
			return fmt.Errorf("work order %q depends on itself", edge.WorkOrderID)
		}
		if from.RootID != to.RootID {
			return fmt.Errorf("dependency %q -> %q crosses roots", edge.WorkOrderID, edge.DependsOnID)
		}
		if seenEdges[edge] {
			return fmt.Errorf("duplicate dependency %q -> %q", edge.WorkOrderID, edge.DependsOnID)
		}
		seenEdges[edge] = true
		adj[edge.DependsOnID] = append(adj[edge.DependsOnID], edge.WorkOrderID)
	}
	state := make(map[WorkOrderID]uint8, len(orders))
	var visit func(WorkOrderID) bool
	visit = func(id WorkOrderID) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		for _, next := range adj[id] {
			if !visit(next) {
				return false
			}
		}
		state[id] = 2
		return true
	}
	for id := range byID {
		if !visit(id) {
			return fmt.Errorf("execution dependency cycle detected")
		}
	}
	return nil
}
