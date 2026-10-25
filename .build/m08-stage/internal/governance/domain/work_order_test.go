package domain

import (
	"math"
	"testing"
)

func order(id, root string, parent *WorkOrderID) WorkOrder {
	return WorkOrder{ID: WorkOrderID(id), RootID: RootID(root), ParentID: parent}
}

func parent(id string) *WorkOrderID { v := WorkOrderID(id); return &v }

func TestValidateWorkOrderTree(t *testing.T) {
	tests := []struct {
		name    string
		orders  []WorkOrder
		wantErr bool
	}{
		{"valid ownership tree", []WorkOrder{order("r", "r", nil), order("a", "r", parent("r")), order("b", "r", parent("a"))}, false},
		{"root work order ID differs from root ID", []WorkOrder{order("root-node", "root-id", nil), order("child", "root-id", parent("root-node"))}, false},
		{"multiple top-level nodes for root", []WorkOrder{order("r1", "r", nil), order("r2", "r", nil)}, true},
		{"duplicate IDs", []WorkOrder{order("r", "r", nil), order("r", "r", nil)}, true},
		{"missing parent", []WorkOrder{order("r", "r", nil), order("a", "r", parent("missing"))}, true},
		{"root mismatch", []WorkOrder{order("r", "r", nil), order("a", "other", parent("r"))}, true},
		{"inconsistent root", []WorkOrder{order("r", "r", nil), order("a", "r", parent("b")), order("b", "b", nil)}, true},
		{"ownership cycle", []WorkOrder{order("r", "r", nil), order("a", "r", parent("b")), order("b", "r", parent("a"))}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWorkOrderTree(tt.orders)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateWorkOrderTree() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWorkOrderGraphValidate(t *testing.T) {
	root := order("root", "root", nil)
	childA := order("a", "root", parent("root"))
	childB := order("b", "root", parent("root"))
	valid := WorkOrderGraph{
		Orders:       []WorkOrder{root, childA, childB},
		Dependencies: []Dependency{{WorkOrderID: "b", DependsOnID: "a"}},
		Attempts:     []Attempt{{ID: "attempt-1", WorkOrderID: "a", Number: 1}, {ID: "attempt-2", WorkOrderID: "a", Number: 2}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid graph rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*WorkOrderGraph)
	}{
		{"empty graph", func(g *WorkOrderGraph) { g.Orders = nil }},
		{"dependency cycle", func(g *WorkOrderGraph) {
			g.Dependencies = append(g.Dependencies, Dependency{WorkOrderID: "a", DependsOnID: "b"})
		}},
		{"cross-root dependency", func(g *WorkOrderGraph) {
			g.Orders = append(g.Orders, order("other", "other-root", nil))
			g.Dependencies = append(g.Dependencies, Dependency{WorkOrderID: "root", DependsOnID: "other"})
		}},
		{"mixed roots", func(g *WorkOrderGraph) {
			g.Orders = append(g.Orders, order("other", "other-root", nil))
		}},
		{"attempt references unknown order", func(g *WorkOrderGraph) {
			g.Attempts = append(g.Attempts, Attempt{ID: "orphan", WorkOrderID: "missing", Number: 1})
		}},
		{"duplicate attempt number", func(g *WorkOrderGraph) {
			g.Attempts = append(g.Attempts, Attempt{ID: "attempt-3", WorkOrderID: "a", Number: 1})
		}},
		{"duplicate attempt ID", func(g *WorkOrderGraph) {
			g.Attempts = append(g.Attempts, Attempt{ID: "attempt-1", WorkOrderID: "b", Number: 1})
		}},
		{"attempt exceeds bigint", func(g *WorkOrderGraph) {
			g.Attempts = append(g.Attempts, Attempt{ID: "attempt-max", WorkOrderID: "a", Number: uint64(math.MaxInt64) + 1})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := valid
			graph.Orders = append([]WorkOrder(nil), valid.Orders...)
			graph.Dependencies = append([]Dependency(nil), valid.Dependencies...)
			graph.Attempts = append([]Attempt(nil), valid.Attempts...)
			tt.edit(&graph)
			if err := graph.Validate(); err == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
}

func TestValidateDependencies(t *testing.T) {
	orders := []WorkOrder{order("r", "r", nil), order("a", "r", parent("r")), order("b", "r", parent("r")), order("other", "other", nil)}
	tests := []struct {
		name         string
		dependencies []Dependency
		input        []WorkOrder
		wantErr      bool
	}{
		{"valid execution DAG", []Dependency{{WorkOrderID: "a", DependsOnID: "r"}, {WorkOrderID: "b", DependsOnID: "a"}}, nil, false},
		{"execution edge independent of ownership", []Dependency{{WorkOrderID: "a", DependsOnID: "b"}}, nil, false},
		{"independent tasks", nil, nil, false},
		{"cross-root edge", []Dependency{{WorkOrderID: "a", DependsOnID: "other"}}, nil, true},
		{"self edge", []Dependency{{WorkOrderID: "a", DependsOnID: "a"}}, nil, true},
		{"cycle", []Dependency{{WorkOrderID: "a", DependsOnID: "b"}, {WorkOrderID: "b", DependsOnID: "a"}}, nil, true},
		{"unknown node", []Dependency{{WorkOrderID: "a", DependsOnID: "missing"}}, nil, true},
		{"invalid work order ID", nil, []WorkOrder{order(" bad", "r", nil)}, true},
		{"invalid root ID", nil, []WorkOrder{order("a", " bad", nil)}, true},
		{"duplicate work order IDs", nil, []WorkOrder{order("a", "r", nil), order("a", "r", nil)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := orders
			if tt.input != nil {
				input = tt.input
			}
			err := ValidateDependencies(input, tt.dependencies)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDependencies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAttemptIsValue(t *testing.T) {
	a := Attempt{ID: "attempt-1", WorkOrderID: "job", Number: 1}
	if a.ID != "attempt-1" || a.WorkOrderID != "job" || a.Number != 1 {
		t.Fatalf("unexpected attempt value: %#v", a)
	}
}

func TestAttemptValidate(t *testing.T) {
	tests := []struct {
		name    string
		attempt Attempt
		wantErr bool
	}{
		{"valid", Attempt{ID: "attempt-1", WorkOrderID: "job", Number: 1}, false},
		{"empty ID", Attempt{WorkOrderID: "job", Number: 1}, true},
		{"whitespace ID", Attempt{ID: " attempt-1", WorkOrderID: "job", Number: 1}, true},
		{"invalid work order ID", Attempt{ID: "attempt-1", WorkOrderID: " bad", Number: 1}, true},
		{"zero number", Attempt{ID: "attempt-1", WorkOrderID: "job"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attempt.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Attempt.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
