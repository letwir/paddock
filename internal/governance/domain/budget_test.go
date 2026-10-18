package domain

import (
	"math"
	"testing"
)

func key(unit string) BudgetKey {
	return BudgetKey{RootID: "root", ResourceKind: string(ResourceTokens), UnitCode: unit}
}

func TestDelegateRejectsStorageResourceKeyMismatch(t *testing.T) {
	parentKey := BudgetKey{RootID: "root", ResourceKind: string(ResourceStorageBytes), UnitCode: "byte"}
	parent := BudgetAccount{ID: "parent", Key: parentKey, Counters: BudgetCounters{Granted: 20}}
	wrongResource := parentKey
	wrongResource.ResourceKind = string(ResourceTokens)
	wrongResource.UnitCode = "token"
	if _, _, _, err := parent.Delegate("alloc", "child", wrongResource, 5); err == nil {
		t.Fatal("delegation with mismatched resource key accepted")
	}
}

func TestStorageBytesBudgetKeyRequiresByteUnit(t *testing.T) {
	for _, tc := range []struct {
		resource ResourceKind
		unit     string
	}{{ResourceCurrency, "USD"}, {ResourceTokens, "token"}, {ResourceCompute, "second"}, {ResourceStorageBytes, "byte"}} {
		if err := (BudgetKey{RootID: "root", ResourceKind: string(tc.resource), UnitCode: tc.unit}).Validate(); err != nil {
			t.Errorf("%s/%s rejected: %v", tc.resource, tc.unit, err)
		}
	}
	valid := BudgetKey{RootID: "root", ResourceKind: string(ResourceStorageBytes), UnitCode: "byte"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("STORAGE_BYTES/byte rejected: %v", err)
	}
	for _, unit := range []string{"bytes", "KiB", ""} {
		t.Run(unit, func(t *testing.T) {
			invalid := valid
			invalid.UnitCode = unit
			if err := invalid.Validate(); err == nil {
				t.Fatalf("STORAGE_BYTES/%q accepted", unit)
			}
		})
	}

	account := BudgetAccount{ID: "storage", Key: valid, Counters: BudgetCounters{Granted: 1024}}
	if _, _, _, err := account.Delegate("storage-allocation", "child", BudgetKey{
		RootID: "root", ResourceKind: string(ResourceTokens), UnitCode: "token",
	}, 512); err == nil {
		t.Fatal("STORAGE_BYTES delegated to a different resource kind")
	}
	wrongUnit := valid
	wrongUnit.UnitCode = "KiB"
	if _, _, _, err := account.Delegate("storage-allocation", "child", wrongUnit, 512); err == nil {
		t.Fatal("STORAGE_BYTES delegated to a different unit")
	}
	reserved, err := account.Reserve(512)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := reserved.SettleReservation(512, 256)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Counters != (BudgetCounters{Granted: 1024, Spent: 256}) {
		t.Fatalf("storage balance was converted: got %+v", settled.Counters)
	}
}

func TestBudgetInvariantAndBoundaries(t *testing.T) {
	if (BudgetCounters{Granted: math.MaxInt64, Spent: math.MaxInt64, Reserved: 1}).Validate() == nil {
		t.Fatal("accepted over-limit invariant")
	}
	if got, err := (BudgetCounters{Granted: math.MaxInt64, Spent: math.MaxInt64}).Available(); err != nil || got != 0 {
		t.Fatalf("available=(%d,%v)", got, err)
	}
	if _, err := addAmount(BudgetAmount(math.MaxInt64), 1); err == nil {
		t.Fatal("overflow accepted")
	}
	if (BudgetCounters{Granted: 1, Spent: -1}).Validate() == nil {
		t.Fatal("negative accepted")
	}
}

func TestBudgetKeyUnitCodeUnicodeValidation(t *testing.T) {
	valid := []string{"token", "m/s", "日本語", "é", "unit name"}
	for _, unit := range valid {
		t.Run(unit, func(t *testing.T) {
			if err := key(unit).Validate(); err != nil {
				t.Fatalf("valid unit rejected: %v", err)
			}
		})
	}
	invalid := []string{"", " e", "e ", "\u00a0token", "token\u3000", "e\u0301", "a\x00b", "a\u0085b"}
	for _, unit := range invalid {
		t.Run("invalid", func(t *testing.T) {
			if err := key(unit).Validate(); err == nil {
				t.Fatalf("invalid unit accepted: %q", unit)
			}
		})
	}
}

func TestBudgetAccountReservationsRejectTerminalAndAreImmutable(t *testing.T) {
	a := BudgetAccount{ID: "a", Key: key("token"), Counters: BudgetCounters{Granted: 10}}
	reserved, err := a.Reserve(8)
	if err != nil {
		t.Fatal(err)
	}
	if a.Counters.Reserved != 0 || reserved.Counters.Reserved != 8 {
		t.Fatal("Reserve mutated input or failed")
	}
	if _, err = reserved.Reserve(3); err == nil {
		t.Fatal("over reservation")
	}
	settled, err := reserved.SettleReservation(8, 5)
	if err != nil {
		t.Fatal(err)
	}
	if settled.Counters.Spent != 5 || settled.Counters.Reserved != 0 {
		t.Fatalf("bad counters: %+v", settled.Counters)
	}
	closed, err := settled.CloseChild(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = closed.Reserve(0); err == nil {
		t.Fatal("terminal reserve accepted")
	}
	if _, err = closed.SettleReservation(0, 0); err == nil {
		t.Fatal("terminal reservation settlement accepted")
	}
	if _, err = closed.CloseChild(false); err == nil {
		t.Fatal("terminal close repeated")
	}
}

func TestDelegateRequiresStrictChildIDAndUniqueAllocationID(t *testing.T) {
	p := BudgetAccount{ID: "parent", Key: key("token"), Counters: BudgetCounters{Granted: 20}}
	for _, child := range []string{" child", "child ", "\u00a0child", "child\u3000", ""} {
		if _, _, _, err := p.Delegate("alloc", child, p.Key, 5); err == nil {
			t.Fatalf("accepted child id %q", child)
		}
	}
	if _, _, _, err := p.Delegate(" \u00a0 ", "child", p.Key, 5); err == nil {
		t.Fatal("accepted invalid allocation id")
	}
	p2, child, allocation, err := p.Delegate("allocation-1", "child", p.Key, 12)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Counters.Delegated != 12 || child.Counters.Granted != 12 || child.AllocationID != allocation.AllocationID || allocation.State != BudgetAllocationOpen {
		t.Fatalf("bad escrow: %+v %+v %+v", p2, child, allocation)
	}
}

func TestSettleRequiresExactAllocationIdentity(t *testing.T) {
	k := key("token")
	p := BudgetAccount{ID: "parent", Key: k, Counters: BudgetCounters{Granted: 30}}
	p, c1, a1, err := p.Delegate("allocation-1", "child-1", k, 10)
	if err != nil {
		t.Fatal(err)
	}
	p, c2, a2, err := p.Delegate("allocation-2", "child-2", k, 10)
	if err != nil {
		t.Fatal(err)
	}
	c1.Counters.Spent = 4
	c1, err = c1.CloseChild(false)
	if err != nil {
		t.Fatal(err)
	}
	c2.Counters.Spent = 3
	c2, err = c2.CloseChild(false)
	if err != nil {
		t.Fatal(err)
	}
	// Aggregate delegated funds are sufficient, but sibling substitution is not.
	if _, _, err = p.SettleAllocation(c1, a2, false); err == nil {
		t.Fatal("sibling allocation substituted")
	}
	foreignParent := p
	foreignParent.ID = "foreign"
	if _, _, err = foreignParent.SettleAllocation(c1, a1, false); err == nil {
		t.Fatal("foreign parent settled allocation")
	}
	if _, _, err = p.SettleAllocation(c2, a1, false); err == nil {
		t.Fatal("wrong child settled allocation")
	}
	p, settled, err := p.SettleAllocation(c1, a1, false)
	if err != nil {
		t.Fatal(err)
	}
	if settled.State != BudgetAllocationSettled || p.Counters.Delegated != 10 || p.Counters.Spent != 4 {
		t.Fatalf("bad settlement: %+v %+v", p.Counters, settled)
	}
	before := p
	if _, _, err = p.SettleAllocation(c1, settled, false); err == nil {
		t.Fatal("duplicate settled allocation replay accepted")
	}
	if p != before {
		t.Fatal("rejected settlement mutated parent")
	}
	if _, _, err = p.SettleAllocation(c2, a2, false); err != nil {
		t.Fatalf("second exact allocation denied: %v", err)
	}
}

func TestSettleRequiresExactGrantTerminalChildAndClosedSubtree(t *testing.T) {
	k := key("token")
	p := BudgetAccount{ID: "parent", Key: k, Counters: BudgetCounters{Granted: 20}}
	p, c, alloc, err := p.Delegate("alloc", "child", k, 10)
	if err != nil {
		t.Fatal(err)
	}
	badAmount := alloc
	badAmount.Amount = 9
	closed, err := c.CloseChild(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.SettleAllocation(closed, badAmount, false); err == nil {
		t.Fatal("allocation amount mismatch accepted")
	}
	if _, _, err = p.SettleAllocation(c, alloc, false); err == nil {
		t.Fatal("non-terminal child settled")
	}
	if _, _, err = p.SettleAllocation(closed, alloc, true); err == nil {
		t.Fatal("open descendant subtree settled")
	}
	reserved := c
	reserved.Counters.Reserved = 1
	if _, _, err = p.SettleAllocation(reserved, alloc, false); err == nil {
		t.Fatal("reserved child settled")
	}
}

func TestParentCannotCloseWithChildrenOrCommitments(t *testing.T) {
	k := key("token")
	p := BudgetAccount{ID: "parent", Key: k, Counters: BudgetCounters{Granted: 10}}
	p, _, _, err := p.Delegate("alloc", "child", k, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CloseChild(false); err == nil {
		t.Fatal("parent closed with delegated commitment")
	}
	reserved, err := BudgetAccount{ID: "reserved", Key: k, Counters: BudgetCounters{Granted: 10}}.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserved.CloseChild(false); err == nil {
		t.Fatal("account closed with reservation")
	}
}

func TestBudgetMethodsDoNotClaimPersistenceReplayReceipts(t *testing.T) {
	// Pure value transitions expose only updated state/errors. Request identity and replay receipts belong to persistence.
	p := BudgetAccount{ID: "parent", Key: key("token"), Counters: BudgetCounters{Granted: 4}}
	p, child, allocation, err := p.Delegate("alloc", "child", p.Key, 4)
	if err != nil {
		t.Fatal(err)
	}
	child, err = child.CloseChild(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, settled, err := p.SettleAllocation(child, allocation, false); err != nil || settled.State != BudgetAllocationSettled {
		t.Fatalf("settlement=(%+v,%v)", settled, err)
	}
}
