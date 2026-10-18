package domain

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrBudgetInvalid  = errors.New("invalid budget")
	ErrBudgetDenied   = errors.New("budget operation denied")
	ErrBudgetOverflow = errors.New("budget counter overflow")
)

// BudgetAmount is a non-negative integer count of the smallest resource quantum.
type BudgetAmount int64

type ResourceKind string

const (
	ResourceCurrency     ResourceKind = "CURRENCY"
	ResourceTokens       ResourceKind = "TOKENS"
	ResourceCompute      ResourceKind = "COMPUTE"
	ResourceStorageBytes ResourceKind = "STORAGE_BYTES"
)

type BudgetKey struct{ RootID, ResourceKind, UnitCode string }

func validTrimmedID(s string) bool { return s != "" && strings.TrimSpace(s) == s }

func (k BudgetKey) Validate() error {
	if !validTrimmedID(k.RootID) {
		return fmt.Errorf("%w: root id", ErrBudgetInvalid)
	}
	if ResourceKind(k.ResourceKind) == ResourceStorageBytes && k.UnitCode != "byte" {
		return fmt.Errorf("%w: STORAGE_BYTES unit_code must be byte", ErrBudgetInvalid)
	}
	switch ResourceKind(k.ResourceKind) {
	case ResourceCurrency, ResourceTokens, ResourceCompute, ResourceStorageBytes:
	default:
		return fmt.Errorf("%w: resource_kind", ErrBudgetInvalid)
	}
	if k.UnitCode == "" || !utf8.ValidString(k.UnitCode) || !norm.NFC.IsNormalString(k.UnitCode) {
		return fmt.Errorf("%w: unit_code must be nonempty NFC UTF-8", ErrBudgetInvalid)
	}
	runes := []rune(k.UnitCode)
	if unicode.IsSpace(runes[0]) || unicode.IsSpace(runes[len(runes)-1]) {
		return fmt.Errorf("%w: unit_code leading/trailing whitespace", ErrBudgetInvalid)
	}
	for _, r := range runes {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: unit_code control character", ErrBudgetInvalid)
		}
	}
	return nil
}

type BudgetCounters struct{ Granted, Spent, Reserved, Delegated BudgetAmount }

func (c BudgetCounters) Validate() error {
	if c.Granted < 0 || c.Spent < 0 || c.Reserved < 0 || c.Delegated < 0 {
		return fmt.Errorf("%w: negative counter", ErrBudgetInvalid)
	}
	if c.Spent > c.Granted || c.Reserved > c.Granted-c.Spent || c.Delegated > c.Granted-c.Spent-c.Reserved {
		return fmt.Errorf("%w: invariant exceeded", ErrBudgetDenied)
	}
	return nil
}
func (c BudgetCounters) Available() (BudgetAmount, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	return c.Granted - c.Spent - c.Reserved - c.Delegated, nil
}
func addAmount(a, b BudgetAmount) (BudgetAmount, error) {
	if b < 0 || a < 0 || int64(a) > math.MaxInt64-int64(b) {
		return 0, ErrBudgetOverflow
	}
	return a + b, nil
}

type BudgetAccount struct {
	ID           string
	Key          BudgetKey
	Counters     BudgetCounters
	Terminal     bool
	AllocationID string // identifies the unique parent escrow that granted this account
}

func (a BudgetAccount) Validate() error {
	if !validTrimmedID(a.ID) {
		return fmt.Errorf("%w: account id", ErrBudgetInvalid)
	}
	if err := a.Key.Validate(); err != nil {
		return err
	}
	if err := a.Counters.Validate(); err != nil {
		return err
	}
	return nil
}

type BudgetOperation struct {
	OperationID string
	Amount      BudgetAmount
}

func (o BudgetOperation) Validate() error {
	if !validTrimmedID(o.OperationID) || o.Amount < 0 {
		return ErrBudgetInvalid
	}
	return nil
}

type BudgetAllocationState string

const (
	BudgetAllocationOpen    BudgetAllocationState = "OPEN"
	BudgetAllocationSettled BudgetAllocationState = "SETTLED"
)

// BudgetAllocation is the unique escrow identity connecting one parent and child.
type BudgetAllocation struct {
	AllocationID    string
	ParentAccountID string
	ChildAccountID  string
	Key             BudgetKey
	Amount          BudgetAmount
	State           BudgetAllocationState
}

func (a BudgetAllocation) Validate() error {
	if !validTrimmedID(a.AllocationID) || !validTrimmedID(a.ParentAccountID) || !validTrimmedID(a.ChildAccountID) || a.ParentAccountID == a.ChildAccountID || a.Amount < 0 {
		return ErrBudgetInvalid
	}
	if err := a.Key.Validate(); err != nil {
		return err
	}
	if a.State != BudgetAllocationOpen && a.State != BudgetAllocationSettled {
		return ErrBudgetInvalid
	}
	return nil
}

// Reserve returns updated counters without mutation. Rejections leave input untouched.
func (a BudgetAccount) Reserve(amount BudgetAmount) (BudgetAccount, error) {
	if err := a.Validate(); err != nil {
		return a, err
	}
	if a.Terminal {
		return a, ErrBudgetDenied
	}
	c, err := a.Counters.Reserve(amount)
	if err != nil {
		return a, err
	}
	a.Counters = c
	return a, nil
}
func (c BudgetCounters) Reserve(amount BudgetAmount) (BudgetCounters, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	if amount < 0 {
		return c, ErrBudgetInvalid
	}
	available, _ := c.Available()
	if amount > available {
		return c, ErrBudgetDenied
	}
	c.Reserved += amount
	return c, nil
}

// SettleReservation charges actual usage and releases the unused reservation.
func (a BudgetAccount) SettleReservation(reserved, actual BudgetAmount) (BudgetAccount, error) {
	if err := a.Validate(); err != nil {
		return a, err
	}
	if a.Terminal {
		return a, ErrBudgetDenied
	}
	c, err := a.Counters.SettleReservation(reserved, actual)
	if err != nil {
		return a, err
	}
	a.Counters = c
	return a, nil
}
func (c BudgetCounters) SettleReservation(reserved, actual BudgetAmount) (BudgetCounters, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	if reserved < 0 || actual < 0 || actual > reserved || reserved > c.Reserved {
		return c, ErrBudgetDenied
	}
	c.Reserved -= reserved
	spent, err := addAmount(c.Spent, actual)
	if err != nil {
		return c, err
	}
	c.Spent = spent
	if err = c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Delegate escrows amount, returning new parent, child, and OPEN allocation snapshots.
func (a BudgetAccount) Delegate(allocationID, childID string, childKey BudgetKey, amount BudgetAmount) (BudgetAccount, BudgetAccount, BudgetAllocation, error) {
	if err := a.Validate(); err != nil {
		return a, BudgetAccount{}, BudgetAllocation{}, err
	}
	if a.Terminal || !validTrimmedID(allocationID) || !validTrimmedID(childID) || childID == a.ID || amount < 0 {
		return a, BudgetAccount{}, BudgetAllocation{}, ErrBudgetDenied
	}
	if childKey != a.Key {
		return a, BudgetAccount{}, BudgetAllocation{}, ErrBudgetDenied
	}
	if err := childKey.Validate(); err != nil {
		return a, BudgetAccount{}, BudgetAllocation{}, err
	}
	available, _ := a.Counters.Available()
	if amount > available {
		return a, BudgetAccount{}, BudgetAllocation{}, ErrBudgetDenied
	}
	d, err := addAmount(a.Counters.Delegated, amount)
	if err != nil {
		return a, BudgetAccount{}, BudgetAllocation{}, err
	}
	a.Counters.Delegated = d
	allocation := BudgetAllocation{AllocationID: allocationID, ParentAccountID: a.ID, ChildAccountID: childID, Key: a.Key, Amount: amount, State: BudgetAllocationOpen}
	child := BudgetAccount{ID: childID, Key: a.Key, Counters: BudgetCounters{Granted: amount}, AllocationID: allocationID}
	return a, child, allocation, nil
}

// SettleAllocation settles only the exact open allocation linked to this child.
func (a BudgetAccount) SettleAllocation(child BudgetAccount, allocation BudgetAllocation, descendantsOpen bool) (BudgetAccount, BudgetAllocation, error) {
	if err := a.Validate(); err != nil {
		return a, allocation, err
	}
	if err := child.Validate(); err != nil {
		return a, allocation, err
	}
	if err := allocation.Validate(); err != nil {
		return a, allocation, err
	}
	if a.Terminal || descendantsOpen || !child.Terminal || child.Counters.Reserved != 0 || child.Counters.Delegated != 0 || a.Key != child.Key || allocation.Key != a.Key || allocation.State != BudgetAllocationOpen || allocation.ParentAccountID != a.ID || allocation.ChildAccountID != child.ID || child.AllocationID != allocation.AllocationID || allocation.Amount != child.Counters.Granted || allocation.Amount > a.Counters.Delegated {
		return a, allocation, ErrBudgetDenied
	}
	d := a.Counters.Delegated - allocation.Amount
	s, err := addAmount(a.Counters.Spent, child.Counters.Spent)
	if err != nil {
		return a, allocation, err
	}
	a.Counters.Delegated, a.Counters.Spent = d, s
	if err = a.Counters.Validate(); err != nil {
		return a, allocation, err
	}
	allocation.State = BudgetAllocationSettled
	return a, allocation, nil
}

// CloseChild marks an account terminal only when no child, reservation, or escrow remains.
func (a BudgetAccount) CloseChild(descendantsOpen bool) (BudgetAccount, error) {
	if err := a.Validate(); err != nil {
		return a, err
	}
	if a.Terminal || descendantsOpen || a.Counters.Reserved != 0 || a.Counters.Delegated != 0 {
		return a, ErrBudgetDenied
	}
	a.Terminal = true
	return a, nil
}
