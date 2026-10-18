package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
)

// BudgetStore uses only the SECURITY DEFINER ledger entry point; it has no direct
// table access and treats SQL errors, malformed results, and uncertain commits as failures.
type BudgetStore struct{ pool *pgxpool.Pool }

func validBudgetUnit(value string) bool {
	if value == "" || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) || unicode.IsSpace([]rune(value)[0]) || unicode.IsSpace([]rune(value)[len([]rune(value))-1]) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func NewBudgetStore(pool *pgxpool.Pool) (*BudgetStore, error) {
	if pool == nil {
		return nil, errors.New("budget store: nil pool")
	}
	return &BudgetStore{pool: pool}, nil
}

type budgetRequest struct {
	AccountID    string              `json:"account_id"`
	ChildID      string              `json:"child_id,omitempty"`
	AllocationID string              `json:"allocation_id,omitempty"`
	RootID       string              `json:"root_id,omitempty"`
	ResourceKind string              `json:"resource_kind,omitempty"`
	UnitCode     string              `json:"unit_code,omitempty"`
	Amount       domain.BudgetAmount `json:"amount,omitempty"`
	Reserved     domain.BudgetAmount `json:"reserved,omitempty"`
	Actual       domain.BudgetAmount `json:"actual,omitempty"`
}

func (s *BudgetStore) apply(ctx context.Context, op domain.BudgetOperation, kind string, req budgetRequest) (json.RawMessage, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("budget store: uninitialized pool")
	}
	if ctx == nil {
		return nil, errors.New("budget store: nil context")
	}
	if err := op.Validate(); err != nil {
		return nil, fmt.Errorf("budget operation: %w", err)
	}
	if req.Amount < 0 || req.Reserved < 0 || req.Actual < 0 {
		return nil, domain.ErrBudgetInvalid
	}
	if req.UnitCode != "" && !validBudgetUnit(req.UnitCode) {
		return nil, domain.ErrBudgetInvalid
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode budget request: %w", err)
	}
	var result []byte
	if err := s.pool.QueryRow(ctx, `SELECT raw.budget_apply($1,$2,$3::jsonb)`, op.OperationID, kind, string(data)).Scan(&result); err != nil {
		return nil, fmt.Errorf("apply budget %s (commit outcome may be unknown): %w", kind, err)
	}
	if !json.Valid(result) {
		return nil, errors.New("budget store: invalid database result")
	}
	return json.RawMessage(result), nil
}

func (s *BudgetStore) InitializeRootGrant(ctx context.Context, op domain.BudgetOperation, accountID string, key domain.BudgetKey) (json.RawMessage, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if accountID == "" || op.Amount < 0 {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "GRANT", budgetRequest{AccountID: accountID, RootID: key.RootID, ResourceKind: key.ResourceKind, UnitCode: key.UnitCode, Amount: op.Amount})
}
func (s *BudgetStore) Delegate(ctx context.Context, op domain.BudgetOperation, parentID, childID string, key domain.BudgetKey) (json.RawMessage, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if parentID == "" || childID == "" || parentID == childID {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "DELEGATE", budgetRequest{AccountID: parentID, ChildID: childID, RootID: key.RootID, ResourceKind: key.ResourceKind, UnitCode: key.UnitCode, Amount: op.Amount})
}
func (s *BudgetStore) Reserve(ctx context.Context, op domain.BudgetOperation, accountID string) (json.RawMessage, error) {
	if accountID == "" {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "RESERVE", budgetRequest{AccountID: accountID, Amount: op.Amount})
}
func (s *BudgetStore) SettleReservation(ctx context.Context, op domain.BudgetOperation, accountID string, reserved, actual domain.BudgetAmount) (json.RawMessage, error) {
	if accountID == "" || reserved < 0 || actual < 0 || actual > reserved {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "SETTLE_RESERVATION", budgetRequest{AccountID: accountID, Reserved: reserved, Actual: actual})
}
func (s *BudgetStore) ReleaseReservation(ctx context.Context, op domain.BudgetOperation, accountID string, reserved domain.BudgetAmount) (json.RawMessage, error) {
	if accountID == "" || reserved < 0 {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "RELEASE", budgetRequest{AccountID: accountID, Reserved: reserved})
}
func (s *BudgetStore) CloseChild(ctx context.Context, op domain.BudgetOperation, accountID string) (json.RawMessage, error) {
	if accountID == "" {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "CLOSE", budgetRequest{AccountID: accountID})
}
func (s *BudgetStore) SettleChild(ctx context.Context, op domain.BudgetOperation, parentID, childID, allocationID string) (json.RawMessage, error) {
	if parentID == "" || childID == "" || allocationID == "" || parentID == childID {
		return nil, domain.ErrBudgetInvalid
	}
	return s.apply(ctx, op, "SETTLE_CHILD", budgetRequest{AccountID: parentID, ChildID: childID, AllocationID: allocationID})
}
