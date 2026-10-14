// Package port defines the persistence boundary used by governance application
// code. It depends only on the domain contract and the Go standard library.
package port

import (
	"context"
	"errors"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

var ErrStaleWrite = errors.New("stale governance snapshot")

// ScopeSnapshot is the persisted Scope plus all same-scope Root authority rows
// and the global Security Epoch observed under the transaction's locks.
type ScopeSnapshot struct {
	ScopeID         domain.ScopeID
	ActivationEpoch domain.Epoch
	Mode            domain.ScopeMode
	BaselineBundle  *domain.Digest
	LiveRolloutID   *domain.RolloutID
	SecurityEpoch   domain.Epoch
	Roots           map[domain.RootID]domain.RootAuthority
}

// CommandReceipt is a completed durable command outcome. Only SUCCEEDED
// receipts with a valid response may be returned by LookupCommandReceipt.
type CommandReceipt struct {
	CommandID     string
	RequestDigest string
	Status        string
	Response      []byte
}

// RolloutTargetSnapshot is one persisted rollout target row.
type RolloutTargetSnapshot struct {
	Baseline      domain.PolicyBinding
	Candidate     domain.PolicyBinding
	BaseRootEpoch domain.Epoch
}

// RolloutSnapshot mirrors persisted rollout and target rows, including SHADOW
// and terminal states that may not be transition inputs to every Domain function.
type RolloutSnapshot struct {
	ID                  domain.RolloutID
	Scope               domain.ScopeID
	State               domain.RolloutState
	TargetRoot          *domain.RootID
	BaseActivationEpoch domain.Epoch
	LastActivationEpoch domain.Epoch
	BaseSecurityEpoch   domain.Epoch
	RollbackFrom        *domain.RolloutState
	Targets             map[domain.RootID]RolloutTargetSnapshot
}

// Transactor executes fn within one transaction. The Transactor owns commit and
// rollback: an error returned by fn must roll back the transaction, and commit
// or transaction errors must be propagated to the caller. The callback must not
// retain or use its GovernanceTx after fn returns.
type Transactor interface {
	WithinTransaction(ctx context.Context, fn func(GovernanceTx) error) error
}

// GovernanceTx is the transaction-bound capability available to governance
// operations. It is valid only for the duration of the Transactor callback and
// must not be used after that callback returns. Implementations must not expose
// database-driver types. Lock order is Scope -> Rollout/targets -> Root rows;
// call ValidateTargets after LockRollout (or after LockScope for a new rollout)
// before any Scope CAS. It locks all same-scope Roots in deterministic order.
type GovernanceTx interface {
	// DatabaseTime returns PostgreSQL wall-clock time within this transaction.
	// Callers must use it, rather than a worker-supplied timestamp, for deadlines.
	DatabaseTime(ctx context.Context) (time.Time, error)
	LockScope(ctx context.Context, scopeID domain.ScopeID) (ScopeSnapshot, error)
	LockRollout(ctx context.Context, scopeID domain.ScopeID, rolloutID domain.RolloutID) (RolloutSnapshot, error)
	ValidateTargets(ctx context.Context, scopeID domain.ScopeID, targets []domain.RootID) error
	CompareAndSwapScope(ctx context.Context, expected, next ScopeSnapshot) error
	CompareAndSwapRollout(ctx context.Context, expected, next RolloutSnapshot) error
	CompareAndSwapSecurityEpoch(ctx context.Context, expected, next domain.Epoch) error
	LookupCommandReceipt(ctx context.Context, commandID string) (CommandReceipt, bool, error)
	InsertCommandReceipt(ctx context.Context, receipt CommandReceipt) error
}
