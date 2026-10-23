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

// ErrReceiptExpired is returned only after the saved request digest matches.
// It never permits command ID reuse; the original terminal status is retained.
var ErrReceiptExpired = errors.New("command receipt response expired")

// ReceiptTombstoneResponse is the permanent payload-free retention marker. The
// fixed SQL API writes these exact UTF-8 bytes, without changing status/digest.
const ReceiptTombstoneResponse = `{"schema_version":"paddock.command-response/1","kind":"EXPIRED","code":"RECEIPT_EXPIRED","detail":"The command response retention period has expired; this command ID cannot be reused."}`

// ErrCommitOutcomeUnknown marks a Commit attempt whose outcome cannot be
// established. Errors carrying it must preserve the underlying cause and never be
// automatically retried, including when that cause exposes an abort SQLSTATE.
// Reconcile the durable receipt using the same command ID instead.
var ErrCommitOutcomeUnknown = errors.New("governance commit outcome unknown")

// ErrTransactionRolledBack means the Transactor confirmed rollback or the
// server explicitly reported an aborted transaction. SQLSTATE alone outside
// that boundary is not proof of rollback. The original cause must be preserved;
// ErrCommitOutcomeUnknown takes precedence if both markers are present.
var ErrTransactionRolledBack = errors.New("governance transaction rolled back")

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

// CommandReceipt is a completed durable SUCCEEDED or REJECTED command outcome.
// Lookup may replace the body with a permanent tombstone at the half-open
// 365-day DB-clock deadline. Consumers must compare RequestDigest before Expired.
type CommandReceipt struct {
	CommandID     string
	RequestDigest domain.Digest
	Status        string
	Response      []byte
	Expired       bool
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
	Monitoring          domain.MonitoringWindow
}

// Transactor executes fn within one transaction. The Transactor owns commit and
// rollback: an error returned by fn must roll back the transaction, and commit
// or transaction errors must be propagated to the caller. The callback must not
// retain or use its GovernanceTx after fn returns.
// Confirmed rollbacks and known server aborts carry ErrTransactionRolledBack.
// Failed rollbacks must not add that marker. Uncertain Commit errors instead
// carry ErrCommitOutcomeUnknown. All errors preserve the original cause.
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
	// InsertPolicyBundle persists a validated content-addressed bundle and its
	// externally supplied signer ID/signature atomically. It performs no key
	// verification or signing.
	InsertPolicyBundle(ctx context.Context, bundle domain.CanonicalBundle, signerKeyID string, signature []byte) error
	// DatabaseTime returns a fresh PostgreSQL clock_timestamp() observation
	// within this transaction, after the caller's state locks. It is not cached
	// transaction-start time (now()/transaction_timestamp()). Callers use this,
	// rather than a worker-supplied timestamp, for all monitoring deadlines.
	DatabaseTime(ctx context.Context) (time.Time, error)
	LockScope(ctx context.Context, scopeID domain.ScopeID) (ScopeSnapshot, error)
	LockRollout(ctx context.Context, scopeID domain.ScopeID, rolloutID domain.RolloutID) (RolloutSnapshot, error)
	ValidateTargets(ctx context.Context, scopeID domain.ScopeID, targets []domain.RootID) error
	CompareAndSwapScope(ctx context.Context, expected, next ScopeSnapshot) error
	// CompareAndSwapRollout compares the entire locked expected snapshot,
	// including all monitoring fields and DecisionRevision. A stale or missing
	// row returns ErrStaleWrite. Never implement this as an unconditional update.
	CompareAndSwapRollout(ctx context.Context, expected, next RolloutSnapshot) error
	CompareAndSwapSecurityEpoch(ctx context.Context, expected, next domain.Epoch) error
	LookupCommandReceipt(ctx context.Context, commandID string) (CommandReceipt, bool, error)
	InsertCommandReceipt(ctx context.Context, receipt CommandReceipt) error
	// AppendEvent persists the event envelope and its outbox row in this transaction.
	AppendEvent(ctx context.Context, event domain.Event) error
}
