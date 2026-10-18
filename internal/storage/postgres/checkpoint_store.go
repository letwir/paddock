package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
)

// CheckpointStore persists through a single pgx transaction. App role reaches only
// the SECURITY DEFINER insertion function and budget_apply; it never accesses tables.
type CheckpointStore struct{ pool *pgxpool.Pool }

func NewCheckpointStore(pool *pgxpool.Pool) (*CheckpointStore, error) {
	if pool == nil {
		return nil, errors.New("checkpoint store: nil pool")
	}
	return &CheckpointStore{pool: pool}, nil
}

type checkpointBudgetRequest struct {
	AccountID string `json:"account_id"`
	Amount    int64  `json:"amount,omitempty"`
	Reserved  int64  `json:"reserved,omitempty"`
	Actual    int64  `json:"actual,omitempty"`
}

func checkpointBudget(ctx context.Context, tx pgx.Tx, op, kind, account string, amount, reserved, actual int64) error {
	b, e := json.Marshal(checkpointBudgetRequest{AccountID: account, Amount: amount, Reserved: reserved, Actual: actual})
	if e != nil {
		return e
	}
	var result []byte
	if e = tx.QueryRow(ctx, `SELECT raw.budget_apply($1,$2,$3::jsonb)`, op, kind, string(b)).Scan(&result); e != nil {
		return fmt.Errorf("budget %s: %w", kind, e)
	}
	if !json.Valid(result) {
		return errors.New("invalid budget result")
	}
	return nil
}
func (s *CheckpointStore) RestoreCheckpoint(ctx context.Context, id string) (domain.Checkpoint, error) {
	if s == nil || s.pool == nil || ctx == nil || id == "" {
		return domain.Checkpoint{}, errors.New("checkpoint store unavailable")
	}
	var out domain.Checkpoint
	var manifest, payload []byte
	var state string
	var n int64
	if err := s.pool.QueryRow(ctx, `SELECT checkpoint_id,manifest,payload,state,stored_bytes FROM raw.restore_work_order_checkpoint($1)`, id).Scan(&out.ID, &manifest, &payload, &state, &n); err != nil {
		return out, err
	}
	out.ManifestBytes = append([]byte(nil), manifest...)
	out.Status = domain.CheckpointStatus(state)
	out.StoredBytes = n
	if out.Status == domain.CheckpointL2 {
		out.Payload = append([]byte(nil), payload...)
	}
	if err := json.Unmarshal(manifest, &out.Manifest); err != nil {
		return domain.Checkpoint{}, fmt.Errorf("invalid stored checkpoint manifest: %w", err)
	}
	return out, nil
}

func (s *CheckpointStore) StoreCheckpoint(ctx context.Context, r domain.CheckpointRequest, manifest []byte, stored int64) (out domain.Checkpoint, err error) {
	if s == nil || s.pool == nil || ctx == nil {
		return out, errors.New("checkpoint store unavailable")
	}
	if r.OperationID == "" || stored <= 0 || int64(len(manifest))+int64(len(r.Payload)) != stored {
		return out, domain.ErrCheckpointInvalid
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return out, e
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var account string
	if e = tx.QueryRow(ctx, `SELECT raw.checkpoint_storage_account($1)`, r.Manifest.RootID).Scan(&account); e != nil {
		return out, fmt.Errorf("checkpoint policy lookup: %w", e)
	}
	if account == "" {
		return out, errors.New("checkpoint storage account missing")
	}
	if e = checkpointBudget(ctx, tx, r.OperationID+":reserve", "RESERVE", account, stored, 0, 0); e != nil {
		return out, e
	}
	// Pass exact JCS manifest and payload; database checks current authority snapshot.
	var id, status string
	var storedBytes int64
	e = tx.QueryRow(ctx, `SELECT checkpoint_id,state,stored_bytes FROM raw.store_work_order_checkpoint($1,$2,$3,$4,$5,$6,$7,$8)`, r.OperationID, r.Manifest.RootID, r.Manifest.WorkOrderID, r.Manifest.AttemptID, int64(r.Manifest.LeaseEpoch), manifest, r.Payload, stored).Scan(&id, &status, &storedBytes)
	if e != nil {
		return out, fmt.Errorf("store checkpoint: %w", e)
	}
	if e = checkpointBudget(ctx, tx, r.OperationID+":settle", "SETTLE_RESERVATION", account, 0, stored, stored); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, fmt.Errorf("checkpoint commit outcome may be unknown: %w", e)
	}
	// Always reauthorize through the restore function, including operation replay:
	// an old L2 result may have gone stale since its original commit.
	return s.RestoreCheckpoint(ctx, r.OperationID)
}
