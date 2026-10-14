package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
)

// WorkOrderStore persists a validated ownership tree, execution DAG, and attempt
// history atomically. It is separate from GovernanceTx because scheduling state
// has its own aggregate and Root-local locking policy.
type WorkOrderStore struct{ pool *pgxpool.Pool }

func NewWorkOrderStore(pool *pgxpool.Pool) (*WorkOrderStore, error) {
	if pool == nil {
		return nil, errors.New("work order store: nil pool")
	}
	return &WorkOrderStore{pool: pool}, nil
}

// PersistGraph validates the complete one-Root graph before opening a
// transaction. SQL constraints and the cycle trigger independently enforce
// persisted invariants.
func (s *WorkOrderStore) PersistGraph(ctx context.Context, graph domain.WorkOrderGraph) (resultErr error) {
	if s == nil || s.pool == nil {
		return errors.New("work order store: uninitialized pool")
	}
	if ctx == nil {
		return errors.New("work order store: nil context")
	}
	if err := graph.Validate(); err != nil {
		return fmt.Errorf("persist work order graph: %w", err)
	}
	rootID := graph.Orders[0].RootID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin work order transaction: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(rollbackCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, fmt.Errorf("rollback work order transaction: %w", rollbackErr))
		}
	}()

	for _, order := range graph.Orders {
		var parent any
		if order.ParentID != nil {
			parent = string(*order.ParentID)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO raw.work_orders (work_order_id, root_id, parent_id) VALUES ($1, $2, $3)`, string(order.ID), string(order.RootID), parent); err != nil {
			return fmt.Errorf("insert work order %q: %w", order.ID, err)
		}
	}
	for _, dependency := range graph.Dependencies {
		if _, err := tx.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id, work_order_id, depends_on_id) VALUES ($1, $2, $3)`, string(rootID), string(dependency.WorkOrderID), string(dependency.DependsOnID)); err != nil {
			return fmt.Errorf("insert dependency %q -> %q: %w", dependency.WorkOrderID, dependency.DependsOnID, err)
		}
	}
	for _, attempt := range graph.Attempts {
		if _, err := tx.Exec(ctx, `INSERT INTO raw.work_order_attempts (attempt_id, work_order_id, attempt_number) VALUES ($1, $2, $3)`, attempt.ID, string(attempt.WorkOrderID), int64(attempt.Number)); err != nil {
			return fmt.Errorf("insert attempt %q: %w", attempt.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit work order graph (outcome may be unknown): %w", err)
	}
	return nil
}

// LoadRoot returns one Root's persisted graph and revalidates it before exposing
// data to callers, failing closed on corrupted or cross-root records.
func (s *WorkOrderStore) LoadRoot(ctx context.Context, rootID domain.RootID) (graph domain.WorkOrderGraph, resultErr error) {
	if s == nil || s.pool == nil {
		return graph, errors.New("work order store: uninitialized pool")
	}
	if ctx == nil {
		return graph, errors.New("work order store: nil context")
	}
	if err := rootID.Validate(); err != nil {
		return graph, fmt.Errorf("load work order graph: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return graph, fmt.Errorf("begin work order read transaction: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(rollbackCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, fmt.Errorf("rollback work order read transaction: %w", rollbackErr))
		}
	}()
	rows, err := tx.Query(ctx, `SELECT work_order_id, root_id, parent_id FROM raw.work_orders WHERE root_id=$1 ORDER BY work_order_id`, string(rootID))
	if err != nil {
		return graph, fmt.Errorf("query work orders: %w", err)
	}
	for rows.Next() {
		var id, root string
		var parent pgtype.Text
		if err := rows.Scan(&id, &root, &parent); err != nil {
			rows.Close()
			return graph, fmt.Errorf("scan work order: %w", err)
		}
		order := domain.WorkOrder{ID: domain.WorkOrderID(id), RootID: domain.RootID(root)}
		if parent.Valid {
			p := domain.WorkOrderID(parent.String)
			order.ParentID = &p
		}
		graph.Orders = append(graph.Orders, order)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return graph, fmt.Errorf("iterate work orders: %w", err)
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT work_order_id, depends_on_id FROM raw.work_order_dependencies WHERE root_id=$1 ORDER BY work_order_id, depends_on_id`, string(rootID))
	if err != nil {
		return graph, fmt.Errorf("query work order dependencies: %w", err)
	}
	for rows.Next() {
		var orderID, dependencyID string
		if err := rows.Scan(&orderID, &dependencyID); err != nil {
			rows.Close()
			return graph, fmt.Errorf("scan work order dependency: %w", err)
		}
		graph.Dependencies = append(graph.Dependencies, domain.Dependency{WorkOrderID: domain.WorkOrderID(orderID), DependsOnID: domain.WorkOrderID(dependencyID)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return graph, fmt.Errorf("iterate work order dependencies: %w", err)
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT attempt.attempt_id, attempt.work_order_id, attempt.attempt_number FROM raw.work_order_attempts AS attempt JOIN raw.work_orders AS work_order USING (work_order_id) WHERE work_order.root_id=$1 ORDER BY attempt.work_order_id, attempt.attempt_number`, string(rootID))
	if err != nil {
		return graph, fmt.Errorf("query work order attempts: %w", err)
	}
	for rows.Next() {
		var attempt domain.Attempt
		var number int64
		if err := rows.Scan(&attempt.ID, &attempt.WorkOrderID, &number); err != nil {
			rows.Close()
			return graph, fmt.Errorf("scan work order attempt: %w", err)
		}
		if number <= 0 {
			rows.Close()
			return graph, fmt.Errorf("invalid persisted attempt number %d", number)
		}
		attempt.Number = uint64(number)
		graph.Attempts = append(graph.Attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return graph, fmt.Errorf("iterate work order attempts: %w", err)
	}
	rows.Close()
	if err := graph.Validate(); err != nil {
		return graph, fmt.Errorf("validate persisted work order graph: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return graph, fmt.Errorf("commit work order read transaction: %w", err)
	}
	return graph, nil
}
