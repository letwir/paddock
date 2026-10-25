//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
)

func TestWorkOrderStorePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("PADDOCK_DB_URL")
	if dsn == "" {
		t.Fatal("PADDOCK_DB_URL must be set to run integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PADDOCK_DB_URL configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("unable to connect to integration database")
	}
	defer pool.Close()
	var dbName string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal("unable to verify integration database")
	}
	if dbName != "paddock_test" {
		t.Fatalf("refusing integration test on unexpected database %q", dbName)
	}

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal("unable to create fixture identifiers")
	}
	prefix := "wo_it_" + hex.EncodeToString(suffix[:])
	rootA, rootB := prefix+"_root_a", prefix+"_root_b"
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	defer func() {
		roots := []string{rootA, rootB}
		for _, cleanup := range []struct {
			statement string
			args      []any
		}{
			{`DELETE FROM raw.work_order_attempts WHERE work_order_id IN (SELECT work_order_id FROM raw.work_orders WHERE root_id = ANY($1::text[]))`, []any{roots}},
			{`DELETE FROM raw.work_order_dependencies WHERE root_id = ANY($1::text[])`, []any{roots}},
			{`DELETE FROM raw.work_orders WHERE root_id = ANY($1::text[])`, []any{roots}},
			{`DELETE FROM raw.roots WHERE root_id = ANY($1::text[])`, []any{roots}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id = $1`, []any{prefix + "_scope"}},
		} {
			if _, err := pool.Exec(cleanupCtx, cleanup.statement, cleanup.args...); err != nil {
				t.Errorf("cleanup WorkOrder fixture: %v", err)
			}
		}
	}()
	scopeID := prefix + "_scope"
	if _, err := pool.Exec(ctx, `INSERT INTO raw.policy_scopes (scope_id, mode) VALUES ($1, 'SAFE_STOPPED')`, scopeID); err != nil {
		t.Fatalf("create isolated SAFE_STOPPED Scope fixture: %v", err)
	}
	for _, id := range []string{rootA, rootB} {
		if _, err := pool.Exec(ctx, `INSERT INTO raw.roots (root_id, scope_id, safe_baseline) VALUES ($1,$2,true)`, id, scopeID); err != nil {
			t.Fatalf("create isolated Root fixture: %v", err)
		}
	}
	parentID := domain.WorkOrderID(prefix + "_parent")
	aID, bID := domain.WorkOrderID(prefix+"_a"), domain.WorkOrderID(prefix+"_b")
	cID, dID := domain.WorkOrderID(prefix+"_c"), domain.WorkOrderID(prefix+"_d")
	orders := []domain.WorkOrder{
		{ID: aID, RootID: domain.RootID(rootA), ParentID: &parentID},
		{ID: bID, RootID: domain.RootID(rootA), ParentID: &parentID},
		{ID: cID, RootID: domain.RootID(rootA), ParentID: &parentID},
		{ID: dID, RootID: domain.RootID(rootA), ParentID: &parentID},
		{ID: parentID, RootID: domain.RootID(rootA)},
	}
	graphA := domain.WorkOrderGraph{
		Orders:       orders,
		Dependencies: []domain.Dependency{{WorkOrderID: bID, DependsOnID: aID}},
		Attempts: []domain.Attempt{
			{ID: prefix + "_attempt_1", WorkOrderID: aID, Number: 1},
			{ID: prefix + "_attempt_2", WorkOrderID: aID, Number: 2},
		},
	}
	graphB := domain.WorkOrderGraph{Orders: []domain.WorkOrder{{ID: domain.WorkOrderID(prefix + "_other"), RootID: domain.RootID(rootB)}}}
	store, err := NewWorkOrderStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistGraph(ctx, graphA); err != nil {
		t.Fatalf("persist Root A graph: %v", err)
	}
	if err := store.PersistGraph(ctx, graphB); err != nil {
		t.Fatalf("persist Root B graph: %v", err)
	}
	got, err := store.LoadRoot(ctx, domain.RootID(rootA))
	if err != nil {
		t.Fatalf("load Root A graph: %v", err)
	}
	if !reflect.DeepEqual(got, graphA) {
		t.Fatalf("persisted graph mismatch: got %#v want %#v", got, graphA)
	}
	t.Run("cycle writers reject repeatable-read isolation", func(t *testing.T) {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id,work_order_id,depends_on_id) VALUES ($1,$2,$3)`, rootA, cID, dID)
		rollbackIntegrationTx(t, tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
			t.Fatalf("repeatable-read insert error=%v, want serialization_failure (40001)", err)
		}
	})

	t.Run("concurrent reverse inserts cannot commit a cycle", func(t *testing.T) {
		txA, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := txA.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id,work_order_id,depends_on_id) VALUES ($1,$2,$3)`, rootA, cID, dID); err != nil {
			rollbackIntegrationTx(t, txA)
			t.Fatalf("insert first concurrent edge: %v", err)
		}
		txB, err := pool.Begin(ctx)
		if err != nil {
			rollbackIntegrationTx(t, txA)
			t.Fatal(err)
		}
		var backendPID int
		if err := txB.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
			rollbackIntegrationTx(t, txA)
			rollbackIntegrationTx(t, txB)
			t.Fatal(err)
		}
		insertDone := make(chan error, 1)
		go func() {
			_, err := txB.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id,work_order_id,depends_on_id) VALUES ($1,$2,$3)`, rootA, dID, cID)
			insertDone <- err
		}()
		waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
		defer waitCancel()
		for {
			var waiting bool
			if err := pool.QueryRow(waitCtx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, backendPID).Scan(&waiting); err != nil {
				rollbackIntegrationTx(t, txA)
				rollbackIntegrationTx(t, txB)
				t.Fatalf("observe advisory-lock wait: %v", err)
			}
			if waiting {
				break
			}
			select {
			case insertErr := <-insertDone:
				rollbackIntegrationTx(t, txA)
				t.Fatalf("second reverse edge did not wait for root lock (err=%v)", insertErr)
			case <-waitCtx.Done():
				rollbackIntegrationTx(t, txA)
				rollbackIntegrationTx(t, txB)
				t.Fatal("second reverse edge never waited for root lock")
			case <-time.After(10 * time.Millisecond):
			}
		}
		if err := txA.Commit(ctx); err != nil {
			rollbackIntegrationTx(t, txB)
			t.Fatalf("commit first concurrent edge: %v", err)
		}
		select {
		case err := <-insertDone:
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				rollbackIntegrationTx(t, txB)
				t.Fatalf("second edge error=%v, want cycle check_violation (23514)", err)
			}
			rollbackIntegrationTx(t, txB)
		case <-waitCtx.Done():
			rollbackIntegrationTx(t, txB)
			t.Fatal("second reverse edge did not finish after first commit")
		}
	})

	t.Run("database rejects dependency cycle", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id, work_order_id, depends_on_id) VALUES ($1,$2,$3)`, rootA, aID, bID)
		rollbackIntegrationTx(t, tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("cycle insert error = %v, want check_violation (23514)", err)
		}
	})
	t.Run("database rejects cross-root dependency", func(t *testing.T) {
		var otherID string
		if err := pool.QueryRow(ctx, `SELECT work_order_id FROM raw.work_orders WHERE root_id=$1`, rootB).Scan(&otherID); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO raw.work_order_dependencies (root_id, work_order_id, depends_on_id) VALUES ($1,$2,$3)`, rootA, aID, otherID)
		rollbackIntegrationTx(t, tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("cross-root insert error = %v, want foreign_key_violation (23503)", err)
		}
	})
	t.Run("database rejects ownership cycle", func(t *testing.T) {
		x, y := prefix+"_parent_x", prefix+"_parent_y"
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO raw.work_orders (work_order_id,root_id,parent_id) VALUES ($1,$2,$3)`, x, rootA, y); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO raw.work_orders (work_order_id,root_id,parent_id) VALUES ($1,$2,$3)`, y, rootA, x)
		}
		rollbackIntegrationTx(t, tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("ownership cycle insert error = %v, want check_violation (23514)", err)
		}
	})
	t.Run("database preserves unique attempt sequence", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO raw.work_order_attempts (attempt_id,work_order_id,attempt_number) VALUES ($1,$2,1)`, prefix+"_duplicate", aID)
		rollbackIntegrationTx(t, tx)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("duplicate attempt error = %v, want unique_violation (23505)", err)
		}
	})
}

func rollbackIntegrationTx(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Errorf("rollback integration transaction: %v", err)
	}
}
