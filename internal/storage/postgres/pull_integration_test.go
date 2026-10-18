//go:build paddock_test

package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/scheduler"
)

type pullAllow struct{}

func workerID(suffix string) string { return "pull_it_worker_" + suffix }

func (pullAllow) Allow(context.Context, scheduler.Candidate, scheduler.Worker) (bool, error) {
	return true, nil
}

// Requires operator-applied M08-S01/S02 migrations; this test never applies migrations.
func TestPullReservationConcurrentOneWinner(t *testing.T) {
	// This longer TTL is test-only and is not a production default.
	const leaseTTL = 10 * time.Second

	setupURL := os.Getenv("PADDOCK_DB_URL")
	appURL := os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	setupPool, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect privileged test fixture database")
	}
	t.Cleanup(setupPool.Close)
	var database string
	if err := setupPool.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil || database != "paddock_test" {
		t.Fatal("privileged fixture connection must target paddock_test")
	}

	appPool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("app connection must target paddock_test and authenticate as paddock_app")
	}
	t.Cleanup(appPool.Close)

	// This is catalog inspection only; application behavior below is exercised through appPool.
	if err := checkPullPrivileges(ctx, setupPool); err != nil {
		t.Fatal("Pull privilege contract check failed")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope, root, pred, wo, emptyWO := "pull_it_scope_"+suffix, "pull_it_root_"+suffix, "pull_it_pred_"+suffix, "pull_it_wo_"+suffix, "pull_it_empty_"+suffix
	t.Cleanup(func() {
		cleanCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		// Attempt every cleanup even if an earlier statement failed; never include DB errors.
		cleanup := []struct {
			name string
			sql  string
			args []any
		}{
			{"leases", "DELETE FROM raw.work_order_leases WHERE work_order_id IN ($1,$2,$3)", []any{wo, pred, emptyWO}},
			{"pull slots", "DELETE FROM raw.work_order_pull_slots WHERE work_order_id IN ($1,$2,$3)", []any{wo, pred, emptyWO}},
			{"capability requirements", "DELETE FROM raw.work_order_capability_requirements WHERE work_order_id=$1", []any{wo}},
			{"dependencies", "DELETE FROM raw.work_order_dependencies WHERE work_order_id=$1", []any{wo}},
			{"attempts", "DELETE FROM raw.work_order_attempts WHERE work_order_id IN ($1,$2,$3)", []any{wo, pred, emptyWO}},
			{"work orders", "DELETE FROM raw.work_orders WHERE work_order_id IN ($1,$2,$3)", []any{wo, pred, emptyWO}},
			{"root", "DELETE FROM raw.roots WHERE root_id=$1", []any{root}},
			{"scope", "DELETE FROM raw.policy_scopes WHERE scope_id=$1", []any{scope}},
		}
		for _, item := range cleanup {
			if _, err := setupPool.Exec(cleanCtx, item.sql, item.args...); err != nil {
				t.Errorf("fixture cleanup failed for %s", item.name)
			}
		}
	})
	if _, err := setupPool.Exec(ctx, "INSERT INTO raw.policy_scopes(scope_id,mode) VALUES($1,'SAFE_STOPPED')", scope); err != nil {
		t.Fatal("fixture scope setup failed")
	}
	if _, err := setupPool.Exec(ctx, "INSERT INTO raw.roots(root_id,scope_id,safe_baseline) VALUES($1,$2,true)", root, scope); err != nil {
		t.Fatal("fixture root setup failed")
	}
	if _, err := setupPool.Exec(ctx, "INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$2,NULL),($3,$2,$1),($4,$2,$1)", pred, root, wo, emptyWO); err != nil {
		t.Fatal("fixture WorkOrder setup failed")
	}
	if _, err := setupPool.Exec(ctx, "INSERT INTO raw.work_order_dependencies(root_id,work_order_id,depends_on_id) VALUES($1,$2,$3)", root, wo, pred); err != nil {
		t.Fatal("fixture dependency setup failed")
	}

	var ready bool
	if err := appPool.QueryRow(ctx, "SELECT raw.mark_work_order_pull_ready($1)", wo).Scan(&ready); err != nil || ready {
		t.Fatal("unconfigured WorkOrder or pending predecessor became ready")
	}
	if _, err := setupPool.Exec(ctx, "UPDATE raw.work_orders SET pull_state='DONE' WHERE work_order_id=$1", pred); err != nil {
		t.Fatal("fixture predecessor update failed")
	}
	if err := appPool.QueryRow(ctx, "SELECT raw.mark_work_order_pull_ready($1)", wo).Scan(&ready); err != nil || ready {
		t.Fatal("unconfigured WorkOrder became ready")
	}
	if err := appPool.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,$2::jsonb)`, wo, `[{"name":"cpu","value":"x"}]`).Scan(&ready); err != nil {
		var dbErr *pgconn.PgError
		if errors.As(err, &dbErr) {
			t.Fatalf("capability configuration query failed (SQLSTATE %s)", dbErr.Code)
		}
		t.Fatalf("capability configuration query failed (%T)", err)
	}
	if !ready {
		t.Fatal("capability configuration returned false")
	}
	if err := appPool.QueryRow(ctx, "SELECT raw.mark_work_order_pull_ready($1)", wo).Scan(&ready); err != nil || !ready {
		t.Fatal("configured WorkOrder readiness transition failed")
	}

	// The DB function independently rejects evidence that does not equal the canonical requirement.
	var rejectedAttempt string
	err = appPool.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::interval)`, wo, workerID(suffix), "session_"+suffix, "bad_attempt_"+suffix, "bad_slot_"+suffix, `[{"name":"cpu","value":"x"}]`, `[{"name":"cpu","value":"wrong"}]`, time.Second).Scan(&rejectedAttempt)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("reservation accepted mismatched evidence")
	}
	store, err := NewPullStore(appPool)
	if err != nil {
		t.Fatal("cannot construct app PullStore")
	}
	candidate := scheduler.Candidate{WorkOrderID: wo, Requirements: []scheduler.CapabilityRequirement{{Name: "cpu", Value: "x"}}}
	worker := scheduler.Worker{ID: workerID(suffix), SessionID: "pull_it_session_" + suffix, Evidence: []scheduler.Evidence{{Name: "cpu", Value: "x"}}}
	if _, err := store.Reserve(ctx, candidate, worker, scheduler.Permit{}, leaseTTL); err == nil {
		t.Fatal("direct zero-permit bypass succeeded")
	}
	puller := scheduler.Puller{Authority: pullAllow{}, Trust: pullAllow{}, Budget: pullAllow{}, Store: store, Lifecycle: store, LeaseTTL: leaseTTL}
	mismatch := scheduler.Candidate{WorkOrderID: wo, Requirements: []scheduler.CapabilityRequirement{{Name: "cpu", Value: "different"}}}
	if _, err := puller.Pull(ctx, mismatch, scheduler.Worker{ID: worker.ID, SessionID: worker.SessionID, Evidence: []scheduler.Evidence{{Name: "cpu", Value: "different"}}}); err == nil {
		t.Fatal("candidate requirements that differ from canonical DB requirements were accepted")
	}
	const n = 2
	start := make(chan struct{})
	type pullOutcome struct {
		result scheduler.PullResult
		err    error
	}
	results := make(chan pullOutcome, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, e := puller.Pull(ctx, candidate, worker)
			results <- pullOutcome{r, e}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	var first scheduler.Reservation
	for outcome := range results {
		if outcome.err == nil {
			wins++
			first = outcome.result.Reservation
		}
	}
	if wins != 1 {
		t.Fatalf("reservation winners=%d, want exactly 1", wins)
	}
	if first.AttemptID == "" || first.SlotID == "" || first.SessionID != worker.SessionID || first.LeaseEpoch <= 0 || first.ExpiresAt.IsZero() {
		t.Fatal("Pull returned incomplete lease identity")
	}
	identity := scheduler.LeaseIdentity{WorkOrderID: wo, AttemptID: first.AttemptID, WorkerID: worker.ID, SessionID: worker.SessionID, Epoch: first.LeaseEpoch}
	ok, err := puller.Heartbeat(ctx, identity)
	if err != nil {
		t.Fatal("valid heartbeat adapter call failed")
	}
	if !ok {
		var matchingUnexpiredLease, workOrderRunning bool
		diagnosticErr := setupPool.QueryRow(ctx, `SELECT
			EXISTS (
				SELECT 1 FROM raw.work_order_leases
				WHERE work_order_id=$1 AND attempt_id=$2 AND worker_id=$3 AND session_id=$4
				  AND lease_epoch=$5 AND expires_at>clock_timestamp()
			),
			EXISTS (
				SELECT 1 FROM raw.work_orders
				WHERE work_order_id=$1 AND pull_state='RUNNING'
			)`, identity.WorkOrderID, identity.AttemptID, identity.WorkerID, identity.SessionID, identity.Epoch).Scan(&matchingUnexpiredLease, &workOrderRunning)
		if diagnosticErr != nil {
			t.Fatal("valid heartbeat returned false; read-only diagnostic unavailable")
		}
		t.Fatalf("valid heartbeat returned false (matching_unexpired_lease=%t work_order_running=%t)", matchingUnexpiredLease, workOrderRunning)
	}
	var renewedExpiry time.Time
	if err := setupPool.QueryRow(ctx, "SELECT expires_at FROM raw.work_order_leases WHERE work_order_id=$1", wo).Scan(&renewedExpiry); err != nil || !renewedExpiry.After(first.ExpiresAt) {
		t.Fatal("heartbeat did not reset expiry using DB time")
	}
	var slots, attempts int
	if err := setupPool.QueryRow(ctx, "SELECT count(*) FROM raw.work_order_pull_slots WHERE work_order_id=$1", wo).Scan(&slots); err != nil {
		t.Fatal("slot readback failed")
	}
	if err := setupPool.QueryRow(ctx, "SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=$1", wo).Scan(&attempts); err != nil {
		t.Fatal("attempt readback failed")
	}
	if slots != 1 || attempts != 1 {
		t.Fatalf("persisted slot=%d attempts=%d", slots, attempts)
	}
	// Worker is stopped: no heartbeats occur while the fixture TTL elapses.
	time.Sleep(leaseTTL + 250*time.Millisecond)
	if count, err := puller.Reap(ctx, 10); err != nil || count != 1 {
		t.Fatal("expired lease was not reaped")
	}
	var state string
	if err := setupPool.QueryRow(ctx, "SELECT pull_state FROM raw.work_orders WHERE work_order_id=$1", wo).Scan(&state); err != nil || state != "READY" {
		t.Fatal("reaper did not release WorkOrder to READY")
	}
	second, err := puller.Pull(ctx, candidate, worker)
	if err != nil {
		t.Fatal("re-pull after reaping failed")
	}
	current := second.Reservation
	if current.LeaseEpoch <= first.LeaseEpoch {
		t.Fatal("lease epoch did not increase")
	}
	var oldAttemptNo, currentAttemptNo int
	if err := setupPool.QueryRow(ctx, "SELECT attempt_number FROM raw.work_order_attempts WHERE attempt_id=$1", first.AttemptID).Scan(&oldAttemptNo); err != nil {
		t.Fatal("old attempt history missing")
	}
	if err := setupPool.QueryRow(ctx, "SELECT attempt_number FROM raw.work_order_attempts WHERE attempt_id=$1", current.AttemptID).Scan(&currentAttemptNo); err != nil || currentAttemptNo <= oldAttemptNo {
		t.Fatal("attempt history did not advance")
	}
	if ok, err := puller.Heartbeat(ctx, identity); err != nil || ok {
		t.Fatal("stale attempt heartbeat was accepted")
	}
	if ok, err := puller.Complete(ctx, identity); err != nil || ok {
		t.Fatal("late stale completion was accepted")
	}
	currentIdentity := scheduler.LeaseIdentity{WorkOrderID: wo, AttemptID: current.AttemptID, WorkerID: worker.ID, SessionID: worker.SessionID, Epoch: current.LeaseEpoch}
	if ok, err := puller.Complete(ctx, currentIdentity); err != nil || !ok {
		t.Fatal("current lease completion failed")
	}
	if err := setupPool.QueryRow(ctx, "SELECT pull_state FROM raw.work_orders WHERE work_order_id=$1", wo).Scan(&state); err != nil || state != "DONE" {
		t.Fatal("completion did not mark WorkOrder DONE")
	}
	if err := setupPool.QueryRow(ctx, "SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=$1", wo).Scan(&attempts); err != nil || attempts != 2 {
		t.Fatal("attempt history was not append-only")
	}

	// An explicitly configured empty policy is unconstrained only when both are empty.
	if err := appPool.QueryRow(ctx, "SELECT raw.mark_work_order_pull_ready($1)", emptyWO).Scan(&ready); err != nil || ready {
		t.Fatal("unconfigured empty WorkOrder became ready")
	}
	if err := appPool.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, emptyWO).Scan(&ready); err != nil || !ready {
		t.Fatal("explicit empty capability configuration failed")
	}
	if err := appPool.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,'[{"name":"cpu","value":"x"}]'::jsonb)`, emptyWO).Scan(&ready); err != nil || ready {
		t.Fatal("one-time capability configuration allowed replacement")
	}
	if err := appPool.QueryRow(ctx, "SELECT raw.mark_work_order_pull_ready($1)", emptyWO).Scan(&ready); err != nil || !ready {
		t.Fatal("explicit empty policy readiness failed")
	}
	err = appPool.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::interval)`, emptyWO, worker.ID, worker.SessionID, "bad_empty_attempt_"+suffix, "bad_empty_slot_"+suffix, `[]`, `[{"name":"cpu","value":"x"}]`, time.Second).Scan(&rejectedAttempt)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("empty policy accepted non-empty evidence")
	}
	if _, err := puller.Pull(ctx, scheduler.Candidate{WorkOrderID: emptyWO}, scheduler.Worker{ID: worker.ID, SessionID: worker.SessionID}); err != nil {
		t.Fatal("explicit empty policy reservation failed")
	}
	if _, err := puller.Pull(ctx, scheduler.Candidate{WorkOrderID: emptyWO}, scheduler.Worker{ID: worker.ID, SessionID: worker.SessionID, Evidence: []scheduler.Evidence{{Name: "cpu", Value: "x"}}}); err == nil {
		t.Fatal("explicit empty policy accepted non-empty worker evidence")
	}
}

func openPullPool(ctx context.Context, url string, requireApp bool) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid connection configuration")
	}
	cfg.MaxConns = 4
	if requireApp {
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			var database, user string
			if err := conn.QueryRow(ctx, "SELECT current_database(), current_user").Scan(&database, &user); err != nil || database != "paddock_test" || user != "paddock_app" {
				return errors.New("app connection identity mismatch")
			}
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("connection failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("connection failed")
	}
	return pool, nil
}

func checkPullPrivileges(ctx context.Context, pool *pgxpool.Pool) error {
	var directAccess, columnAccess, extraFunctionExecute, app_exec, public_exec bool
	err := pool.QueryRow(ctx, `WITH expected(oid) AS (VALUES
	 ('raw.configure_work_order_capabilities(text,jsonb)'::regprocedure::oid),
	 ('raw.mark_work_order_pull_ready(text)'::regprocedure::oid),
	 ('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)'::regprocedure::oid),
	 ('raw.heartbeat_work_order_lease(text,text,text,text,bigint,interval)'::regprocedure::oid),
	 ('raw.reap_work_order_leases(integer)'::regprocedure::oid),
	 ('raw.complete_work_order_lease(text,text,text,text,bigint)'::regprocedure::oid),
	 ('raw.configure_work_order_offline_policy(text,text,text,text,bytea,text)'::regprocedure::oid),
	 ('raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text)'::regprocedure::oid),
	 ('raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text)'::regprocedure::oid),
	 ('raw.budget_apply(text,text,jsonb)'::regprocedure::oid)
	 ) SELECT
	 EXISTS (SELECT 1 FROM unnest(ARRAY['work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_capability_requirements','work_order_leases','budget_accounts','budget_allocations','budget_operations','budget_journal']) AS tab(name) CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) AS priv(name) WHERE has_table_privilege('paddock_app','raw.'||tab.name,priv.name)),
	 (EXISTS (SELECT 1 FROM unnest(ARRAY['work_orders','work_order_dependencies','work_order_attempts','work_order_pull_slots','work_order_capability_requirements','work_order_leases','budget_accounts','budget_allocations','budget_operations','budget_journal']) AS tab(name) CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) AS priv(name) WHERE has_any_column_privilege('paddock_app','raw.'||tab.name,priv.name)) OR EXISTS (SELECT 1 FROM unnest(ARRAY['offline_policy_mode','checkpointability','policy_canonical','policy_digest','external_action_allowlist','low_risk_actions']) AS col(name) CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) AS priv(name) WHERE has_column_privilege('paddock_app','raw.work_orders',col.name,priv.name))),
	 EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='raw' AND p.prorettype <> 'trigger'::regtype AND has_function_privilege('paddock_app',p.oid,'EXECUTE') AND NOT EXISTS (SELECT 1 FROM expected e WHERE e.oid=p.oid)),
	 (SELECT count(*)=10 AND bool_and(has_function_privilege('paddock_app',p.oid,'EXECUTE') AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']) FROM expected e JOIN pg_catalog.pg_proc p ON p.oid=e.oid),
	 EXISTS (SELECT 1 FROM expected e, LATERAL aclexplode(COALESCE((SELECT p.proacl FROM pg_catalog.pg_proc p WHERE p.oid=e.oid),acldefault('f',(SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=e.oid)))) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')`).Scan(&directAccess, &columnAccess, &extraFunctionExecute, &app_exec, &public_exec)
	if err != nil || directAccess || columnAccess || extraFunctionExecute || !app_exec || public_exec {
		return errors.New("privilege contract mismatch")
	}
	return nil
}
