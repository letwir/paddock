//go:build paddock_test

package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
)

// This is an explicit opt-in DB-write integration test. It requires an isolated
// paddock_test database with the M08 offline-policy migration already applied;
// it never applies migrations, prints DSNs, or performs network effects.
func TestOfflinePolicySnapshotIntegration(t *testing.T) {
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required for the opt-in paddock_test DB-write test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	setup, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect privileged fixture database")
	}
	t.Cleanup(setup.Close)
	var db string
	if err := setup.QueryRow(ctx, "SELECT current_database()").Scan(&db); err != nil || db != "paddock_test" {
		t.Fatal("privileged fixture connection must target exact database paddock_test")
	}
	appPool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("app connection must target paddock_test as paddock_app")
	}
	t.Cleanup(appPool.Close)

	var schemaOK bool
	err = setup.QueryRow(ctx, `SELECT
		to_regprocedure('raw.configure_work_order_offline_policy(text,text,text,text,bytea,text)') IS NOT NULL
		AND to_regprocedure('raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text)') IS NOT NULL
		AND (SELECT count(*)=6 FROM information_schema.columns WHERE table_schema='raw' AND table_name='work_orders'
		 AND column_name=ANY(ARRAY['offline_policy_mode','checkpointability','policy_canonical','policy_digest','external_action_allowlist','low_risk_actions']))
		AND to_regprocedure('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)') IS NOT NULL`).Scan(&schemaOK)
	if err != nil || !schemaOK {
		t.Skip("required M08 snapshot/policy schema absent; apply migrations separately before running this opt-in test")
	}
	var direct, appExecute, publicExecute bool
	err = setup.QueryRow(ctx, `SELECT
	 has_table_privilege('paddock_app','raw.work_orders','SELECT'),
	 has_function_privilege('paddock_app','raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text)','EXECUTE')
	 AND has_function_privilege('paddock_app','raw.configure_work_order_offline_policy(text,text,text,text,bytea,text)','EXECUTE'),
	 EXISTS (SELECT 1 FROM (VALUES ('raw.read_work_order_authorization(text,text,text,text,text,bigint,text,text)'::regprocedure),('raw.configure_work_order_offline_policy(text,text,text,text,bytea,text)'::regprocedure)) f(p) CROSS JOIN LATERAL aclexplode(COALESCE((SELECT proacl FROM pg_proc WHERE oid=f.p),acldefault('f',(SELECT proowner FROM pg_proc WHERE oid=f.p)))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')`).Scan(&direct, &appExecute, &publicExecute)
	if err != nil || direct || !appExecute || publicExecute {
		t.Fatal("snapshot authorization privilege contract mismatch")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope, root, wo := "offline_it_scope_"+suffix, "offline_it_root_"+suffix, "offline_it_wo_"+suffix
	attempt, slot, worker, session := "offline_it_attempt_"+suffix, "offline_it_slot_"+suffix, "offline_it_worker_"+suffix, "offline_it_session_"+suffix
	var collision bool
	err = setup.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM raw.policy_scopes WHERE scope_id=$1) OR
		EXISTS (SELECT 1 FROM raw.roots WHERE root_id=$2) OR
		EXISTS (SELECT 1 FROM raw.work_orders WHERE work_order_id=$3) OR
		EXISTS (SELECT 1 FROM raw.work_order_attempts WHERE attempt_id=$4) OR
		EXISTS (SELECT 1 FROM raw.work_order_pull_slots WHERE slot_id=$5)`, scope, root, wo, attempt, slot).Scan(&collision)
	if err != nil || collision {
		t.Fatal("generated fixture identifier collision preflight failed")
	}
	// Registered before seeding so exact test-owned rows are removed first.
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"DELETE FROM raw.work_order_leases WHERE work_order_id=$1 AND attempt_id=$2", []any{wo, attempt}},
			{"DELETE FROM raw.work_order_pull_slots WHERE work_order_id=$1 AND slot_id=$2", []any{wo, slot}},
			{"DELETE FROM raw.work_order_capability_requirements WHERE work_order_id=$1", []any{wo}},
			{"DELETE FROM raw.work_order_attempts WHERE work_order_id=$1 AND attempt_id=$2", []any{wo, attempt}},
			{"DELETE FROM raw.work_orders WHERE work_order_id=$1 AND root_id=$2", []any{wo, root}},
			{"DELETE FROM raw.roots WHERE root_id=$1 AND scope_id=$2", []any{root, scope}},
			{"DELETE FROM raw.policy_scopes WHERE scope_id=$1", []any{scope}},
		} {
			if _, e := setup.Exec(c, q.sql, q.args...); e != nil {
				t.Errorf("exact fixture cleanup failed")
			}
		}
	})
	if _, err := setup.Exec(ctx, `INSERT INTO raw.policy_scopes(scope_id,mode) VALUES($1,'SAFE_STOPPED')`, scope); err != nil {
		t.Fatal("fixture scope setup failed")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.roots(root_id,scope_id,safe_baseline) VALUES($1,$2,true)`, root, scope); err != nil {
		t.Fatal("fixture root setup failed")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$2,NULL)`, wo, root); err != nil {
		t.Fatal("fixture WorkOrder setup failed")
	}

	store := NewOfflinePolicyStore(appPool)
	policy := domain.WorkOrderPolicy{Mode: domain.OnlineRequired, Checkpoint: domain.Checkpointable, ExternalActions: []string{"read", "write"}, LowRiskActions: []string{"read"}}
	digest, err := store.Configure(ctx, domain.RootID(root), domain.WorkOrderID(wo), policy)
	if err != nil {
		t.Fatal("app-role policy configuration failed")
	}
	var ready bool
	if err := appPool.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, wo).Scan(&ready); err != nil || !ready {
		t.Fatal("empty capability configuration failed")
	}
	if err := appPool.QueryRow(ctx, `SELECT raw.mark_work_order_pull_ready($1)`, wo).Scan(&ready); err != nil || !ready {
		t.Fatal("WorkOrder readiness transition failed")
	}
	var gotAttempt, gotSlot string
	var epoch int64
	if err := appPool.QueryRow(ctx, `SELECT attempt_id,slot_id,lease_epoch FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,$6::interval)`, wo, worker, session, attempt, slot, "5 seconds").Scan(&gotAttempt, &gotSlot, &epoch); err != nil || gotAttempt != attempt || gotSlot != slot || epoch <= 0 {
		t.Fatal("app-role lease reservation failed")
	}
	authorizer := NewOfflinePolicyAuthorizer(appPool)
	op := application.GatewayOperation{RootID: domain.RootID(root), WorkOrderID: domain.WorkOrderID(wo), AttemptID: attempt, WorkerID: worker, SessionID: session, LeaseEpoch: domain.Epoch(epoch), PolicyDigest: domain.Digest(digest), Action: "read"}
	check := func(action string, allowed bool, risk application.AuthorizationRisk, positive bool) {
		t.Helper()
		op.Action = action
		s, e := authorizer.ReadAuthorization(ctx, op)
		if e != nil || s.Allowed != allowed || s.Risk != risk || (s.LeaseRemaining > 0) != positive {
			t.Fatalf("authorization snapshot mismatch for action %q", action)
		}
	}
	check("read", true, application.AuthorizationRiskLow, true)
	check("write", true, application.AuthorizationRiskHigh, true)
	check("external-not-allowlisted", false, application.AuthorizationRiskHigh, false)
	for _, mutate := range []func(*application.GatewayOperation){func(x *application.GatewayOperation) { x.LeaseEpoch++ }, func(x *application.GatewayOperation) {
		x.PolicyDigest = domain.Digest("0000000000000000000000000000000000000000000000000000000000000000")
	}, func(x *application.GatewayOperation) { x.WorkerID += "_wrong" }} {
		op.Action = "read"
		mutate(&op)
		s, e := authorizer.ReadAuthorization(ctx, op)
		if e != nil || s.Allowed {
			t.Fatal("snapshot accepted mismatched lease identity or digest")
		}
		op.LeaseEpoch = domain.Epoch(epoch)
		op.PolicyDigest = domain.Digest(digest)
		op.WorkerID = worker
	}
	if _, err := setup.Exec(ctx, `UPDATE raw.work_order_leases SET issued_at=clock_timestamp()-interval '10 seconds',heartbeat_at=clock_timestamp()-interval '5 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE work_order_id=$1 AND attempt_id=$2 AND worker_id=$3 AND lease_epoch=$4`, wo, attempt, worker, epoch); err != nil {
		t.Fatal("privileged exact lease expiry fixture update failed")
	}
	check("write", false, application.AuthorizationRiskHigh, false)
}
