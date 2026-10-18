//go:build paddock_test

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

// D_worker=HARD (same EASY<MEDIUM<HARD scale as D_pub): this single source
// fixture crosses SECURITY DEFINER APIs, root-serialized persistent limits,
// semantic DAG hashing, operation replay, DB time, and atomic Lease/Attempt
// enforcement. Evidence observed before writing: Issues.md PDK-M09-S02 selected
// design lines 482-497; spawn_store.go calls spawn_policy_set/spawn_admit and
// computes domain.SemanticFingerprints; governance_spawn_policy.sql implements
// the root lock, admission caps, ledger, and Lease retry cap; pull_integration_test.go
// establishes the opt-in DB role/pool and exact-cleanup patterns. All required
// boundaries are known, so D_worker does not exceed D_pub=HARD.
//
// This test is strictly opt-in. It requires separately provisioned migrations
// and test-only database URLs; it never applies migrations or prints a DSN.
func TestSpawnAdmissionIntegration(t *testing.T) {
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required for the opt-in paddock_test test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	setup, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect privileged fixture database")
	}
	t.Cleanup(setup.Close)
	var database string
	if err := setup.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil || database != "paddock_test" {
		t.Fatal("fixture connection must target exact database paddock_test")
	}
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("application connection must authenticate as paddock_app on paddock_test")
	}
	t.Cleanup(app.Close)
	var appDatabase, sessionUser, currentUser string
	if err := app.QueryRow(ctx, `SELECT current_database(), session_user, current_user`).Scan(&appDatabase, &sessionUser, &currentUser); err != nil || appDatabase != "paddock_test" || sessionUser != "paddock_app" || currentUser != "paddock_app" {
		t.Fatal("application connection must use paddock_app in exact database paddock_test")
	}
	store, err := NewSpawnStore(app)
	if err != nil {
		t.Fatal("SpawnStore construction failed")
	}

	var schemaOK bool
	if err := setup.QueryRow(ctx, `SELECT
		to_regprocedure('raw.spawn_fingerprint_context(text,text)') IS NOT NULL AND
		to_regprocedure('raw.spawn_policy_set(text,text,jsonb)') IS NOT NULL AND
		to_regprocedure('raw.spawn_admit(text,text,jsonb,text,text,jsonb)') IS NOT NULL AND
		to_regprocedure('raw.issue_work_order_lease(text,text,text,text,text,jsonb,jsonb,interval)') IS NOT NULL AND
		to_regclass('raw.spawn_policies') IS NOT NULL AND to_regclass('raw.spawn_operations') IS NOT NULL AND
		to_regclass('raw.spawn_fingerprints') IS NOT NULL`).Scan(&schemaOK); err != nil || !schemaOK {
		t.Fatalf("M09-S02 schema absent; apply its migration separately before running this opt-in test")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	// Every fixture identifier is deliberately prefixed, deterministic within
	// this run, and collision-checked before any rows are created.
	ids := spawnFixtureIDs(suffix)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("spawn_it_bundle_"+suffix)))
	var collision bool
	if err := setup.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM raw.policy_scopes WHERE scope_id=ANY($1::text[])) OR
		EXISTS(SELECT 1 FROM raw.roots WHERE root_id=ANY($2::text[])) OR
		EXISTS(SELECT 1 FROM raw.policy_bundles WHERE bundle_digest=$7) OR
		EXISTS(SELECT 1 FROM raw.work_orders WHERE work_order_id=ANY($3::text[])) OR
		EXISTS(SELECT 1 FROM raw.spawn_operations WHERE operation_id=ANY($4::text[])) OR
		EXISTS(SELECT 1 FROM raw.work_order_attempts WHERE attempt_id=ANY($5::text[])) OR
		EXISTS(SELECT 1 FROM raw.work_order_pull_slots WHERE slot_id=ANY($6::text[])) OR
		EXISTS(SELECT 1 FROM raw.work_order_leases WHERE worker_id=$8 OR session_id=$9) OR
		EXISTS(SELECT 1 FROM raw.work_order_pull_slots WHERE worker_id=$8)`,
		ids.scopes(), ids.roots(), ids.workOrders(), ids.operations(), ids.attempts(), ids.slots(), digest, ids.worker(), ids.session()).Scan(&collision); err != nil || collision {
		t.Fatal("fixture identifier collision preflight failed")
	}
	// Register cleanup before setup. Each DELETE is restricted to exact IDs
	// allocated by this fixture; do not broaden these predicates.
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM raw.spawn_operations WHERE root_id=ANY($1::text[]) AND operation_id=ANY($2::text[])`, []any{ids.roots(), ids.operations()}},
			{`DELETE FROM raw.spawn_fingerprints WHERE root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_order_leases l USING raw.work_orders w WHERE l.work_order_id=w.work_order_id AND w.root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_order_pull_slots l USING raw.work_orders w WHERE l.work_order_id=w.work_order_id AND w.root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_order_capability_requirements c USING raw.work_orders w WHERE c.work_order_id=w.work_order_id AND w.root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_order_dependencies WHERE root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_order_attempts a USING raw.work_orders w WHERE a.work_order_id=w.work_order_id AND w.root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.work_orders WHERE root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.spawn_policies WHERE root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.roots WHERE root_id=ANY($1::text[])`, []any{ids.roots()}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id=ANY($1::text[])`, []any{ids.scopes()}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest=$1`, []any{digest}},
		} {
			if _, e := setup.Exec(c, q.sql, q.args...); e != nil {
				t.Errorf("exact Spawn fixture cleanup failed")
			}
		}
	})
	if _, err := setup.Exec(ctx, `INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,'spawn_it/1',$3,$4)`, digest, []byte(`{"fixture":"spawn_it"}`), "spawn_it_signer_"+suffix, []byte("fixture-signature")); err != nil {
		t.Fatal("fixture policy bundle setup failed")
	}

	// Distinct Roots isolate policy limits so each negative case does not rely
	// on mutating an immutable policy. Every Root starts with one depth-zero node.
	policies := []domain.SpawnPolicy{
		spawnPolicy(4, 20, 10, 2, 2, time.Now().Add(2*time.Hour)),   // DAG/fingerprint/replay
		spawnPolicy(1, 10, 10, 2, 10, time.Now().Add(2*time.Hour)),  // depth
		spawnPolicy(4, 1, 10, 2, 10, time.Now().Add(2*time.Hour)),   // descendants
		spawnPolicy(4, 10, 1, 2, 10, time.Now().Add(2*time.Hour)),   // direct live children
		spawnPolicy(4, 10, 10, 1, 10, time.Now().Add(2*time.Hour)),  // Lease cap
		spawnPolicy(4, 10, 10, 2, 10, time.Now().Add(-time.Minute)), // DB deadline
	}
	roots := ids.roots()
	for i, root := range roots {
		scope, parent := ids.scope(i), ids.parent(i)
		if _, err := setup.Exec(ctx, `INSERT INTO raw.policy_scopes(scope_id,mode) VALUES($1,'SAFE_STOPPED')`, scope); err != nil {
			t.Fatal("fixture Scope setup failed")
		}
		if _, err := setup.Exec(ctx, `INSERT INTO raw.roots(root_id,scope_id,effective_bundle_digest,safe_baseline) VALUES($1,$2,$3,false)`, root, scope, digest); err != nil {
			t.Fatal("fixture Root setup failed")
		}
		if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id,policy_digest) VALUES($1,$2,NULL,NULL)`, parent, root); err != nil {
			t.Fatal("fixture Root WorkOrder setup failed")
		}
		policyDigest, err := NewOfflinePolicyStore(app).Configure(ctx, domain.RootID(root), domain.WorkOrderID(parent), domain.WorkOrderPolicy{
			Mode: domain.OnlineRequired, Checkpoint: domain.Checkpointable,
			ExternalActions: []string{"read", "write"}, LowRiskActions: []string{"read"},
		})
		if err != nil || policyDigest == "" {
			t.Fatal("trusted app-role WorkOrder offline policy setup failed")
		}
		if i == 6 {
			continue
		}
		if _, err := store.SetPolicy(ctx, root, ids.policyOperation(i), policies[i]); err != nil {
			t.Fatal("trusted app-role immutable Root policy setup failed")
		}
	}

	// Policy is Root-wide and immutable; exact operation replay is idempotent,
	// while a changed request under that operation ID must conflict.
	policyReplay, err := store.SetPolicy(ctx, roots[0], ids.policyOperation(0), policies[0])
	if err != nil || len(policyReplay) == 0 {
		t.Fatal("identical policy operation replay failed")
	}
	changedPolicy := policies[0]
	changedPolicy.MaxLiveChildren++
	if _, err := store.SetPolicy(ctx, roots[0], ids.policyOperation(0), changedPolicy); err == nil {
		t.Fatal("changed policy request reused operation ID")
	}
	if _, err := store.SetPolicy(ctx, roots[0], ids.secondPolicyOperation(), policies[0]); err == nil {
		t.Fatal("second operation changed immutable Root policy")
	}

	// Semantic DAG fingerprints ignore temporary keys recursively. Repeat
	// admission reaches the configured per-fingerprint limit; a further new
	// operation with fresh task keys must be rejected. Request array ordering
	// is not a topological contract: these valid DAGs list dependents first.
	parent0 := ids.parent(0)
	requestA := spawnRequest(parent0, "c", "b", "a")
	requestB := spawnRequest(parent0, "z", "y", "x")
	requestA.Tasks[0].DependsOn = []string{"b"}
	requestA.Tasks[1].DependsOn = []string{"a"}
	requestB.Tasks[0].DependsOn = []string{"y"}
	requestB.Tasks[1].DependsOn = []string{"x"}
	fpa, err := spawnFingerprints(requestA)
	if err != nil {
		t.Fatal("fingerprint DAG A invalid")
	}
	fpb, err := spawnFingerprints(requestB)
	if err != nil {
		t.Fatal("fingerprint DAG B invalid")
	}
	for _, key := range []string{"a", "b", "c"} {
		other := map[string]string{"a": "x", "b": "y", "c": "z"}[key]
		if fpa[key] != fpb[other] {
			t.Fatal("semantic DAG fingerprint changed under temporary-key renaming")
		}
	}
	reqA, _ := json.Marshal(requestA)
	first, err := store.Spawn(ctx, roots[0], ids.spawnOperation(0), reqA)
	if err != nil {
		t.Fatalf("initial Spawn admission failed: %v", err)
	}
	replay, err := store.Spawn(ctx, roots[0], ids.spawnOperation(0), reqA)
	if err != nil || string(first) != string(replay) {
		t.Fatal("exact Spawn operation replay did not return prior result")
	}
	altered := requestA
	altered.Tasks[0].Goal = "changed goal"
	alteredJSON, _ := json.Marshal(altered)
	if _, err := store.Spawn(ctx, roots[0], ids.spawnOperation(0), alteredJSON); err == nil {
		t.Fatal("changed Spawn request reused operation ID")
	}
	requestBJSON, _ := json.Marshal(requestB)
	if _, err := store.Spawn(ctx, roots[0], ids.spawnOperation(1), requestBJSON); err != nil {
		t.Fatal("renamed equivalent DAG admission failed")
	}
	if _, err := store.Spawn(ctx, roots[0], ids.spawnOperation(2), spawnSingle(parent0, "repeat_cap", "same goal")); err == nil {
		t.Fatal("Root repeat fingerprint limit was bypassed with a fresh operation/key")
	}
	var persistedEdges int
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_order_dependencies WHERE root_id=$1`, roots[0]).Scan(&persistedEdges); err != nil || persistedEdges != 4 {
		t.Fatal("Spawn dependency DAG edges were not persisted exactly")
	}

	// Root depth and total-descendant caps.
	if _, err := store.Spawn(ctx, roots[1], ids.spawnOperation(3), spawnSingle(ids.parent(1), "depth_child", "depth cap")); err != nil {
		t.Fatal("first-level child admission failed")
	}
	var depthChild string
	if err := setup.QueryRow(ctx, `SELECT work_order_id FROM raw.work_orders WHERE root_id=$1 AND parent_id=$2`, roots[1], ids.parent(1)).Scan(&depthChild); err != nil {
		t.Fatal("depth child lookup failed")
	}
	if _, err := store.Spawn(ctx, roots[1], ids.spawnOperation(4), spawnSingle(depthChild, "too_deep", "depth cap")); err == nil {
		t.Fatal("Root depth cap exceeded")
	}
	if _, err := store.Spawn(ctx, roots[2], ids.spawnOperation(5), spawnPair(ids.parent(2))); err == nil {
		t.Fatal("Root total-descendant cap exceeded")
	}
	// Simultaneous distinct requests must serialize on the Root and enforce the
	// max_live_children=1 cap atomically.
	start := make(chan struct{})
	type spawnResult struct {
		operation string
		err       error
	}
	results := make(chan spawnResult, 2)
	for n, operation := range []string{ids.spawnOperation(6), ids.spawnOperation(7)} {
		goal := fmt.Sprintf("concurrent live child task %d", n)
		request := spawnSingle(ids.parent(3), fmt.Sprintf("live_concurrent_%d", n), goal)
		go func(op string, req json.RawMessage) {
			<-start
			_, err := store.Spawn(ctx, roots[3], op, req)
			results <- spawnResult{operation: op, err: err}
		}(operation, request)
	}
	close(start)
	capResults := []spawnResult{<-results, <-results}
	succeeded, failed := 0, 0
	for _, result := range capResults {
		if result.err == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("concurrent live-child cap admitted %d and denied %d; want one each", succeeded, failed)
	}
	var liveChildren, liveOperations int
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_orders WHERE root_id=$1 AND parent_id=$2 AND work_order_id<>$2`, roots[3], ids.parent(3)).Scan(&liveChildren); err != nil || liveChildren != 1 {
		t.Fatal("concurrent live-child cap did not persist exactly one child")
	}
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.spawn_operations WHERE root_id=$1 AND operation_id=ANY($2::text[])`, roots[3], []string{ids.spawnOperation(6), ids.spawnOperation(7)}).Scan(&liveOperations); err != nil || liveOperations != 1 {
		t.Fatal("concurrent live-child cap did not persist exactly one operation ledger row")
	}
	// Deadline is evaluated by PostgreSQL clock, including a deliberately past deadline.
	if _, err := store.Spawn(ctx, roots[5], ids.spawnOperation(8), spawnSingle(ids.parent(5), "late", "expired deadline")); err == nil {
		t.Fatal("DB-clock elapsed Root deadline accepted Spawn")
	}

	// First attempt remains compatible without SpawnPolicy; configured Root
	// policy then permits exactly one Lease attempt and denies a retry.
	leaseWO := ids.leaseWorkOrder()
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id,policy_digest) VALUES($1,$2,$3,NULL)`, leaseWO, roots[4], ids.parent(4)); err != nil {
		t.Fatal("Lease fixture WorkOrder setup failed")
	}
	var configured bool
	if err := app.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, leaseWO).Scan(&configured); err != nil || !configured {
		t.Fatal("Lease capability setup failed")
	}
	var ready bool
	if err := app.QueryRow(ctx, `SELECT raw.mark_work_order_pull_ready($1)`, leaseWO).Scan(&ready); err != nil || !ready {
		t.Fatal("Lease fixture was not made READY")
	}
	for i := 0; i < 2; i++ {
		attempt, slot := ids.attempt(i), ids.slot(i)
		var gotAttempt string
		err := app.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,'5 seconds'::interval)`, leaseWO, ids.worker(), ids.session(), attempt, slot).Scan(&gotAttempt)
		if i == 0 && (err != nil || gotAttempt != attempt) {
			t.Fatal("first Lease attempt was not admitted")
		}
		if i == 1 && err == nil {
			t.Fatal("retry exceeded Root attempt cap")
		}
		if i == 1 { // Re-arm only this fixture row; preserve the persisted Attempt for cap verification.
			if _, e := setup.Exec(ctx, `UPDATE raw.work_orders SET pull_state='READY' WHERE work_order_id=$1`, leaseWO); e != nil {
				t.Fatal("Lease retry fixture rearm failed")
			}
			err = app.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,'5 seconds'::interval)`, leaseWO, ids.worker(), ids.session(), attempt, slot).Scan(&gotAttempt)
			if err == nil {
				t.Fatal("retry exceeded Root attempt cap after READY rearm")
			}
		}
	}

	// Compatibility path: this distinct Root has a finite, compatible offline
	// WorkOrder policy and READY capability setup, but intentionally no
	// SpawnPolicy. It permits one initial Lease/Attempt and denies a retry.
	unconfiguredRoot, unconfiguredWO := ids.root(6), ids.leaseWorkOrder(6)
	var spawnPolicyExists bool
	if err := setup.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.spawn_policies WHERE root_id=$1)`, unconfiguredRoot).Scan(&spawnPolicyExists); err != nil || spawnPolicyExists {
		t.Fatal("unconfigured-root Lease fixture unexpectedly has a SpawnPolicy")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id,policy_digest) VALUES($1,$2,$3,NULL)`, unconfiguredWO, unconfiguredRoot, ids.parent(6)); err != nil {
		t.Fatal("unconfigured-root Lease WorkOrder setup failed")
	}
	var unconfiguredCapabilityConfigured bool
	if err := app.QueryRow(ctx, `SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, unconfiguredWO).Scan(&unconfiguredCapabilityConfigured); err != nil || !unconfiguredCapabilityConfigured {
		t.Fatal("unconfigured-root Lease capability setup failed")
	}
	var unconfiguredReady bool
	if err := app.QueryRow(ctx, `SELECT raw.mark_work_order_pull_ready($1)`, unconfiguredWO).Scan(&unconfiguredReady); err != nil || !unconfiguredReady {
		t.Fatal("unconfigured-root Lease fixture was not made READY")
	}
	var unconfiguredGotAttempt string
	if err := app.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,'5 seconds'::interval)`, unconfiguredWO, ids.worker(), ids.session(), ids.attempt(2), ids.slot(2)).Scan(&unconfiguredGotAttempt); err != nil || unconfiguredGotAttempt != ids.attempt(2) {
		t.Fatal("initial Lease attempt without SpawnPolicy was not admitted")
	}
	if _, err := setup.Exec(ctx, `UPDATE raw.work_orders SET pull_state='READY' WHERE work_order_id=$1`, unconfiguredWO); err != nil {
		t.Fatal("unconfigured-root Lease fixture rearm failed")
	}
	if err := app.QueryRow(ctx, `SELECT attempt_id FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,'5 seconds'::interval)`, unconfiguredWO, ids.worker(), ids.session(), ids.attempt(3), ids.slot(3)).Scan(&unconfiguredGotAttempt); err == nil {
		t.Fatal("retry without SpawnPolicy was admitted")
	}
	var unconfiguredAttempts int
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=$1`, unconfiguredWO).Scan(&unconfiguredAttempts); err != nil || unconfiguredAttempts != 1 {
		t.Fatal("unconfigured-root retry changed persisted Attempt count")
	}
}

type spawnIDs struct{ suffix string }

func (i spawnIDs) scopes() []string {
	return []string{i.scope(0), i.scope(1), i.scope(2), i.scope(3), i.scope(4), i.scope(5), i.scope(6)}
}
func (i spawnIDs) roots() []string {
	return []string{i.root(0), i.root(1), i.root(2), i.root(3), i.root(4), i.root(5), i.root(6)}
}
func (i spawnIDs) scope(n int) string  { return fmt.Sprintf("spawn_it_scope_%s_%d", i.suffix, n) }
func (i spawnIDs) root(n int) string   { return fmt.Sprintf("spawn_it_root_%s_%d", i.suffix, n) }
func (i spawnIDs) parent(n int) string { return fmt.Sprintf("spawn_it_parent_%s_%d", i.suffix, n) }
func (i spawnIDs) leaseWorkOrder(n ...int) string {
	index := 4
	if len(n) > 0 {
		index = n[0]
	}
	return fmt.Sprintf("spawn_it_lease_%s_%d", i.suffix, index)
}
func (i spawnIDs) workOrders() []string {
	return []string{i.parent(0), i.parent(1), i.parent(2), i.parent(3), i.parent(4), i.parent(5), i.parent(6), i.leaseWorkOrder(), i.leaseWorkOrder(6)}
}
func (i spawnIDs) policyOperation(n int) string {
	return fmt.Sprintf("spawn_it_policy_%s_%d", i.suffix, n)
}
func (i spawnIDs) secondPolicyOperation() string { return "spawn_it_policy_second_" + i.suffix }
func (i spawnIDs) spawnOperation(n int) string {
	return fmt.Sprintf("spawn_it_spawn_%s_%d", i.suffix, n)
}
func (i spawnIDs) operations() []string {
	return []string{i.policyOperation(0), i.policyOperation(1), i.policyOperation(2), i.policyOperation(3), i.policyOperation(4), i.policyOperation(5), i.policyOperation(6), i.secondPolicyOperation(), i.spawnOperation(0), i.spawnOperation(1), i.spawnOperation(2), i.spawnOperation(3), i.spawnOperation(4), i.spawnOperation(5), i.spawnOperation(6), i.spawnOperation(7), i.spawnOperation(8)}
}
func (i spawnIDs) attempts() []string {
	return []string{i.attempt(0), i.attempt(1), i.attempt(2), i.attempt(3)}
}
func (i spawnIDs) attempt(n int) string { return fmt.Sprintf("spawn_it_attempt_%s_%d", i.suffix, n) }
func (i spawnIDs) slots() []string      { return []string{i.slot(0), i.slot(1), i.slot(2), i.slot(3)} }
func (i spawnIDs) slot(n int) string    { return fmt.Sprintf("spawn_it_slot_%s_%d", i.suffix, n) }
func (i spawnIDs) worker() string       { return "spawn_it_worker_" + i.suffix }
func (i spawnIDs) session() string      { return "spawn_it_session_" + i.suffix }

const spawnTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func spawnFixtureIDs(s string) spawnIDs { return spawnIDs{suffix: s} }
func spawnPolicy(depth, descendants, live, attempts, repeats int, deadline time.Time) domain.SpawnPolicy {
	return domain.SpawnPolicy{MaxSpawnDepth: depth, MaxTotalDescendants: descendants, MaxLiveChildren: live, MaxAttemptsPerWorkOrder: attempts, MaxRepeatFingerprint: repeats, RootDeadline: deadline}
}
func spawnRequest(parent, a, b, c string) SpawnRequest {
	return SpawnRequest{ParentWorkOrderID: parent, Tasks: []SpawnTask{{Key: a, Title: "node", Goal: "same goal", Acceptance: "same acceptance", DependsOn: []string{}}, {Key: b, Title: "node", Goal: "same goal", Acceptance: "same acceptance", DependsOn: []string{}}, {Key: c, Title: "node", Goal: "same goal", Acceptance: "same acceptance", DependsOn: []string{}}}}
}
func spawnSingle(parent, key, goal string) json.RawMessage {
	b, _ := json.Marshal(SpawnRequest{ParentWorkOrderID: parent, Tasks: []SpawnTask{{Key: key, Title: "node", Goal: goal, Acceptance: "same acceptance", DependsOn: []string{}}}})
	return b
}
func spawnPair(parent string) json.RawMessage {
	b, _ := json.Marshal(SpawnRequest{ParentWorkOrderID: parent, Tasks: []SpawnTask{{Key: "pair_a", Title: "fixture task", Goal: "total cap a", Acceptance: "fixture acceptance", DependsOn: []string{}}, {Key: "pair_b", Title: "fixture task", Goal: "total cap b", Acceptance: "fixture acceptance", DependsOn: []string{}}}})
	return b
}
func spawnFingerprints(r SpawnRequest) (map[string]string, error) {
	nodes := make([]domain.SemanticNode, len(r.Tasks))
	for n, task := range r.Tasks {
		nodes[n] = domain.SemanticNode{ID: task.Key, Title: task.Title, Goal: task.Goal, Acceptance: task.Acceptance, DefinitionDigest: spawnTestDigest, PolicyDigest: spawnTestDigest, Dependencies: task.DependsOn}
	}
	return domain.SemanticFingerprints(nodes)
}
