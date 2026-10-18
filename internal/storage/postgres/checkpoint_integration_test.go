//go:build paddock_test

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/letwir/paddock/internal/governance/domain"
)

// TestCheckpointDurabilityIntegration is opt-in and requires the S03 migration
// to have been applied separately. It never applies migrations or deletes data.
func TestCheckpointDurabilityIntegration(t *testing.T) {
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	setup, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect privileged checkpoint fixture database")
	}
	defer setup.Close()
	var db, user string
	if err := setup.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&db, &user); err != nil || db != "paddock_test" || user != "paddock_migrator" {
		t.Fatal("fixture setup connection must target paddock_test as paddock_migrator")
	}
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("app connection must target paddock_test as paddock_app")
	}
	defer app.Close()
	var appDB, appSessionUser, appUser string
	if err := app.QueryRow(ctx, `SELECT current_database(),session_user,current_user`).Scan(&appDB, &appSessionUser, &appUser); err != nil || appDB != "paddock_test" || appSessionUser != "paddock_app" || appUser != "paddock_app" {
		t.Fatal("app connection must target paddock_test as paddock_app")
	}
	var schema bool
	if err := setup.QueryRow(ctx, `SELECT to_regprocedure('raw.configure_checkpoint_policy(text,bigint,bigint,text)') IS NOT NULL AND to_regprocedure('raw.store_work_order_checkpoint(text,text,text,text,bigint,bytea,bytea,bigint)') IS NOT NULL AND to_regprocedure('raw.restore_work_order_checkpoint(text)') IS NOT NULL`).Scan(&schema); err != nil || !schema {
		t.Fatalf("required checkpoint schema is absent or incomplete; apply the S03 migration separately")
	}

	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("cannot generate collision-resistant fixture identifiers")
	}
	suffix := hex.EncodeToString(random[:])
	prefix := "checkpoint_it_" + suffix
	root, scope, workOrder := "m09_it_root_"+suffix, "m09_it_scope_"+suffix, "m09_it_work_"+suffix
	attempt, worker, session, slot := "m09_it_attempt_"+suffix, "m09_it_worker_"+suffix, "m09_it_session_"+suffix, "m09_it_slot_"+suffix
	account := "m09_it_storage_" + suffix
	definitionHash := sha256.Sum256([]byte("checkpoint-it-definition-" + suffix))
	definition := hex.EncodeToString(definitionHash[:])
	policyConfig := `{"checkpointability":"CHECKPOINTABLE","external_actions":[],"low_risk_actions":[],"mode":"ONLINE_REQUIRED"}`
	policyHash := sha256.Sum256([]byte(policyConfig))
	policy := hex.EncodeToString(policyHash[:])
	ids := []string{prefix + "_valid", prefix + "_stale", prefix + "_interrupted", prefix + "_over_cap", prefix + "_tampered_manifest", prefix + "_tampered_payload", prefix + "_missing_reserve"}
	operations := make([]string, 0, len(ids)*2+1)
	for _, id := range ids {
		operations = append(operations, id+":reserve", id+":settle")
	}
	grantID := "m09_it_" + suffix + "_grant"
	collision := false
	if err := setup.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM raw.policy_scopes WHERE scope_id=$1) OR
		EXISTS(SELECT 1 FROM raw.policy_bundles WHERE bundle_digest=$2) OR
		EXISTS(SELECT 1 FROM raw.roots WHERE root_id=$3) OR
		EXISTS(SELECT 1 FROM raw.work_orders WHERE work_order_id=$4) OR
		EXISTS(SELECT 1 FROM raw.work_order_attempts WHERE attempt_id=$5) OR
		EXISTS(SELECT 1 FROM raw.budget_accounts WHERE account_id=$6) OR
		EXISTS(SELECT 1 FROM raw.work_order_checkpoints WHERE checkpoint_id=ANY($7::text[])) OR
		EXISTS(SELECT 1 FROM raw.budget_operations WHERE operation_id=ANY($8::text[])) OR
		EXISTS(SELECT 1 FROM raw.budget_operations WHERE operation_id=$9)`, scope, definition, root, workOrder, attempt, account, ids, operations, grantID).Scan(&collision); err != nil || collision {
		t.Fatal("fixture namespace collision check failed; refusing to continue")
	}
	// IDs are logged before the first write. All checkpoint/budget records remain append-only.
	t.Logf("retained checkpoint fixture IDs: scope=%s root=%s work_order=%s attempt=%s worker=%s session=%s slot=%s account=%s checkpoints=%v operations=%v grant=%s", scope, root, workOrder, attempt, worker, session, slot, account, ids, operations, grantID)

	if _, err := setup.Exec(ctx, `INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,'paddock.test/1',$3,$4)`, definition, []byte(`{"fixture":true}`), "m09_it_signer_"+suffix, []byte{1}); err != nil {
		t.Fatal("create retained checkpoint definition fixture")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.policy_scopes(scope_id,mode,baseline_bundle_digest) VALUES($1,'ACTIVE',$2)`, scope, definition); err != nil {
		t.Fatal("create retained checkpoint scope fixture")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.roots(root_id,scope_id,safe_baseline,effective_bundle_digest) VALUES($1,$2,false,$3)`, root, scope, definition); err != nil {
		t.Fatal("create retained checkpoint root fixture")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id,pull_state,lease_epoch,policy_digest) VALUES($1,$2,NULL,'QUEUED',0,NULL)`, workOrder, root); err != nil {
		t.Fatal("create retained checkpoint WorkOrder fixture")
	}
	if _, err := app.Exec(ctx, `SELECT raw.configure_work_order_offline_policy($1,$2,'ONLINE_REQUIRED','CHECKPOINTABLE',$3::bytea,$4)`, root, workOrder, []byte(policyConfig), policy); err != nil {
		t.Fatal("configure WorkOrder policy for checkpoint fixture")
	}
	// Confirm the configured digest exactly matches the immutable policy digest used in manifests.
	var actualPolicy string
	if err := setup.QueryRow(ctx, `SELECT policy_digest FROM raw.work_orders WHERE work_order_id=$1`, workOrder).Scan(&actualPolicy); err != nil || actualPolicy != policy {
		t.Fatal("checkpoint WorkOrder policy digest fixture mismatch")
	}
	if _, err := setup.Exec(ctx, `UPDATE raw.work_orders SET pull_state='RUNNING',lease_epoch=1 WHERE work_order_id=$1 AND root_id=$2 AND pull_state='QUEUED' AND lease_epoch=0 AND policy_digest=$3`, workOrder, root, policy); err != nil {
		t.Fatal("advance retained checkpoint WorkOrder fixture to RUNNING")
	}
	var running bool
	if err := setup.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.work_orders WHERE work_order_id=$1 AND pull_state='RUNNING' AND lease_epoch=1 AND policy_digest=$2)`, workOrder, policy).Scan(&running); err != nil || !running {
		t.Fatal("checkpoint WorkOrder fixture did not advance to the configured policy epoch")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_order_attempts(attempt_id,work_order_id,attempt_number) VALUES($1,$2,1)`, attempt, workOrder); err != nil {
		t.Fatal("create retained checkpoint Attempt fixture")
	}
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_order_leases(work_order_id,attempt_id,lease_epoch,worker_id,session_id,issued_at,heartbeat_at,expires_at) VALUES($1,$2,1,$3,$4,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour')`, workOrder, attempt, worker, session); err != nil {
		t.Fatal("create retained checkpoint Lease fixture")
	}
	budgetGrant := jsonResourceGrant(account, root, string(domain.ResourceStorageBytes), "byte", 1<<20)
	var grantResult []byte
	if err := setup.QueryRow(ctx, `SELECT raw.budget_apply($1,'GRANT',$2::jsonb)`, grantID, budgetGrant).Scan(&grantResult); err != nil {
		t.Fatal("create retained STORAGE_BYTES grant")
	}
	var configured bool
	if err := app.QueryRow(ctx, `SELECT raw.configure_checkpoint_policy($1,$2,$3,$4)`, root, int64(1<<16), int64(1<<20), account).Scan(&configured); err != nil || !configured {
		t.Fatal("configure finite checkpoint policy through app API")
	}

	store, err := NewCheckpointStore(app)
	if err != nil {
		t.Fatal("initialize CheckpointStore")
	}

	makeRequest := func(id string, payload []byte, epoch uint64) (domain.CheckpointRequest, []byte, int64) {
		h := sha256.Sum256(payload)
		request := domain.CheckpointRequest{OperationID: id, Payload: payload, Manifest: domain.CheckpointManifest{SchemaVersion: "paddock.checkpoint/1", RootID: root, WorkOrderID: workOrder, AttemptID: attempt, LeaseEpoch: epoch, DefinitionDigest: domain.Digest(definition), PolicyDigest: domain.Digest(policy), PayloadSHA256: hex.EncodeToString(h[:]), PayloadSize: int64(len(payload))}}
		manifest, size, e := domain.ValidateCheckpointRequest(request, domain.CheckpointPolicy{MaxBytesPerCheckpoint: 1 << 16, MaxTotalCheckpointBytes: 1 << 20})
		if e != nil {
			t.Fatalf("construct checkpoint manifest: %v", e)
		}
		return request, manifest, size
	}
	// A direct, valid app-role insert without budget_apply RESERVE must be denied.
	// Its collision-checked ID remains unused and append-only; no failed rows are retained.
	missingReserve, missingReserveManifest, missingReserveSize := makeRequest(ids[6], []byte("missing reserve payload"), 1)
	var missingReserveID, missingReserveState string
	var missingReserveBytes int64
	if err := app.QueryRow(ctx, `SELECT checkpoint_id,state,stored_bytes FROM raw.store_work_order_checkpoint($1,$2,$3,$4,$5,$6,$7,$8)`, missingReserve.OperationID, root, workOrder, attempt, int64(missingReserve.Manifest.LeaseEpoch), missingReserveManifest, missingReserve.Payload, missingReserveSize).Scan(&missingReserveID, &missingReserveState, &missingReserveBytes); err == nil {
		t.Fatal("checkpoint insert without a matching budget reservation was accepted")
	}
	var missingCheckpointCount, missingBudgetOperationCount int
	var missingReserveSpent, missingReserveReserved int64
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_order_checkpoints WHERE checkpoint_id=$1`, ids[6]).Scan(&missingCheckpointCount); err != nil || missingCheckpointCount != 0 {
		t.Fatal("rejected missing-reserve insert left a checkpoint row")
	}
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.budget_operations WHERE operation_id=ANY($1::text[])`, []string{ids[6] + ":reserve", ids[6] + ":settle"}).Scan(&missingBudgetOperationCount); err != nil || missingBudgetOperationCount != 0 {
		t.Fatal("rejected missing-reserve insert left budget operations")
	}
	if err := setup.QueryRow(ctx, `SELECT spent,reserved FROM raw.budget_accounts WHERE account_id=$1`, account).Scan(&missingReserveSpent, &missingReserveReserved); err != nil || missingReserveSpent != 0 || missingReserveReserved != 0 {
		t.Fatal("rejected missing-reserve insert changed budget balances")
	}
	payload := []byte("durable semantic checkpoint payload")
	valid, manifest, size := makeRequest(ids[0], payload, 1)
	stored, err := store.StoreCheckpoint(ctx, valid, manifest, size)
	if err != nil || stored.Status != domain.CheckpointL2 || string(stored.Payload) != string(payload) {
		t.Fatalf("valid checkpoint upload did not persist as L2 (status=%s stored=%d): %v", stored.Status, stored.StoredBytes, err)
	}
	// Restore through a separate pool so the L2 read crosses a connection boundary.
	restorePool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("open independent app connection for checkpoint restore")
	}
	defer restorePool.Close()
	var restoreDB, restoreSessionUser, restoreUser string
	if err := restorePool.QueryRow(ctx, `SELECT current_database(),session_user,current_user`).Scan(&restoreDB, &restoreSessionUser, &restoreUser); err != nil || restoreDB != "paddock_test" || restoreSessionUser != "paddock_app" || restoreUser != "paddock_app" {
		t.Fatal("restore connection must target paddock_test as paddock_app")
	}
	restoreStore, err := NewCheckpointStore(restorePool)
	if err != nil {
		t.Fatal("initialize checkpoint restore store")
	}
	restored, err := restoreStore.RestoreCheckpoint(ctx, ids[0])
	if err != nil || restored.Status != domain.CheckpointL2 || string(restored.Payload) != string(payload) {
		t.Fatal("independent connection could not restore valid L2 payload")
	}

	// Expire the exact lease with the fixture role; stale upload is retained only as metadata.
	if _, err := setup.Exec(ctx, `UPDATE raw.work_order_leases
		SET issued_at=stale.base-interval '3 seconds',
		    heartbeat_at=stale.base-interval '2 seconds',
		    expires_at=stale.base-interval '1 second'
		FROM (SELECT clock_timestamp() AS base) AS stale
		WHERE work_order_id=$1 AND attempt_id=$2`, workOrder, attempt); err != nil {
		t.Fatal("expire exact fixture Lease")
	}
	stale, staleManifest, staleSize := makeRequest(ids[1], []byte("stale payload"), 1)
	quarantined, err := store.StoreCheckpoint(ctx, stale, staleManifest, staleSize)
	if err != nil || quarantined.Status != domain.CheckpointQuarantined || len(quarantined.Payload) != 0 {
		t.Fatal("stale Lease upload was not retained as QUARANTINED metadata only")
	}
	staleRestore, err := restoreStore.RestoreCheckpoint(ctx, ids[1])
	if err != nil || staleRestore.Status != domain.CheckpointQuarantined || len(staleRestore.Payload) != 0 {
		t.Fatal("stale checkpoint restore exposed payload")
	}

	// Reproduce the store transaction through its exact budget and insert APIs,
	// then inject a DB error after INSERT but before settlement. Rollback must erase
	// both the inserted checkpoint and reserve operation.
	var spentBefore int64
	if err := setup.QueryRow(ctx, `SELECT spent FROM raw.budget_accounts WHERE account_id=$1`, account).Scan(&spentBefore); err != nil {
		t.Fatal("read budget spend before interrupted upload")
	}
	interrupted, interruptedManifest, interruptedSize := makeRequest(ids[2], []byte("interrupted"), 1)
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal("begin interrupted checkpoint transaction")
	}
	var storageAccount string
	if err := tx.QueryRow(ctx, `SELECT raw.checkpoint_storage_account($1)`, root).Scan(&storageAccount); err != nil || storageAccount != account {
		_ = tx.Rollback(ctx)
		t.Fatal("read checkpoint storage account in transaction")
	}
	if err := checkpointBudget(ctx, tx, ids[2]+":reserve", "RESERVE", storageAccount, interruptedSize, 0, 0); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("reserve budget in interrupted checkpoint transaction")
	}
	var insertedID, insertedState string
	var insertedBytes int64
	if err := tx.QueryRow(ctx, `SELECT checkpoint_id,state,stored_bytes FROM raw.store_work_order_checkpoint($1,$2,$3,$4,$5,$6,$7,$8)`, interrupted.OperationID, root, workOrder, attempt, int64(interrupted.Manifest.LeaseEpoch), interruptedManifest, interrupted.Payload, interruptedSize).Scan(&insertedID, &insertedState, &insertedBytes); err != nil || insertedID != ids[2] || insertedState != string(domain.CheckpointQuarantined) || insertedBytes != interruptedSize {
		_ = tx.Rollback(ctx)
		t.Fatal("insert checkpoint before injected settlement failure")
	}
	if _, err := tx.Exec(ctx, `SELECT 1/0`); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("injected failure after checkpoint insert unexpectedly succeeded")
	}
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal("rollback interrupted checkpoint transaction")
	}
	var checkpointCount, reserveCount, settleCount int
	var spent, reserved int64
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_order_checkpoints WHERE checkpoint_id=$1`, ids[2]).Scan(&checkpointCount); err != nil || checkpointCount != 0 {
		t.Fatal("failed upload left a checkpoint row")
	}
	if err := setup.QueryRow(ctx, `SELECT count(*) FILTER(WHERE operation_id=$1),count(*) FILTER(WHERE operation_id=$2) FROM raw.budget_operations WHERE operation_id IN ($1,$2)`, ids[2]+":reserve", ids[2]+":settle").Scan(&reserveCount, &settleCount); err != nil || reserveCount != 0 || settleCount != 0 {
		t.Fatal("failed upload left budget reservation/settlement operations")
	}
	if err := setup.QueryRow(ctx, `SELECT spent,reserved FROM raw.budget_accounts WHERE account_id=$1`, account).Scan(&spent, &reserved); err != nil || reserved != 0 || spent != spentBefore {
		t.Fatal("failed upload left budget reservation or spend")
	}

	// Policy cap denial is exercised through the public store API. Construct the
	// request against a larger caller policy so rejection is authoritative in DB.
	overCap := domain.CheckpointRequest{OperationID: ids[3], Payload: make([]byte, (1<<16)+1)}
	overHash := sha256.Sum256(overCap.Payload)
	overCap.Manifest = domain.CheckpointManifest{SchemaVersion: "paddock.checkpoint/1", RootID: root, WorkOrderID: workOrder, AttemptID: attempt, LeaseEpoch: 1, DefinitionDigest: domain.Digest(definition), PolicyDigest: domain.Digest(policy), PayloadSHA256: hex.EncodeToString(overHash[:]), PayloadSize: int64(len(overCap.Payload))}
	overManifest, overSize, err := domain.ValidateCheckpointRequest(overCap, domain.CheckpointPolicy{MaxBytesPerCheckpoint: 1 << 17, MaxTotalCheckpointBytes: 1 << 20})
	if err != nil {
		t.Fatal("construct over-cap request")
	}
	if _, err := store.StoreCheckpoint(ctx, overCap, overManifest, overSize); err == nil {
		t.Fatal("over-cap checkpoint was accepted")
	}

	// Both manifest and payload integrity are checked by the application/API boundary.
	badPayloadReq, badPayloadManifest, badPayloadSize := makeRequest(ids[5], []byte("tamper source"), 1)
	badPayloadReq.Payload = []byte("tamper sourcx")
	if _, err := store.StoreCheckpoint(ctx, badPayloadReq, badPayloadManifest, badPayloadSize); err == nil {
		t.Fatal("payload tampering was accepted")
	}
	badManifestReq, badCanonical, badCanonicalSize := makeRequest(ids[4], []byte("manifest source"), 1)
	badCanonical = bytes.Replace(badCanonical, []byte("{"), []byte(" "), 1)
	if _, err := store.StoreCheckpoint(ctx, badManifestReq, badCanonical, badCanonicalSize); err == nil {
		t.Fatal("manifest with noncanonical JCS bytes was accepted")
	}
	// Read back retained valid/quarantined checkpoint and budget rows independently.
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.work_order_checkpoints WHERE checkpoint_id=ANY($1::text[])`, ids).Scan(&checkpointCount); err != nil || checkpointCount != 2 {
		t.Fatal("retained checkpoint rows do not match successful L2/quarantine writes")
	}
	var storedBytes, spentAfter, reservedAfter int64
	if err := setup.QueryRow(ctx, `SELECT
		(SELECT COALESCE(sum(stored_bytes),0) FROM raw.work_order_checkpoints WHERE checkpoint_id=ANY($1::text[])),
		(SELECT spent FROM raw.budget_accounts WHERE account_id=$2),
		(SELECT reserved FROM raw.budget_accounts WHERE account_id=$2)`, ids[:2], account).Scan(&storedBytes, &spentAfter, &reservedAfter); err != nil || storedBytes != spentAfter || reservedAfter != 0 {
		t.Fatal("retained L2/quarantined checkpoint bytes were not charged exactly once with no remaining reservation")
	}
	var validReserve, validSettle, quarantineReserve, quarantineSettle int
	if err := setup.QueryRow(ctx, `SELECT
		count(*) FILTER(WHERE operation_id=$1), count(*) FILTER(WHERE operation_id=$2),
		count(*) FILTER(WHERE operation_id=$3), count(*) FILTER(WHERE operation_id=$4)
		FROM raw.budget_operations WHERE operation_id=ANY($5::text[])`,
		ids[0]+":reserve", ids[0]+":settle", ids[1]+":reserve", ids[1]+":settle",
		[]string{ids[0] + ":reserve", ids[0] + ":settle", ids[1] + ":reserve", ids[1] + ":settle"}).Scan(&validReserve, &validSettle, &quarantineReserve, &quarantineSettle); err != nil || validReserve != 1 || validSettle != 1 || quarantineReserve != 1 || quarantineSettle != 1 {
		t.Fatal("successful checkpoints must each have exactly one reserve and settlement operation")
	}
	var rejectedOperationCount int
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.budget_operations WHERE operation_id=ANY($1::text[])`, operations[4:]).Scan(&rejectedOperationCount); err != nil || rejectedOperationCount != 0 {
		t.Fatal("interrupted, over-cap, or tampered checkpoint left budget operations")
	}
	t.Logf("retained checkpoint IDs after readback: %v", ids[:2])
}
