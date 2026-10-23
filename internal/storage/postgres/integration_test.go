//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// These tests are deliberately opt-in: go test ./... never connects to a database.
func TestPostgresGovernanceIntegration(t *testing.T) {
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
	// Never enable pgx's connection logging: DSNs and connection errors may contain secrets.
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("unable to connect to integration database")
	}
	// Register pool closure before fixture cleanup is registered below. Testing
	// cleanup callbacks run before function defers, so this keeps the pool alive
	// while cleanup removes the fixtures.
	t.Cleanup(pool.Close)
	var db string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal("unable to verify integration database")
	}
	if db != "paddock_test" {
		t.Fatalf("refusing integration tests against unexpected database %q", db)
	}
	if err := requireSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Run("database clock contract", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin clock transaction: %v", err)
		}
		t.Cleanup(func() {
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer rollbackCancel()
			_ = tx.Rollback(rollbackCtx)
		})
		gov := newGovernanceTx(tx)
		var transactionNow, firstClock time.Time
		if err := tx.QueryRow(ctx, `SELECT now(), clock_timestamp()`).Scan(&transactionNow, &firstClock); err != nil {
			t.Fatalf("read initial transaction/database clocks: %v", err)
		}
		firstDatabaseTime, err := gov.DatabaseTime(ctx)
		if err != nil {
			t.Fatalf("GovernanceTx.DatabaseTime: %v", err)
		}
		if firstDatabaseTime.Before(firstClock) {
			t.Fatalf("DatabaseTime %v precedes clock_timestamp() %v", firstDatabaseTime, firstClock)
		}
		time.Sleep(25 * time.Millisecond)
		var laterNow, laterClock time.Time
		if err := tx.QueryRow(ctx, `SELECT now(), clock_timestamp()`).Scan(&laterNow, &laterClock); err != nil {
			t.Fatalf("read subsequent transaction/database clocks: %v", err)
		}
		if !laterNow.Equal(transactionNow) {
			t.Fatalf("now() changed within transaction: %v -> %v", transactionNow, laterNow)
		}
		if !laterClock.After(firstClock) {
			t.Fatalf("clock_timestamp() did not advance: %v -> %v", firstClock, laterClock)
		}
		// A deliberately stale worker timestamp cannot determine expiry: the
		// comparison's authority is the database clock returned by the port.
		workerTimestamp := transactionNow.Add(24 * time.Hour)
		deadline := transactionNow.Add(12 * time.Hour)
		if !firstDatabaseTime.Before(deadline) || workerTimestamp.Before(deadline) {
			t.Fatal("clock fixture does not distinguish database-time and worker-time deadline decisions")
		}
	})

	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("unable to create unique fixture IDs")
	}
	prefix := "it_" + hex.EncodeToString(suffix)
	bundle := sha256.Sum256(suffix)
	f := fixture{bundle: hex.EncodeToString(bundle[:]), scope: prefix + "_scope", root: prefix + "_root", otherRoot: prefix + "_other", otherScope: prefix + "_scope2", otherScopeRoot: prefix + "_root2", rollout: prefix + "_rollout"}
	var collisions int
	if err := pool.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM raw.policy_bundles WHERE bundle_digest=$1) +
  (SELECT count(*) FROM raw.policy_scopes WHERE scope_id=ANY($2::text[])) +
  (SELECT count(*) FROM raw.roots WHERE root_id=ANY($3::text[])) +
  (SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id=$4) +
  (SELECT count(*) FROM raw.rollout_targets WHERE rollout_id=$4)`, f.bundle,
		[]string{f.scope, f.otherScope}, []string{f.root, f.otherRoot, f.otherScopeRoot}, f.rollout).Scan(&collisions); err != nil {
		t.Fatal("unable to verify integration fixture IDs")
	}
	if collisions != 0 {
		t.Fatalf("refusing integration test: generated fixture identifiers collide with %d existing rows", collisions)
	}
	cleanupFixtures(t, ctx, pool, f)
	if err := seedFixtures(ctx, pool, f); err != nil {
		t.Fatalf("fixture setup failed: %v", err)
	}
	t.Run("AppendEvent envelope, uniqueness, and callback rollback", func(t *testing.T) {
		caseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		appURL := os.Getenv("PADDOCK_APP_DB_URL")
		if appURL == "" {
			t.Fatal("PADDOCK_APP_DB_URL must be set to run the app-role event integration test")
		}
		appPool, err := openPullPool(caseCtx, appURL, true)
		if err != nil {
			t.Fatal("unable to connect as paddock_app")
		}
		t.Cleanup(appPool.Close)
		var appDB, sessionUser, currentUser string
		if err := appPool.QueryRow(caseCtx, `SELECT current_database(), session_user, current_user`).Scan(&appDB, &sessionUser, &currentUser); err != nil {
			t.Fatalf("verify app connection identity: %v", err)
		}
		if appDB != "paddock_test" || sessionUser != "paddock_app" || currentUser != "paddock_app" {
			t.Fatalf("unexpected app connection identity: database=%q session_user=%q current_user=%q", appDB, sessionUser, currentUser)
		}
		var hasAppendExecute, directDomainInsert, directOutboxInsert, anyOutboxPrivilege bool
		if err := pool.QueryRow(caseCtx, `SELECT
			has_function_privilege('paddock_app', 'raw.append_domain_event_and_outbox(text,text,text,bigint,text,text,bytea)', 'EXECUTE'),
			has_table_privilege('paddock_app', 'raw.domain_events', 'INSERT'),
			has_table_privilege('paddock_app', 'raw.event_outbox', 'INSERT'),
			EXISTS (SELECT 1 FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) AS p(privilege) WHERE has_table_privilege('paddock_app', 'raw.event_outbox', p.privilege))`).Scan(&hasAppendExecute, &directDomainInsert, &directOutboxInsert, &anyOutboxPrivilege); err != nil {
			t.Fatalf("inspect event app-role privileges: %v", err)
		}
		if !hasAppendExecute || directDomainInsert || directOutboxInsert || anyOutboxPrivilege {
			t.Fatalf("event app-role privilege contract mismatch: append_execute=%t domain_insert=%t outbox_insert=%t any_outbox_privilege=%t", hasAppendExecute, directDomainInsert, directOutboxInsert, anyOutboxPrivilege)
		}
		aggregateID := prefix + "_aggregate"
		eventID := prefix + "_event"
		duplicateID, rollbackID := prefix+"_duplicate", prefix+"_rollback"
		var eventCollisions int
		if err := pool.QueryRow(caseCtx, `SELECT
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])) +
			(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])) +
			(SELECT count(*) FROM raw.domain_events WHERE aggregate_kind=$2 AND aggregate_id=$3 AND aggregate_version IN (1,2))`,
			[]string{eventID, duplicateID, rollbackID}, "rollout", aggregateID).Scan(&eventCollisions); err != nil {
			t.Fatalf("preflight generated event fixture IDs: %v", err)
		}
		if eventCollisions != 0 {
			t.Fatalf("refusing event fixture: generated event IDs or aggregate/version pairs collide with %d existing rows", eventCollisions)
		}
		t.Cleanup(func() {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanCancel()
			if _, err := pool.Exec(cleanCtx, `DELETE FROM raw.event_outbox WHERE event_id = ANY($1::text[])`, []string{eventID, duplicateID, rollbackID}); err != nil {
				t.Errorf("event outbox cleanup failed: %v", err)
			}
			if _, err := pool.Exec(cleanCtx, `DELETE FROM raw.domain_events WHERE event_id = ANY($1::text[])`, []string{eventID, duplicateID, rollbackID}); err != nil {
				t.Errorf("domain event cleanup failed: %v", err)
			}
		})
		payload := []byte(`{"state":"CANARY"}`)
		event, err := domain.NewEvent(eventID, "rollout", aggregateID, 1, "RolloutStarted", "event/1", payload)
		if err != nil {
			t.Fatal(err)
		}
		transactor := newTransactor(poolBeginner{pool: appPool})
		if err := transactor.WithinTransaction(caseCtx, func(gov port.GovernanceTx) error {
			return gov.AppendEvent(caseCtx, event)
		}); err != nil {
			t.Fatalf("append event: %v", err)
		}
		var gotKind, gotAggregate, gotType, gotSchema string
		var gotVersion int64
		var gotPayload []byte
		if err := pool.QueryRow(caseCtx, `SELECT aggregate_kind, aggregate_id, aggregate_version, event_type, schema_version, payload FROM raw.domain_events WHERE event_id=$1`, eventID).Scan(&gotKind, &gotAggregate, &gotVersion, &gotType, &gotSchema, &gotPayload); err != nil {
			t.Fatalf("read persisted event envelope: %v", err)
		}
		if gotKind != event.AggregateKind() || gotAggregate != aggregateID || gotVersion != 1 || gotType != event.Type() || gotSchema != event.SchemaVersion() || string(gotPayload) != string(payload) {
			t.Fatalf("stored event envelope mismatch: kind=%q aggregate=%q version=%d type=%q schema=%q payload=%q", gotKind, gotAggregate, gotVersion, gotType, gotSchema, gotPayload)
		}
		var outboxCount int
		if err := pool.QueryRow(caseCtx, `SELECT count(*) FROM raw.event_outbox WHERE event_id=$1`, eventID).Scan(&outboxCount); err != nil || outboxCount != 1 {
			t.Fatalf("outbox count=%d err=%v, want one matching row", outboxCount, err)
		}

		duplicate, err := domain.NewEvent(duplicateID, "rollout", aggregateID, 1, "RolloutRetried", "event/1", []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		err = transactor.WithinTransaction(caseCtx, func(gov port.GovernanceTx) error {
			return gov.AppendEvent(caseCtx, duplicate)
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("duplicate aggregate version error=%v, want PostgreSQL unique_violation (23505)", err)
		}
		var duplicateCount int
		if err := pool.QueryRow(caseCtx, `SELECT count(*) FROM raw.domain_events WHERE aggregate_kind=$1 AND aggregate_id=$2 AND aggregate_version=1`, "rollout", aggregateID).Scan(&duplicateCount); err != nil || duplicateCount != 1 {
			t.Fatalf("duplicate version count=%d err=%v, want original only", duplicateCount, err)
		}
		for _, table := range []string{"raw.domain_events", "raw.event_outbox"} {
			var count int
			query := `SELECT count(*) FROM ` + table + ` WHERE event_id=$1`
			if err := pool.QueryRow(caseCtx, query, duplicate.ID()).Scan(&count); err != nil || count != 0 {
				t.Fatalf("duplicate event in %s count=%d err=%v, want absent", table, count, err)
			}
		}

		rolledBack, err := domain.NewEvent(rollbackID, "rollout", aggregateID, 2, "RolloutAborted", "event/1", []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		callbackErr := errors.New("integration callback failure")
		err = transactor.WithinTransaction(caseCtx, func(gov port.GovernanceTx) error {
			if err := gov.AppendEvent(caseCtx, rolledBack); err != nil {
				return err
			}
			return callbackErr
		})
		if !errors.Is(err, callbackErr) {
			t.Fatalf("callback transaction error=%v, want callback failure", err)
		}
		var rollbackCount int
		if err := pool.QueryRow(caseCtx, `SELECT (SELECT count(*) FROM raw.domain_events WHERE event_id=$1) + (SELECT count(*) FROM raw.event_outbox WHERE event_id=$1)`, rolledBack.ID()).Scan(&rollbackCount); err != nil || rollbackCount != 0 {
			t.Fatalf("callback-error event/outbox rows=%d err=%v, want both rolled back", rollbackCount, err)
		}
	})

	t.Run("SafetyService receipts in rollback-only transaction", func(t *testing.T) {
		caseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		appURL := os.Getenv("PADDOCK_APP_DB_URL")
		if appURL == "" {
			t.Fatal("PADDOCK_APP_DB_URL must be set to run the SafetyService app-role integration test")
		}
		appPool, err := openPullPool(caseCtx, appURL, true)
		if err != nil {
			t.Fatal("unable to connect as paddock_app")
		}
		t.Cleanup(appPool.Close)
		var appDB, sessionUser, currentUser string
		if err := appPool.QueryRow(caseCtx, `SELECT current_database(), session_user, current_user`).Scan(&appDB, &sessionUser, &currentUser); err != nil {
			t.Fatalf("verify SafetyService app connection identity: %v", err)
		}
		if appDB != "paddock_test" || sessionUser != "paddock_app" || currentUser != "paddock_app" {
			t.Fatalf("unexpected SafetyService app connection identity: database=%q session_user=%q current_user=%q", appDB, sessionUser, currentUser)
		}
		var baselineMode string
		var baselineActivation, baselineSecurity int64
		if err := pool.QueryRow(caseCtx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&baselineMode, &baselineActivation); err != nil {
			t.Fatalf("read pre-test scope baseline: %v", err)
		}
		if err := pool.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&baselineSecurity); err != nil {
			t.Fatalf("read pre-test security baseline: %v", err)
		}
		// Migrator pre-seeds only this WorkOrder. Attempt/Slot/Lease are created
		// below by the existing app APIs, and disappear with the outer rollback.
		workID := f.root + "_safety_work"
		if _, err := pool.Exec(caseCtx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$2,NULL)`, workID, f.root); err != nil {
			t.Fatal("preseed safety WorkOrder failed")
		}
		t.Cleanup(func() {
			cleanCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			var leases, slots, attempts, requirements int
			if err := pool.QueryRow(cleanCtx, `SELECT
                (SELECT count(*) FROM raw.work_order_leases WHERE work_order_id=$1),
                (SELECT count(*) FROM raw.work_order_pull_slots WHERE work_order_id=$1),
                (SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=$1),
                (SELECT count(*) FROM raw.work_order_capability_requirements WHERE work_order_id=$1)`, workID).Scan(&leases, &slots, &attempts, &requirements); err != nil || leases != 0 || slots != 0 || attempts != 0 || requirements != 0 {
				t.Errorf("rollback left safety lease fixture rows: leases=%d slots=%d attempts=%d requirements=%d err=%v", leases, slots, attempts, requirements, err)
				return
			}
			tag, err := pool.Exec(cleanCtx, `DELETE FROM raw.work_orders WHERE work_order_id=$1 AND root_id=$2`, workID, f.root)
			if err != nil || tag.RowsAffected() != 1 {
				t.Errorf("exact safety WorkOrder cleanup failed: %v", err)
			}
		})
		tx, err := appPool.Begin(caseCtx)
		if err != nil {
			t.Fatalf("begin safety transaction: %v", err)
		}
		open := true
		defer func() {
			if open {
				rollbackCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = tx.Rollback(rollbackCtx)
			}
		}()
		for _, query := range []string{
			`SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`,
			`SELECT raw.mark_work_order_pull_ready($1)`,
		} {
			var ok bool
			if err := tx.QueryRow(caseCtx, query, workID).Scan(&ok); err != nil || !ok {
				t.Fatal("app safety WorkOrder configuration/ready failed")
			}
		}
		binding := domain.AttemptLeaseBinding{WorkOrderID: domain.WorkOrderID(workID), AttemptID: domain.AttemptID(workID + "_attempt"), WorkerID: domain.WorkerID(workID + "_worker"), SessionID: domain.SessionID(workID + "_session")}
		var issuedAttempt, issuedSlot string
		var leaseExpiry time.Time
		if err := tx.QueryRow(caseCtx, `SELECT attempt_id,slot_id,lease_epoch,expires_at FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,interval '10 minutes')`, workID, string(binding.WorkerID), string(binding.SessionID), string(binding.AttemptID), workID+"_slot").Scan(&issuedAttempt, &issuedSlot, &binding.LeaseEpoch, &leaseExpiry); err != nil || issuedAttempt != string(binding.AttemptID) || issuedSlot != workID+"_slot" || binding.LeaseEpoch != 1 {
			t.Fatal("app safety lease issuance failed")
		}
		authorization := func(grant domain.Grant) domain.HighRiskAuthorization {
			return domain.HighRiskAuthorization{Grant: grant, Lease: binding}
		}
		gov := newSafetyGovernanceTx(tx)
		snapshot, err := gov.LockScope(caseCtx, domain.ScopeID(f.scope))
		if err != nil {
			t.Fatalf("read safety snapshot: %v", err)
		}
		keys := make([]ed25519.PrivateKey, 3)
		signers := make([]domain.SafetySigner, 3)
		for i := range keys {
			pub, priv, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			keys[i] = priv
			signers[i] = domain.SafetySigner{ID: fmt.Sprintf("test-key-%d", i), PublicKey: pub}
		}
		quorum, err := domain.NewSafetyQuorum(signers)
		if err != nil {
			t.Fatal(err)
		}
		service := application.NewSafetyService(outerTxTransactor{tx: tx, safetyAPI: true}, quorum)
		gate := application.NewSafetyGate(outerTxTransactor{tx: tx, safetyAPI: true})
		makeSigs := func(action domain.SafetyAction, epoch domain.Epoch, id string, activation *[32]byte) []domain.SafetySignature {
			var msg []byte
			var e error
			if activation == nil {
				msg, e = domain.SafetyApprovalMessage(action, snapshot.ScopeID, epoch, id, "safety-fixture-nonce")
			} else {
				msg, e = domain.SafetyApprovalMessage(action, snapshot.ScopeID, epoch, id, "safety-fixture-nonce", *activation)
			}
			if e != nil {
				t.Fatal(e)
			}
			return []domain.SafetySignature{{SignerID: signers[0].ID, Signature: ed25519.Sign(keys[0], msg)}, {SignerID: signers[1].ID, Signature: ed25519.Sign(keys[1], msg)}}
		}
		checkSafetyEvent := func(commandID, eventType string, version int64, wantPayload string) {
			t.Helper()
			var gotKind, gotAggregate, gotType, gotSchema string
			var gotVersion int64
			var gotPayload []byte
			eventID := "safety/" + commandID
			if err := tx.QueryRow(caseCtx, `SELECT aggregate_kind,aggregate_id,aggregate_version,event_type,schema_version,payload FROM raw.domain_events WHERE event_id=$1`, eventID).Scan(&gotKind, &gotAggregate, &gotVersion, &gotType, &gotSchema, &gotPayload); err != nil {
				t.Fatalf("read safety event %q: %v", eventID, err)
			}
			if gotKind != "scope" || gotAggregate != string(snapshot.ScopeID) || gotVersion != version || gotType != eventType || gotSchema != "paddock.safety-event/1" || string(gotPayload) != wantPayload {
				t.Fatalf("safety event mismatch: kind=%q aggregate=%q version=%d type=%q schema=%q payload=%s", gotKind, gotAggregate, gotVersion, gotType, gotSchema, gotPayload)
			}
		}
		stopID := f.scope + "_stop"
		stopSigs := makeSigs(domain.SafetyActionStop, snapshot.SecurityEpoch, stopID, nil)
		stopped, err := service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, "safety-fixture-nonce", stopSigs)
		if err != nil || stopped.State.Mode != domain.ScopeSafeStop || stopped.State.SecurityEpoch != snapshot.SecurityEpoch+1 {
			t.Fatalf("Stop result=%+v err=%v", stopped, err)
		}
		preStopRoot := snapshot.Roots[domain.RootID(f.root)]
		preStopGrant := domain.Grant{Root: domain.RootID(f.root), Policy: preStopRoot.Policy, AuthorizationEpoch: preStopRoot.AuthorizationEpoch, SecurityEpoch: snapshot.SecurityEpoch}
		if err := gate.CheckNewDispatch(caseCtx, snapshot.ScopeID, domain.RootID(f.root)); !errors.Is(err, domain.ErrSafeStopped) {
			t.Fatalf("CheckNewDispatch after Stop = %v, want ErrSafeStopped", err)
		}
		if err := gate.CheckNewGrant(caseCtx, snapshot.ScopeID, domain.RootID(f.root)); !errors.Is(err, domain.ErrSafeStopped) {
			t.Fatalf("CheckNewGrant after Stop = %v, want ErrSafeStopped", err)
		}
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, authorization(preStopGrant)); !errors.Is(err, domain.ErrSafeStopped) {
			t.Fatalf("CheckHighRiskAction after Stop = %v, want ErrSafeStopped", err)
		}
		stoppedSnapshot, err := newSafetyGovernanceTx(tx).LockScope(caseCtx, snapshot.ScopeID)
		if err != nil {
			t.Fatalf("read stopped Scope through app API: %v", err)
		}
		if stoppedSnapshot.Mode != domain.ScopeSafeStop || stoppedSnapshot.ActivationEpoch != snapshot.ActivationEpoch || stoppedSnapshot.SecurityEpoch != snapshot.SecurityEpoch+1 {
			t.Fatalf("stopped DB state mode=%s activation=%d security=%d", stoppedSnapshot.Mode, stoppedSnapshot.ActivationEpoch, stoppedSnapshot.SecurityEpoch)
		}
		checkSafetyEvent(stopID, "SafetyStopped", int64(stopped.State.SecurityEpoch), fmt.Sprintf(`{"previous_scope_activation_epoch":%d,"scope_activation_epoch":%d,"previous_security_epoch":%d,"security_epoch":%d}`, snapshot.ActivationEpoch, stopped.State.ScopeActivationEpoch, snapshot.SecurityEpoch, stopped.State.SecurityEpoch))
		stopReceipt, stopReceiptFound, err := newSafetyGovernanceTx(tx).LookupCommandReceipt(caseCtx, stopID)
		if err != nil || !stopReceiptFound {
			t.Fatalf("lookup Stop receipt: found=%t err=%v", stopReceiptFound, err)
		}
		if stopReceipt.Status != "SUCCEEDED" || len(stopReceipt.Response) == 0 {
			t.Fatalf("invalid stop receipt: %+v", stopReceipt)
		}
		if _, err = service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, "safety-fixture-nonce", stopSigs); err != nil {
			t.Fatalf("Stop replay: %v", err)
		}
		changed := append([]domain.SafetySignature(nil), stopSigs...)
		changed[0].Signature = append([]byte(nil), changed[0].Signature...)
		changed[0].Signature[0] ^= 1
		if _, err = service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, "safety-fixture-nonce", changed); err == nil {
			t.Fatal("changed Stop request unexpectedly accepted")
		}
		activation := domain.AuthorityState{Scope: snapshot.ScopeID, ScopeActivationEpoch: snapshot.ActivationEpoch + 1, SecurityEpoch: stopped.State.SecurityEpoch + 1, Mode: domain.ScopeActive, DatabaseAvailable: true, Roots: stopped.State.Roots}
		digest, err := domain.ActivationDigest(activation)
		if err != nil {
			t.Fatal(err)
		}
		releaseID := f.scope + "_release"
		releaseSigs := makeSigs(domain.SafetyActionRelease, stopped.State.SecurityEpoch, releaseID, &digest)
		released, err := service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, "safety-fixture-nonce", activation, releaseSigs)
		if err != nil || released.State.Mode != domain.ScopeActive || released.State.ScopeActivationEpoch != activation.ScopeActivationEpoch {
			t.Fatalf("Release result=%+v err=%v", released, err)
		}
		if err := gate.CheckNewDispatch(caseCtx, snapshot.ScopeID, domain.RootID(f.root)); err != nil {
			t.Fatalf("CheckNewDispatch after Release: %v", err)
		}
		if err := gate.CheckNewGrant(caseCtx, snapshot.ScopeID, domain.RootID(f.root)); err != nil {
			t.Fatalf("CheckNewGrant after Release: %v", err)
		}
		releasedRoot := released.State.Roots[domain.RootID(f.root)]
		releasedGrant := domain.Grant{Root: domain.RootID(f.root), Policy: releasedRoot.Policy, AuthorizationEpoch: releasedRoot.AuthorizationEpoch, SecurityEpoch: released.State.SecurityEpoch}
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, authorization(releasedGrant)); err != nil {
			t.Fatalf("CheckHighRiskAction after Release with current grant: %v", err)
		}
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, authorization(preStopGrant)); !errors.Is(err, domain.ErrStaleGrant) {
			t.Fatalf("CheckHighRiskAction after Release with stale grant = %v, want ErrStaleGrant", err)
		}
		if _, err = service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, "safety-fixture-nonce", activation, releaseSigs); err != nil {
			t.Fatalf("Release replay: %v", err)
		}
		altered := activation
		altered.ScopeActivationEpoch++
		if _, err = service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, "safety-fixture-nonce", altered, releaseSigs); err == nil {
			t.Fatal("changed Release activation unexpectedly accepted")
		}
		releaseReceipt, releaseReceiptFound, err := newSafetyGovernanceTx(tx).LookupCommandReceipt(caseCtx, releaseID)
		if err != nil || !releaseReceiptFound || releaseReceipt.Status != "SUCCEEDED" || len(releaseReceipt.Response) == 0 {
			t.Fatalf("invalid release receipt found=%t receipt=%+v err=%v", releaseReceiptFound, releaseReceipt, err)
		}
		releasedSnapshot, err := newSafetyGovernanceTx(tx).LockScope(caseCtx, snapshot.ScopeID)
		if err != nil {
			t.Fatalf("read released Scope through app API: %v", err)
		}
		if releasedSnapshot.Mode != domain.ScopeActive || releasedSnapshot.ActivationEpoch != activation.ScopeActivationEpoch || releasedSnapshot.SecurityEpoch != released.State.SecurityEpoch || releasedSnapshot.SecurityEpoch != stopped.State.SecurityEpoch+1 {
			t.Fatalf("released DB state mode=%s activation=%d security=%d; want mode=ACTIVE activation=%d security=%d", releasedSnapshot.Mode, releasedSnapshot.ActivationEpoch, releasedSnapshot.SecurityEpoch, activation.ScopeActivationEpoch, released.State.SecurityEpoch)
		}
		checkSafetyEvent(releaseID, "SafetyReleased", int64(released.State.SecurityEpoch), fmt.Sprintf(`{"previous_scope_activation_epoch":%d,"scope_activation_epoch":%d,"previous_security_epoch":%d,"security_epoch":%d}`, stopped.State.ScopeActivationEpoch, released.State.ScopeActivationEpoch, stopped.State.SecurityEpoch, released.State.SecurityEpoch))

		// Force the final Event append to violate the unique aggregate version after
		// Scope, Security Epoch, and Receipt writes. A savepoint lets the test inspect
		// that the failed command left none of its own rows while preserving this
		// deliberate colliding Event fixture until the outer transaction is rolled back.
		faultCommandID := f.scope + "_event_failure"
		faultEventID := "safety/" + faultCommandID
		fixtureEventID := "failure-fixture/" + faultCommandID
		faultVersion := released.State.SecurityEpoch + 1
		var faultCollisions int
		if err := pool.QueryRow(caseCtx, `SELECT
			(SELECT count(*) FROM raw.command_receipts WHERE command_id=$1) +
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($2::text[])) +
			(SELECT count(*) FROM raw.domain_events WHERE aggregate_kind='scope' AND aggregate_id=$3 AND aggregate_version=$4)`,
			faultCommandID, []string{faultEventID, fixtureEventID}, snapshot.ScopeID, int64(faultVersion)).Scan(&faultCollisions); err != nil || faultCollisions != 0 {
			t.Fatalf("refusing safety event failure fixture: collisions=%d err=%v", faultCollisions, err)
		}
		failureFixture, err := domain.NewEvent(fixtureEventID, "scope", string(snapshot.ScopeID), int64(faultVersion), "SafetyFailureFixture", "paddock.safety-event/1", []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := gov.AppendEvent(caseCtx, failureFixture); err != nil {
			t.Fatalf("seed event unique-version failure fixture: %v", err)
		}
		if _, err := tx.Exec(caseCtx, `SAVEPOINT safety_event_failure`); err != nil {
			t.Fatalf("create event failure savepoint: %v", err)
		}
		faultSignatures := makeSigs(domain.SafetyActionStop, released.State.SecurityEpoch, faultCommandID, nil)
		_, faultErr := service.Stop(caseCtx, snapshot.ScopeID, released.State.SecurityEpoch, faultCommandID, "safety-fixture-nonce", faultSignatures)
		var faultPGErr *pgconn.PgError
		if !errors.As(faultErr, &faultPGErr) || faultPGErr.Code != "23505" {
			t.Fatalf("fault-injected Stop error=%v, want event unique_violation (23505)", faultErr)
		}
		if _, err := tx.Exec(caseCtx, `ROLLBACK TO SAVEPOINT safety_event_failure`); err != nil {
			t.Fatalf("rollback failed safety transition to savepoint: %v", err)
		}
		if _, err := tx.Exec(caseCtx, `RELEASE SAVEPOINT safety_event_failure`); err != nil {
			t.Fatalf("release safety event failure savepoint: %v", err)
		}
		failedScopeSnapshot, err := newSafetyGovernanceTx(tx).LockScope(caseCtx, snapshot.ScopeID)
		if err != nil {
			t.Fatalf("read Scope after injected Event failure through app API: %v", err)
		}
		if failedScopeSnapshot.Mode != domain.ScopeActive || failedScopeSnapshot.ActivationEpoch != released.State.ScopeActivationEpoch || failedScopeSnapshot.SecurityEpoch != released.State.SecurityEpoch {
			t.Fatalf("failed safety transition persisted state: mode=%s activation=%d security=%d", failedScopeSnapshot.Mode, failedScopeSnapshot.ActivationEpoch, failedScopeSnapshot.SecurityEpoch)
		}
		_, faultReceiptFound, err := newSafetyGovernanceTx(tx).LookupCommandReceipt(caseCtx, faultCommandID)
		if err != nil || faultReceiptFound {
			t.Fatalf("failed command Receipt found=%t err=%v, want absent", faultReceiptFound, err)
		}
		var failedEventRows int
		if err := tx.QueryRow(caseCtx, `SELECT count(*) FROM raw.domain_events WHERE event_id=$1`, faultEventID).Scan(&failedEventRows); err != nil || failedEventRows != 0 {
			t.Fatalf("failed command Event rows=%d err=%v, want zero", failedEventRows, err)
		}
		var collisionEventRows int
		if err := tx.QueryRow(caseCtx, `SELECT count(*) FROM raw.domain_events WHERE event_id=$1`, fixtureEventID).Scan(&collisionEventRows); err != nil || collisionEventRows != 1 {
			t.Fatalf("failure fixture Event rows=%d err=%v, want one", collisionEventRows, err)
		}
		if err := tx.Rollback(caseCtx); err != nil {
			t.Fatalf("rollback safety transaction: %v", err)
		}
		open = false
		var finalMode string
		var finalActivation, finalSecurity int64
		if err := pool.QueryRow(caseCtx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&finalMode, &finalActivation); err != nil {
			t.Fatalf("read scope after rollback: %v", err)
		}
		if err := pool.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&finalSecurity); err != nil {
			t.Fatalf("read security epoch after rollback: %v", err)
		}
		if finalMode != baselineMode || finalActivation != baselineActivation || finalSecurity != baselineSecurity {
			t.Fatalf("rollback did not restore baseline: mode=%s activation=%d security=%d; want mode=%s activation=%d security=%d", finalMode, finalActivation, finalSecurity, baselineMode, baselineActivation, baselineSecurity)
		}
		var receiptCount, eventCount, outboxCount int
		eventIDs := []string{"safety/" + stopID, "safety/" + releaseID, faultEventID, fixtureEventID}
		if err := pool.QueryRow(caseCtx, `SELECT
			(SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[])),
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($2::text[])),
			(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($2::text[]))`,
			[]string{stopID, releaseID, faultCommandID}, eventIDs).Scan(&receiptCount, &eventCount, &outboxCount); err != nil {
			t.Fatalf("read final rollback row counts: %v", err)
		}
		t.Logf("post-rollback safety fixture counts: receipts=%d events=%d outbox=%d", receiptCount, eventCount, outboxCount)
		if receiptCount != 0 || eventCount != 0 || outboxCount != 0 {
			t.Fatalf("safety fixture rows remain after rollback: receipts=%d events=%d outbox=%d", receiptCount, eventCount, outboxCount)
		}
	})

	// Each stale case changes the exact row in the same transaction after the
	// adapter has locked/snapshotted canonical Scope -> Rollout -> Root order.
	// These exercise zero-row CAS rejection, not an external-writer race.
	for _, staleCase := range []string{"scope", "root", "rollout", "rollout state", "target", "security epoch"} {
		t.Run("stale "+staleCase, func(t *testing.T) {
			caseCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			tx, err := pool.Begin(caseCtx)
			if err != nil {
				t.Fatalf("begin stale %s transaction: %v", staleCase, err)
			}
			t.Cleanup(func() {
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer rollbackCancel()
				_ = tx.Rollback(rollbackCtx)
			})
			gov := newGovernanceTx(tx)
			scope, err := gov.LockScope(caseCtx, domain.ScopeID(f.scope))
			if err != nil {
				t.Fatalf("stale %s LockScope: %v", staleCase, err)
			}
			rollout, err := gov.LockRollout(caseCtx, domain.ScopeID(f.scope), domain.RolloutID(f.rollout))
			if err != nil {
				t.Fatalf("stale %s LockRollout: %v", staleCase, err)
			}
			if err := gov.ValidateTargets(caseCtx, domain.ScopeID(f.scope), []domain.RootID{domain.RootID(f.root)}); err != nil {
				t.Fatalf("stale %s ValidateTargets: %v", staleCase, err)
			}
			var staleErr error
			checkMutation := func(rows int64, mutationErr error) error {
				if mutationErr != nil {
					return mutationErr
				}
				if rows != 1 {
					return fmt.Errorf("setup mutation affected %d rows, want exactly 1", rows)
				}
				return nil
			}
			switch staleCase {
			case "scope":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.policy_scopes SET activation_epoch=activation_epoch+1 WHERE scope_id=$1`, f.scope)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					next := scope
					next.ActivationEpoch++
					staleErr = gov.CompareAndSwapScope(caseCtx, scope, next)
				}
			case "root":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.roots SET authorization_epoch=authorization_epoch+1 WHERE root_id=$1`, f.root)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					next := scope
					next.Roots = cloneRoots(scope.Roots)
					r := next.Roots[domain.RootID(f.root)]
					r.AuthorizationEpoch++
					next.Roots[domain.RootID(f.root)] = r
					staleErr = gov.CompareAndSwapScope(caseCtx, scope, next)
				}
			case "rollout":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.policy_rollouts SET last_activation_epoch=last_activation_epoch+1 WHERE rollout_id=$1`, f.rollout)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					next := rollout
					next.LastActivationEpoch++
					staleErr = gov.CompareAndSwapRollout(caseCtx, rollout, next)
				}
			case "rollout state":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.policy_rollouts SET state='COMPLETED' WHERE rollout_id=$1`, f.rollout)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					next := rollout
					next.State = domain.RolloutCompleted
					staleErr = gov.CompareAndSwapRollout(caseCtx, rollout, next)
				}
			case "target":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.rollout_targets SET base_root_epoch=base_root_epoch+1 WHERE rollout_id=$1 AND root_id=$2`, f.rollout, f.root)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					next := rollout
					next.Targets = make(map[domain.RootID]port.RolloutTargetSnapshot, len(rollout.Targets))
					for id, target := range rollout.Targets {
						next.Targets[id] = target
					}
					target := next.Targets[domain.RootID(f.root)]
					target.BaseRootEpoch++
					next.Targets[domain.RootID(f.root)] = target
					staleErr = gov.CompareAndSwapRollout(caseCtx, rollout, next)
				}
			case "security epoch":
				tag, mutationErr := tx.Exec(caseCtx, `UPDATE raw.security_generation SET security_epoch=security_epoch+1 WHERE singleton_id=true`)
				err = checkMutation(tag.RowsAffected(), mutationErr)
				if err == nil {
					staleErr = gov.CompareAndSwapSecurityEpoch(caseCtx, scope.SecurityEpoch, scope.SecurityEpoch+1)
				}
			}
			if err != nil {
				t.Fatalf("mutate stale %s fixture row: %v", staleCase, err)
			}
			if !errors.Is(staleErr, port.ErrStaleWrite) {
				t.Fatalf("stale %s CAS error = %v, want ErrStaleWrite", staleCase, staleErr)
			}
			if err := tx.Rollback(caseCtx); err != nil {
				t.Fatalf("rollback stale %s transaction: %v", staleCase, err)
			}
		})
	}
	t.Run("concurrent global security epoch CAS across scopes", func(t *testing.T) {
		caseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		beginTxn := func(scopeID domain.ScopeID) (pgx.Tx, *governanceTx, domain.Epoch) {
			tx, err := pool.Begin(caseCtx)
			if err != nil {
				t.Fatalf("begin scope %q transaction: %v", scopeID, err)
			}
			// Register bounded rollback immediately so every subsequent setup failure
			// releases this transaction's Scope lock.
			t.Cleanup(func() {
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer rollbackCancel()
				_ = tx.Rollback(rollbackCtx)
			})
			gov := newGovernanceTx(tx)
			snapshot, err := gov.LockScope(caseCtx, scopeID)
			if err != nil {
				t.Fatalf("LockScope(%q): %v", scopeID, err)
			}
			return tx, gov, snapshot.SecurityEpoch
		}
		txA, govA, expected := beginTxn(domain.ScopeID(f.scope))
		txB, govB, expectedB := beginTxn(domain.ScopeID(f.otherScope))
		if expectedB != expected {
			t.Fatalf("scope snapshots have different security epochs: %d and %d", expected, expectedB)
		}
		var baseline int64
		if err := pool.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&baseline); err != nil {
			t.Fatalf("read initial global security epoch: %v", err)
		}
		if int64(expected) != baseline {
			t.Fatalf("scope snapshot epoch=%d differs from global baseline=%d", expected, baseline)
		}
		var pidA, pidB int
		if err := txA.QueryRow(caseCtx, `SELECT pg_backend_pid()`).Scan(&pidA); err != nil {
			t.Fatalf("read transaction A pid: %v", err)
		}
		if err := txB.QueryRow(caseCtx, `SELECT pg_backend_pid()`).Scan(&pidB); err != nil {
			t.Fatalf("read transaction B pid: %v", err)
		}
		if err := govA.CompareAndSwapSecurityEpoch(caseCtx, expected, expected+1); err != nil {
			t.Fatalf("transaction A CAS: %v", err)
		}

		attempted := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(attempted)
			result <- govB.CompareAndSwapSecurityEpoch(caseCtx, expected, expected+1)
		}()
		<-attempted
		// Observe PostgreSQL's actual blocking graph, not elapsed time alone.
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		blocked := false
		for !blocked {
			select {
			case err := <-result:
				t.Fatalf("transaction B CAS completed before A rollback: %v", err)
			case <-ticker.C:
				if err := pool.QueryRow(caseCtx, `SELECT $2 = ANY(pg_blocking_pids($1))`, pidB, pidA).Scan(&blocked); err != nil {
					t.Fatalf("inspect CAS lock blocking: %v", err)
				}
			case <-caseCtx.Done():
				t.Fatalf("transaction B did not block on A's epoch update: %v", caseCtx.Err())
			}
		}
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := txA.Rollback(rollbackCtx); err != nil {
			rollbackCancel()
			t.Fatalf("rollback transaction A: %v", err)
		}
		rollbackCancel()
		select {
		case err := <-result:
			if err != nil && !errors.Is(err, port.ErrStaleWrite) {
				t.Fatalf("transaction B CAS after A rollback: %v", err)
			}
		case <-caseCtx.Done():
			t.Fatalf("transaction B did not finish after A rollback: %v", caseCtx.Err())
		}
		rollbackCtx, rollbackCancel = context.WithTimeout(context.Background(), 5*time.Second)
		if err := txB.Rollback(rollbackCtx); err != nil {
			rollbackCancel()
			t.Fatalf("rollback transaction B: %v", err)
		}
		rollbackCancel()
		var final int64
		if err := pool.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&final); err != nil {
			t.Fatalf("read final global security epoch: %v", err)
		}
		if final != baseline {
			t.Fatalf("global security epoch changed: before=%d after=%d", baseline, final)
		}
	})
	assertScopeLockBlocksConcurrentTransaction(t, ctx, pool, f.scope)
	// Confirm all changed fixture values were restored by rollback.
	var activation, rootEpoch, securityEpoch, rolloutActivation, targetEpoch int64
	var rolloutState string
	if err := pool.QueryRow(ctx, `SELECT activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&activation); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT authorization_epoch FROM raw.roots WHERE root_id=$1`, f.root).Scan(&rootEpoch); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT state,last_activation_epoch FROM raw.policy_rollouts WHERE rollout_id=$1`, f.rollout).Scan(&rolloutState, &rolloutActivation); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT base_root_epoch FROM raw.rollout_targets WHERE rollout_id=$1 AND root_id=$2`, f.rollout, f.root).Scan(&targetEpoch); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&securityEpoch); err != nil {
		t.Fatal(err)
	}
	if activation != 0 || rootEpoch != 0 || rolloutState != "SHADOW" || rolloutActivation != 0 || targetEpoch != 0 {
		t.Fatalf("fixture values not restored: scope=%d root=%d rollout=%s/%d target=%d", activation, rootEpoch, rolloutState, rolloutActivation, targetEpoch)
	}
	var baselineSecurity int64
	if err := pool.QueryRow(ctx, `SELECT base_security_epoch FROM raw.policy_rollouts WHERE rollout_id=$1`, f.rollout).Scan(&baselineSecurity); err != nil {
		t.Fatal(err)
	}
	if securityEpoch != baselineSecurity {
		t.Fatalf("security epoch after rollback=%d, fixture snapshot=%d", securityEpoch, baselineSecurity)
	}
}

func assertScopeLockBlocksConcurrentTransaction(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scopeID string) {
	t.Helper()
	lockCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	rollback := func(tx pgx.Tx) error {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rollbackCancel()
		return tx.Rollback(rollbackCtx)
	}

	ownerTx, err := pool.Begin(lockCtx)
	if err != nil {
		t.Fatalf("begin Scope lock owner transaction: %v", err)
	}
	ownerOpen := true
	defer func() {
		if ownerOpen {
			_ = rollback(ownerTx)
		}
	}()
	var ownerPID int
	if err := ownerTx.QueryRow(lockCtx, `SELECT pg_backend_pid()`).Scan(&ownerPID); err != nil {
		t.Fatalf("read Scope lock owner pid: %v", err)
	}
	if _, err := newGovernanceTx(ownerTx).LockScope(lockCtx, domain.ScopeID(scopeID)); err != nil {
		t.Fatalf("adapter LockScope: %v", err)
	}

	type queryResult struct {
		pid   int
		epoch int64
		err   error
	}
	started := make(chan int, 1)
	completed := make(chan queryResult, 1)
	completionReceived := false
	go func() {
		tx, err := pool.Begin(lockCtx)
		if err != nil {
			completed <- queryResult{err: err}
			return
		}
		defer rollback(tx)
		var pid int
		if err := tx.QueryRow(lockCtx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			completed <- queryResult{err: err}
			return
		}
		started <- pid
		var epoch int64
		err = tx.QueryRow(lockCtx, `SELECT activation_epoch FROM raw.policy_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID).Scan(&epoch)
		completed <- queryResult{pid: pid, epoch: epoch, err: err}
	}()
	defer func() {
		cancel()
		if !completionReceived {
			select {
			case <-completed:
			case <-time.After(2 * time.Second):
				t.Error("concurrent transaction goroutine did not terminate after cancellation")
			}
		}
	}()

	var waiterPID int
	select {
	case waiterPID = <-started:
	case result := <-completed:
		completionReceived = true
		_ = rollback(ownerTx)
		ownerOpen = false
		t.Fatalf("concurrent transaction ended before reporting its pid: %v", result.err)
	case <-lockCtx.Done():
		_ = rollback(ownerTx)
		ownerOpen = false
		t.Fatalf("concurrent transaction did not start: %v", lockCtx.Err())
	}
	if waiterPID == ownerPID {
		_ = rollback(ownerTx)
		ownerOpen = false
		t.Fatalf("transactions unexpectedly share backend pid %d", ownerPID)
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		select {
		case <-ticker.C:
			var blockedByOwner bool
			if err := ownerTx.QueryRow(lockCtx, `SELECT $2 = ANY(pg_blocking_pids($1))`, waiterPID, ownerPID).Scan(&blockedByOwner); err != nil {
				t.Fatalf("inspect concurrent lock blockers: %v", err)
			}
			blocked = blockedByOwner
		case result := <-completed:
			t.Fatalf("second transaction completed before owner released Scope lock (pid=%d err=%v)", result.pid, result.err)
		case <-deadline.C:
			t.Fatal("pg_blocking_pids did not show the second backend blocked by Scope lock owner")
		case <-lockCtx.Done():
			t.Fatalf("timed out observing Scope lock blocking: %v", lockCtx.Err())
		}
	}
	ticker.Stop()
	if !deadline.Stop() {
		select {
		case <-deadline.C:
		default:
		}
	}
	if err := rollback(ownerTx); err != nil {
		t.Errorf("release Scope lock owner transaction: %v", err)
	}
	ownerOpen = false
	select {
	case result := <-completed:
		completionReceived = true
		if result.err != nil {
			t.Errorf("second transaction Scope FOR UPDATE failed after release: %v", result.err)
		} else if result.epoch != 0 {
			t.Errorf("second transaction read activation_epoch=%d, want 0", result.epoch)
		}
	case <-lockCtx.Done():
		t.Errorf("second transaction did not proceed after Scope lock release: %v", lockCtx.Err())
	}
}

type fixture struct{ bundle, scope, root, otherRoot, otherScope, otherScopeRoot, rollout string }

// outerTxTransactor adapts an already-open transaction without taking ownership
// of its commit. The integration test always performs the final rollback.
type outerTxTransactor struct {
	tx        pgx.Tx
	safetyAPI bool
}

func (o outerTxTransactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	if o.safetyAPI {
		return fn(newSafetyGovernanceTx(o.tx))
	}
	return fn(newGovernanceTx(o.tx))
}

// This adapter borrows the existing rollback-only transaction; it never commits
// or opens another connection for the typed SafetyGate capability.
func (o outerTxTransactor) WithinSafetyGateTransaction(ctx context.Context, fn func(port.SafetyGateTx) error) error {
	if !o.safetyAPI {
		return errors.New("SafetyGate requires app-only adapter")
	}
	return fn(newSafetyGateTx(o.tx))
}

func requireSchema(ctx context.Context, pool *pgxpool.Pool) error {
	var missing []string
	checks := []struct{ name, query string }{
		{"S01 base tables", `SELECT to_regclass('raw.policy_bundles') IS NOT NULL AND to_regclass('raw.policy_scopes') IS NOT NULL AND to_regclass('raw.roots') IS NOT NULL AND to_regclass('raw.policy_rollouts') IS NOT NULL AND to_regclass('raw.rollout_targets') IS NOT NULL AND to_regclass('raw.security_generation') IS NOT NULL`},
		{"S02 active rollout index", `SELECT to_regclass('raw.policy_rollouts_one_active_per_scope_uidx') IS NOT NULL`},
		{"S06 triggers", `SELECT count(*) = 2 FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ('policy_scopes_frozen_rollback_ct','policy_rollouts_frozen_rollback_ct')`},
		{"S06 trigger functions", `SELECT to_regprocedure('raw.enforce_frozen_scope_rollback()') IS NOT NULL AND to_regprocedure('raw.prevent_frozen_rollout_leaving_rollback()') IS NOT NULL`},
	}
	for _, c := range checks {
		var ok bool
		if err := pool.QueryRow(ctx, c.query).Scan(&ok); err != nil {
			return fmt.Errorf("schema preflight %s failed", c.name)
		}
		if !ok {
			missing = append(missing, c.name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("required migrations/schema missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func seedFixtures(ctx context.Context, pool *pgxpool.Pool, f fixture) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES ($1,$2,'integration','integration-test',$3)`, f.bundle, []byte("integration fixture"), []byte{1})
	if err != nil {
		return err
	}
	for _, scope := range []string{f.scope, f.otherScope} {
		if _, err := tx.Exec(ctx, `INSERT INTO raw.policy_scopes(scope_id,activation_epoch,baseline_bundle_digest,mode) VALUES ($1,0,$2,'ACTIVE')`, scope, f.bundle); err != nil {
			return err
		}
	}
	for _, root := range []struct{ id, scope string }{{f.root, f.scope}, {f.otherRoot, f.scope}, {f.otherScopeRoot, f.otherScope}} {
		if _, err := tx.Exec(ctx, `INSERT INTO raw.roots(root_id,scope_id,authorization_epoch,effective_bundle_digest,safe_baseline) VALUES ($1,$2,0,$3,false)`, root.id, root.scope, f.bundle); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO raw.policy_rollouts(rollout_id,scope_id,state,target_root_id,base_activation_epoch,last_activation_epoch,base_security_epoch) SELECT $1,$2,'SHADOW',$3,0,0,security_epoch FROM raw.security_generation WHERE singleton_id=true`, f.rollout, f.scope, f.root); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO raw.rollout_targets(rollout_id,scope_id,root_id,baseline_bundle_digest,candidate_bundle_digest,base_root_epoch) VALUES ($1,$2,$3,$4,$4,0)`, f.rollout, f.scope, f.root, f.bundle); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cleanupFixtures(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f fixture) {
	t.Helper()
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(cleanCtx)
		if err != nil {
			t.Errorf("fixture cleanup begin failed: %v", err)
			return
		}
		defer tx.Rollback(cleanCtx)
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM raw.rollout_targets WHERE rollout_id=$1`, []any{f.rollout}},
			{`DELETE FROM raw.policy_rollouts WHERE rollout_id=$1`, []any{f.rollout}},
			{`DELETE FROM raw.roots WHERE root_id = ANY($1::text[])`, []any{[]string{f.root, f.otherRoot, f.otherScopeRoot}}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id = ANY($1::text[])`, []any{[]string{f.scope, f.otherScope}}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest=$1`, []any{f.bundle}},
		} {
			if _, err := tx.Exec(cleanCtx, q.sql, q.args...); err != nil {
				t.Errorf("fixture cleanup failed: %v", err)
				return
			}
		}
		if err := tx.Commit(cleanCtx); err != nil {
			t.Errorf("fixture cleanup commit failed: %v", err)
			return
		}
		var count int
		if err := pool.QueryRow(cleanCtx, `SELECT (SELECT count(*) FROM raw.policy_bundles WHERE bundle_digest=$1) + (SELECT count(*) FROM raw.policy_scopes WHERE scope_id=ANY($2::text[])) + (SELECT count(*) FROM raw.roots WHERE root_id=ANY($3::text[])) + (SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id=$4) + (SELECT count(*) FROM raw.rollout_targets WHERE rollout_id=$4)`, f.bundle, []string{f.scope, f.otherScope}, []string{f.root, f.otherRoot, f.otherScopeRoot}, f.rollout).Scan(&count); err != nil || count != 0 {
			t.Errorf("fixture absence verification failed (rows=%d, err=%v)", count, err)
		}
	})
}

func cloneRoots(in map[domain.RootID]domain.RootAuthority) map[domain.RootID]domain.RootAuthority {
	out := make(map[domain.RootID]domain.RootAuthority, len(in))
	for id, root := range in {
		out[id] = root
	}
	return out
}
