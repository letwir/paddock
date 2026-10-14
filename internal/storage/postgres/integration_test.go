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
	t.Run("SafetyService receipts in rollback-only transaction", func(t *testing.T) {
		caseCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var baselineMode string
		var baselineActivation, baselineSecurity int64
		if err := pool.QueryRow(caseCtx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&baselineMode, &baselineActivation); err != nil {
			t.Fatalf("read pre-test scope baseline: %v", err)
		}
		if err := pool.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&baselineSecurity); err != nil {
			t.Fatalf("read pre-test security baseline: %v", err)
		}
		tx, err := pool.Begin(caseCtx)
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
		gov := newGovernanceTx(tx)
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
		service := application.NewSafetyService(outerTxTransactor{tx: tx}, quorum)
		gate := application.NewSafetyGate(outerTxTransactor{tx: tx})
		makeSigs := func(action domain.SafetyAction, epoch domain.Epoch, id string, activation *[32]byte) []domain.SafetySignature {
			var msg []byte
			var e error
			if activation == nil {
				msg, e = domain.SafetyApprovalMessage(action, snapshot.ScopeID, epoch, id)
			} else {
				msg, e = domain.SafetyApprovalMessage(action, snapshot.ScopeID, epoch, id, *activation)
			}
			if e != nil {
				t.Fatal(e)
			}
			return []domain.SafetySignature{{SignerID: signers[0].ID, Signature: ed25519.Sign(keys[0], msg)}, {SignerID: signers[1].ID, Signature: ed25519.Sign(keys[1], msg)}}
		}
		stopID := f.scope + "_stop"
		stopSigs := makeSigs(domain.SafetyActionStop, snapshot.SecurityEpoch, stopID, nil)
		stopped, err := service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, stopSigs)
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
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, preStopGrant); !errors.Is(err, domain.ErrSafeStopped) {
			t.Fatalf("CheckHighRiskAction after Stop = %v, want ErrSafeStopped", err)
		}
		var mode string
		var activationEpoch, securityEpoch int64
		if err := tx.QueryRow(caseCtx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&mode, &activationEpoch); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&securityEpoch); err != nil {
			t.Fatal(err)
		}
		if mode != "SAFE_STOPPED" || activationEpoch != int64(snapshot.ActivationEpoch) || securityEpoch != int64(snapshot.SecurityEpoch+1) {
			t.Fatalf("stopped DB state mode=%s activation=%d security=%d", mode, activationEpoch, securityEpoch)
		}
		var stopReceipt port.CommandReceipt
		if err := tx.QueryRow(caseCtx, `SELECT command_id,request_digest,status,response_bytes FROM raw.command_receipts WHERE command_id=$1`, stopID).Scan(&stopReceipt.CommandID, &stopReceipt.RequestDigest, &stopReceipt.Status, &stopReceipt.Response); err != nil {
			t.Fatal(err)
		}
		if stopReceipt.Status != "SUCCEEDED" || len(stopReceipt.Response) == 0 {
			t.Fatalf("invalid stop receipt: %+v", stopReceipt)
		}
		if _, err = service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, stopSigs); err != nil {
			t.Fatalf("Stop replay: %v", err)
		}
		changed := append([]domain.SafetySignature(nil), stopSigs...)
		changed[0].Signature = append([]byte(nil), changed[0].Signature...)
		changed[0].Signature[0] ^= 1
		if _, err = service.Stop(caseCtx, snapshot.ScopeID, snapshot.SecurityEpoch, stopID, changed); err == nil {
			t.Fatal("changed Stop request unexpectedly accepted")
		}
		activation := domain.AuthorityState{Scope: snapshot.ScopeID, ScopeActivationEpoch: snapshot.ActivationEpoch + 1, SecurityEpoch: stopped.State.SecurityEpoch + 1, Mode: domain.ScopeActive, DatabaseAvailable: true, Roots: stopped.State.Roots}
		digest, err := domain.ActivationDigest(activation)
		if err != nil {
			t.Fatal(err)
		}
		releaseID := f.scope + "_release"
		releaseSigs := makeSigs(domain.SafetyActionRelease, stopped.State.SecurityEpoch, releaseID, &digest)
		released, err := service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, activation, releaseSigs)
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
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, releasedGrant); err != nil {
			t.Fatalf("CheckHighRiskAction after Release with current grant: %v", err)
		}
		if err := gate.CheckHighRiskAction(caseCtx, snapshot.ScopeID, preStopGrant); !errors.Is(err, domain.ErrStaleGrant) {
			t.Fatalf("CheckHighRiskAction after Release with stale grant = %v, want ErrStaleGrant", err)
		}
		if _, err = service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, activation, releaseSigs); err != nil {
			t.Fatalf("Release replay: %v", err)
		}
		altered := activation
		altered.ScopeActivationEpoch++
		if _, err = service.Release(caseCtx, snapshot.ScopeID, stopped.State.SecurityEpoch, releaseID, altered, releaseSigs); err == nil {
			t.Fatal("changed Release activation unexpectedly accepted")
		}
		var releaseStatus string
		var response []byte
		if err := tx.QueryRow(caseCtx, `SELECT status,response_bytes FROM raw.command_receipts WHERE command_id=$1`, releaseID).Scan(&releaseStatus, &response); err != nil {
			t.Fatal(err)
		}
		if releaseStatus != "SUCCEEDED" || len(response) == 0 {
			t.Fatalf("invalid release receipt status=%s", releaseStatus)
		}
		if err := tx.QueryRow(caseCtx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&mode, &activationEpoch); err != nil {
			t.Fatalf("read released scope state: %v", err)
		}
		if err := tx.QueryRow(caseCtx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&securityEpoch); err != nil {
			t.Fatalf("read released security epoch: %v", err)
		}
		if mode != "ACTIVE" || activationEpoch != int64(activation.ScopeActivationEpoch) || securityEpoch != int64(released.State.SecurityEpoch) || securityEpoch != int64(stopped.State.SecurityEpoch+1) {
			t.Fatalf("released DB state mode=%s activation=%d security=%d; want mode=ACTIVE activation=%d security=%d", mode, activationEpoch, securityEpoch, activation.ScopeActivationEpoch, released.State.SecurityEpoch)
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
		var receiptCount int
		if err := pool.QueryRow(caseCtx, `SELECT count(*) FROM raw.command_receipts WHERE command_id = ANY($1::text[])`, []string{stopID, releaseID}).Scan(&receiptCount); err != nil {
			t.Fatalf("check receipts after rollback: %v", err)
		}
		if receiptCount != 0 {
			t.Fatalf("command receipts remain after rollback: count=%d", receiptCount)
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
type outerTxTransactor struct{ tx pgx.Tx }

func (o outerTxTransactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	return fn(newGovernanceTx(o.tx))
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
