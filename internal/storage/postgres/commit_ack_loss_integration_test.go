//go:build integration && paddock_test

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

var errSimulatedCommitAcknowledgementLost = errors.New("simulated commit acknowledgement lost after successful commit")

// commitAcknowledgementLossTransactor simulates a dropped response after the
// real underlying PostgreSQL transaction has committed successfully.
type commitAcknowledgementLossTransactor struct {
	inner   port.Transactor
	lostAck bool
}

func (t *commitAcknowledgementLossTransactor) WithinTransaction(ctx context.Context, fn func(port.GovernanceTx) error) error {
	if t == nil || t.inner == nil {
		return errors.New("commit acknowledgement loss transactor is not initialized")
	}
	err := t.inner.WithinTransaction(ctx, fn)
	if err != nil {
		return err
	}
	if !t.lostAck {
		t.lostAck = true
		return errSimulatedCommitAcknowledgementLost
	}
	return nil
}

func TestPostgresSafetyReceiptReplayAfterCommitAcknowledgementLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dsn := os.Getenv("PADDOCK_DB_URL")
	if dsn == "" {
		t.Fatal("PADDOCK_DB_URL must be set for the isolated M04-S02 integration test")
	}
	pool, err := openPullPool(ctx, dsn, false)
	if err != nil {
		t.Fatal("unable to connect to the configured test database")
	}
	t.Cleanup(pool.Close)
	var database, currentUser, sessionUser string
	if err := pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&database, &currentUser, &sessionUser); err != nil || database != "paddock_test" || currentUser != "paddock_migrator" || sessionUser != "paddock_migrator" {
		t.Fatalf("refusing unexpected fixture connection identity: database=%q current_user=%q session_user=%q err=%v", database, currentUser, sessionUser, err)
	}
	if err := requireSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("unable to create unique fixture IDs")
	}
	prefix := "it_m04_" + hex.EncodeToString(suffix)
	bundleHash := sha256.Sum256(suffix)
	f := fixture{
		bundle: hex.EncodeToString(bundleHash[:]),
		scope:  prefix + "_scope", root: prefix + "_root",
		otherRoot: prefix + "_other", otherScope: prefix + "_scope2",
		otherScopeRoot: prefix + "_root2", rollout: prefix + "_rollout",
	}
	var fixtureCollisions int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.policy_bundles WHERE bundle_digest=$1) +
		(SELECT count(*) FROM raw.policy_scopes WHERE scope_id=ANY($2::text[])) +
		(SELECT count(*) FROM raw.roots WHERE root_id=ANY($3::text[])) +
		(SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id=$4) +
		(SELECT count(*) FROM raw.rollout_targets WHERE rollout_id=$4)`,
		f.bundle, []string{f.scope, f.otherScope}, []string{f.root, f.otherRoot, f.otherScopeRoot}, f.rollout).Scan(&fixtureCollisions); err != nil || fixtureCollisions != 0 {
		t.Fatalf("refusing colliding fixture: rows=%d err=%v", fixtureCollisions, err)
	}
	cleanupFixtures(t, ctx, pool, f)
	if err := seedFixtures(ctx, pool, f); err != nil {
		t.Fatalf("fixture setup failed: %v", err)
	}

	appURL := os.Getenv("PADDOCK_APP_DB_URL")
	if appURL == "" {
		t.Fatal("PADDOCK_APP_DB_URL must be set for the app-role replay fixture")
	}
	appPool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to connect as paddock_app")
	}
	t.Cleanup(appPool.Close)
	var appDatabase, appCurrentUser, appSessionUser string
	if err := appPool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&appDatabase, &appCurrentUser, &appSessionUser); err != nil {
		t.Fatalf("verify app connection identity: %v", err)
	}
	if appDatabase != "paddock_test" || appCurrentUser != "paddock_app" || appSessionUser != "paddock_app" {
		t.Fatalf("unexpected app connection identity: database=%q current_user=%q session_user=%q", appDatabase, appCurrentUser, appSessionUser)
	}
	transactor, err := NewSafetyTransactor(appPool)
	if err != nil {
		t.Fatal(err)
	}
	keys, signers, quorum := newM04SafetyQuorum(t)
	ackLossTransactor := &commitAcknowledgementLossTransactor{inner: transactor}
	service := application.NewSafetyService(ackLossTransactor, quorum)

	baseline, err := readSafetyScope(ctx, transactor, domain.ScopeID(f.scope))
	if err != nil {
		t.Fatalf("read baseline Safety snapshot: %v", err)
	}
	if baseline.Mode != domain.ScopeActive {
		t.Fatalf("fixture baseline mode=%s, want ACTIVE", baseline.Mode)
	}

	stopID := prefix + "_lost_ack_stop"
	releaseID := prefix + "_cleanup_release"
	nonce := "m04-s02-commit-ack-loss"
	eventIDs := []string{"safety/" + stopID, "safety/" + releaseID}
	var commandCollisions int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($2::text[])) +
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($2::text[]))`,
		[]string{stopID, releaseID}, eventIDs).Scan(&commandCollisions); err != nil || commandCollisions != 0 {
		t.Fatalf("refusing colliding command fixture: rows=%d err=%v", commandCollisions, err)
	}

	stopSignatures, err := makeM04SafetySignatures(keys, signers, domain.SafetyActionStop, baseline, stopID, nonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	releaseCommitted := false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if ackLossTransactor.lostAck && !releaseCommitted {
			current, readErr := readSafetyScope(cleanupCtx, transactor, domain.ScopeID(f.scope))
			if readErr != nil {
				t.Errorf("cleanup: read committed Scope before Release: %v", readErr)
			} else if current.Mode == domain.ScopeSafeStop {
				activation, activationErr := nextSafetyActivation(current)
				if activationErr != nil {
					t.Errorf("cleanup: prepare Release: %v", activationErr)
				} else if releaseSignatures, signErr := makeM04SafetySignatures(keys, signers, domain.SafetyActionRelease, current, releaseID, nonce, &activation); signErr != nil {
					t.Errorf("cleanup: sign Release: %v", signErr)
				} else if _, releaseErr := service.Release(cleanupCtx, current.ScopeID, current.SecurityEpoch, releaseID, nonce, activation, releaseSignatures); releaseErr != nil {
					t.Errorf("cleanup: restore active Scope through Release: %v", releaseErr)
				} else {
					releaseCommitted = true
				}
			}
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("cleanup: delete test Outbox rows: %v", err)
			return
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("cleanup: delete test Event rows: %v", err)
			return
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM raw.command_receipts WHERE command_id=ANY($1::text[])`, []string{stopID, releaseID}); err != nil {
			t.Errorf("cleanup: delete test Receipt rows: %v", err)
			return
		}
		var receipts, events, outbox int
		if err := pool.QueryRow(cleanupCtx, `SELECT
			(SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[])),
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($2::text[])),
			(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($2::text[]))`,
			[]string{stopID, releaseID}, eventIDs).Scan(&receipts, &events, &outbox); err != nil {
			t.Errorf("cleanup: read final command row counts: %v", err)
			return
		}
		t.Logf("post-cleanup commit-unknown fixture counts: receipts=%d events=%d outbox=%d", receipts, events, outbox)
		if receipts != 0 || events != 0 || outbox != 0 {
			t.Errorf("cleanup left rows: receipts=%d events=%d outbox=%d", receipts, events, outbox)
		}
	})

	first, firstErr := service.Stop(ctx, baseline.ScopeID, baseline.SecurityEpoch, stopID, nonce, stopSignatures)
	if !errors.Is(firstErr, errSimulatedCommitAcknowledgementLost) {
		t.Fatalf("first Stop result=%+v err=%v; want simulated lost acknowledgement after a successful DB commit", first, firstErr)
	}
	if first.CommandID != "" {
		t.Fatalf("unknown commit returned a success result: %+v", first)
	}
	var committedMode string
	var committedActivation, committedSecurity int64
	if err := pool.QueryRow(ctx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&committedMode, &committedActivation); err != nil {
		t.Fatalf("read Scope after simulated lost acknowledgement: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&committedSecurity); err != nil {
		t.Fatalf("read Security Epoch after simulated lost acknowledgement: %v", err)
	}
	if committedMode != string(domain.ScopeSafeStop) || committedActivation != int64(baseline.ActivationEpoch) || committedSecurity != int64(baseline.SecurityEpoch+1) {
		t.Fatalf("committed Stop state mode=%s activation=%d security=%d; want SAFE_STOPPED/%d/%d", committedMode, committedActivation, committedSecurity, baseline.ActivationEpoch, baseline.SecurityEpoch+1)
	}
	storedReceipt := readM04CommandReceipt(t, ctx, pool, stopID)
	var storedResult domain.SafetyTransitionResult
	if err := json.Unmarshal(storedReceipt.Response, &storedResult); err != nil {
		t.Fatalf("decode committed Stop response: %v", err)
	}
	assertM04CommandRows(t, ctx, pool, []string{stopID}, []string{"safety/" + stopID}, 1, 1, 1)

	replayed, err := service.Stop(ctx, baseline.ScopeID, baseline.SecurityEpoch, stopID, nonce, stopSignatures)
	if err != nil {
		t.Fatalf("retry after lost commit acknowledgement: %v", err)
	}
	if !reflect.DeepEqual(replayed, storedResult) {
		t.Fatalf("replayed result differs from durable Receipt: got=%+v want=%+v", replayed, storedResult)
	}
	changedSignatures := append([]domain.SafetySignature(nil), stopSignatures...)
	changedSignatures[0].Signature = append([]byte(nil), stopSignatures[0].Signature...)
	changedSignatures[0].Signature[0] ^= 1
	if _, err := service.Stop(ctx, baseline.ScopeID, baseline.SecurityEpoch, stopID, nonce, changedSignatures); err == nil {
		t.Fatal("same command ID with a different request was accepted after commit-ack-loss replay")
	}
	var replayMode string
	var replayActivation, replaySecurity int64
	if err := pool.QueryRow(ctx, `SELECT mode,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, f.scope).Scan(&replayMode, &replayActivation); err != nil {
		t.Fatalf("read Scope after Receipt replay: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&replaySecurity); err != nil {
		t.Fatalf("read Security Epoch after Receipt replay: %v", err)
	}
	if replayMode != committedMode || replayActivation != committedActivation || replaySecurity != committedSecurity {
		t.Fatalf("Receipt replay changed persisted state: mode=%s activation=%d security=%d; before=%s/%d/%d", replayMode, replayActivation, replaySecurity, committedMode, committedActivation, committedSecurity)
	}
	assertM04CommandRows(t, ctx, pool, []string{stopID}, []string{"safety/" + stopID}, 1, 1, 1)

	current, err := readSafetyScope(ctx, transactor, baseline.ScopeID)
	if err != nil {
		t.Fatalf("read Scope before cleanup Release: %v", err)
	}
	activation, err := nextSafetyActivation(current)
	if err != nil {
		t.Fatal(err)
	}
	releaseSignatures, err := makeM04SafetySignatures(keys, signers, domain.SafetyActionRelease, current, releaseID, nonce, &activation)
	if err != nil {
		t.Fatal(err)
	}
	released, err := service.Release(ctx, current.ScopeID, current.SecurityEpoch, releaseID, nonce, activation, releaseSignatures)
	if err != nil || released.State.Mode != domain.ScopeActive || released.State.SecurityEpoch != baseline.SecurityEpoch+2 {
		t.Fatalf("cleanup Release=%+v err=%v", released, err)
	}
	releaseCommitted = true
	var finalSecurity int64
	if err := pool.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&finalSecurity); err != nil {
		t.Fatal(err)
	}
	if finalSecurity != int64(baseline.SecurityEpoch+2) {
		t.Fatalf("final Security Epoch=%d, want monotone +2=%d", finalSecurity, baseline.SecurityEpoch+2)
	}
	assertM04CommandRows(t, ctx, pool, []string{stopID, releaseID}, eventIDs, 2, 2, 2)
	t.Logf("commit-unknown replay preserved Stop epoch; dedicated paddock_test Security Epoch advanced monotonically by %d", finalSecurity-int64(baseline.SecurityEpoch))
}

func newM04SafetyQuorum(t *testing.T) ([]ed25519.PrivateKey, []domain.SafetySigner, domain.SafetyQuorum) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	signers := make([]domain.SafetySigner, 3)
	for i := range keys {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = privateKey
		signers[i] = domain.SafetySigner{ID: fmt.Sprintf("m04-test-key-%d", i), PublicKey: publicKey}
	}
	quorum, err := domain.NewSafetyQuorum(signers)
	if err != nil {
		t.Fatal(err)
	}
	return keys, signers, quorum
}

func makeM04SafetySignatures(keys []ed25519.PrivateKey, signers []domain.SafetySigner, action domain.SafetyAction, state port.ScopeSnapshot, commandID, nonce string, activation *domain.AuthorityState) ([]domain.SafetySignature, error) {
	var message []byte
	var err error
	if activation == nil {
		message, err = domain.SafetyApprovalMessage(action, state.ScopeID, state.SecurityEpoch, commandID, nonce)
	} else {
		digest, digestErr := domain.ActivationDigest(*activation)
		if digestErr != nil {
			return nil, digestErr
		}
		message, err = domain.SafetyApprovalMessage(action, state.ScopeID, state.SecurityEpoch, commandID, nonce, digest)
	}
	if err != nil {
		return nil, err
	}
	return []domain.SafetySignature{
		{SignerID: signers[0].ID, Signature: ed25519.Sign(keys[0], message)},
		{SignerID: signers[1].ID, Signature: ed25519.Sign(keys[1], message)},
	}, nil
}

func readSafetyScope(ctx context.Context, transactor port.Transactor, scopeID domain.ScopeID) (port.ScopeSnapshot, error) {
	var snapshot port.ScopeSnapshot
	err := transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		var err error
		snapshot, err = tx.LockScope(ctx, scopeID)
		return err
	})
	return snapshot, err
}

func nextSafetyActivation(current port.ScopeSnapshot) (domain.AuthorityState, error) {
	activationEpoch, err := current.ActivationEpoch.Next()
	if err != nil {
		return domain.AuthorityState{}, err
	}
	securityEpoch, err := current.SecurityEpoch.Next()
	if err != nil {
		return domain.AuthorityState{}, err
	}
	return domain.AuthorityState{
		Scope: current.ScopeID, ScopeActivationEpoch: activationEpoch,
		SecurityEpoch: securityEpoch, Mode: domain.ScopeActive,
		DatabaseAvailable: true, Roots: current.Roots,
	}, nil
}

func readM04CommandReceipt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, commandID string) port.CommandReceipt {
	t.Helper()
	var receipt port.CommandReceipt
	var digest string
	if err := pool.QueryRow(ctx, `SELECT command_id,request_digest,status,response_bytes FROM raw.command_receipts WHERE command_id=$1`, commandID).Scan(&receipt.CommandID, &digest, &receipt.Status, &receipt.Response); err != nil {
		t.Fatalf("read committed command Receipt: %v", err)
	}
	parsed, err := domain.ParseDigest(digest)
	if err != nil {
		t.Fatalf("parse committed command Receipt digest: %v", err)
	}
	receipt.RequestDigest = parsed
	return receipt
}

func assertM04CommandRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, commandIDs, eventIDs []string, wantReceipts, wantEvents, wantOutbox int) {
	t.Helper()
	var receipts, events, outbox int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[])),
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($2::text[])),
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($2::text[]))`, commandIDs, eventIDs).Scan(&receipts, &events, &outbox); err != nil {
		t.Fatalf("read command/Event/Outbox rows: %v", err)
	}
	if receipts != wantReceipts || events != wantEvents || outbox != wantOutbox {
		t.Fatalf("command row counts receipts/events/outbox=%d/%d/%d, want %d/%d/%d", receipts, events, outbox, wantReceipts, wantEvents, wantOutbox)
	}
}
