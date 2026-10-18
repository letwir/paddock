//go:build integration && paddock_test

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func TestPostgresOutboxLeaseRetryDeadLetterAndRedrive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL must be set")
	}
	pool, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("unable to connect to the configured test database")
	}
	t.Cleanup(pool.Close)
	var database, currentUser, sessionUser string
	if err := pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&database, &currentUser, &sessionUser); err != nil || database != "paddock_test" || currentUser != "paddock_migrator" || sessionUser != "paddock_migrator" {
		t.Fatalf("refusing setup identity: database=%q current_user=%q session_user=%q err=%v", database, currentUser, sessionUser, err)
	}
	if err := requireSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	appPool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to connect as paddock_app")
	}
	t.Cleanup(appPool.Close)
	if err := requireOutboxDispatchSchema(ctx, pool, appPool); err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("unable to create unique Outbox fixture IDs")
	}
	prefix := "it_m05_outbox_" + hex.EncodeToString(suffix)
	aggregateID := prefix + "_aggregate"
	eventIDs := []string{prefix + "_claim", prefix + "_retry"}
	var collisions, pending int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.domain_events WHERE aggregate_kind='scope' AND aggregate_id=$2 AND aggregate_version IN (1,2))`, eventIDs, aggregateID).Scan(&collisions); err != nil || collisions != 0 {
		t.Fatalf("refusing colliding fixture: rows=%d err=%v", collisions, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM raw.event_outbox WHERE published_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("refusing to claim over existing pending Outbox rows: rows=%d err=%v", pending, err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if _, err := pool.Exec(cleanCtx, `DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("Outbox fixture cleanup failed: %v", err)
			return
		}
		if _, err := pool.Exec(cleanCtx, `DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("Event fixture cleanup failed: %v", err)
			return
		}
		var rows int
		if err := pool.QueryRow(cleanCtx, `SELECT
			(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])) +
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[]))`, eventIDs).Scan(&rows); err != nil || rows != 0 {
			t.Errorf("Outbox/Event fixture absence check failed (rows=%d err=%v)", rows, err)
		}
	})

	store, err := NewPostgresOutboxStore(appPool)
	if err != nil {
		t.Fatal(err)
	}

	// LISTEN is committed before Event append; the notification is only a hint.
	listener, err := store.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listenerOpen := true
	t.Cleanup(func() {
		if listenerOpen {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer closeCancel()
			if err := listener.Close(closeCtx); err != nil {
				t.Errorf("Outbox listener cleanup failed: %v", err)
			}
		}
	})
	appendEvent := func(eventID string, version int64) {
		t.Helper()
		event, err := domain.NewEvent(eventID, "scope", aggregateID, version, "OutboxFixture", "event/1", []byte(`{"fixture":true}`))
		if err != nil {
			t.Fatal(err)
		}
		transactor, err := NewTransactor(appPool)
		if err != nil {
			t.Fatal(err)
		}
		if err := transactor.WithinTransaction(ctx, func(gov port.GovernanceTx) error { return gov.AppendEvent(ctx, event) }); err != nil {
			t.Fatalf("append app-role Event: %v", err)
		}
	}
	appendEvent(eventIDs[0], 1)
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := listener.Wait(waitCtx); err != nil {
		waitCancel()
		t.Fatalf("commit-aligned Outbox NOTIFY missing: %v", err)
	}
	waitCancel()
	if err := listener.Close(ctx); err != nil {
		t.Fatal(err)
	}
	listenerOpen = false

	// Two independent app transactions race for one pending Event; exactly one owns it.
	start := make(chan struct{})
	type claimResult struct {
		claims []port.OutboxClaim
		err    error
	}
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claims, err := store.Claim(ctx, 1)
			results <- claimResult{claims: claims, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var first *port.OutboxClaim
	empty := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent Claim failed: %v", result.err)
		}
		if len(result.claims) == 0 {
			empty++
			continue
		}
		if len(result.claims) != 1 || first != nil {
			t.Fatalf("duplicate/wide claim: %+v", result.claims)
		}
		claim := result.claims[0]
		first = &claim
	}
	if first == nil || empty != 1 || first.Event.ID() != eventIDs[0] {
		t.Fatalf("Claim winners=%+v empty=%d, want one owner for %q", first, empty, eventIDs[0])
	}
	if _, err := pool.Exec(ctx, `UPDATE raw.event_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE event_id=$1 AND claim_token=$2::uuid`, first.Event.ID(), first.ClaimToken); err != nil {
		t.Fatalf("expire crashed Claim lease: %v", err)
	}
	if acked, err := store.Ack(ctx, first.Event.ID(), first.ClaimToken); err != nil || acked {
		t.Fatalf("expired Claim Ack accepted=%t err=%v, want false", acked, err)
	}
	if disposition, err := store.Retry(ctx, first.Event.ID(), first.ClaimToken, "TEST_STALE"); err != nil || disposition != port.OutboxClaimStale {
		t.Fatalf("expired Claim Retry disposition=%s err=%v, want stale", disposition, err)
	}
	reclaimed, err := store.Claim(ctx, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim expired lease count=%d err=%v", len(reclaimed), err)
	}
	second := reclaimed[0]
	if second.Event.ID() != first.Event.ID() || second.ClaimToken == first.ClaimToken || second.AttemptCount != first.AttemptCount+1 {
		t.Fatalf("reclaimed lease did not fence/increment: first=%+v second=%+v", *first, second)
	}
	if acked, err := store.Ack(ctx, first.Event.ID(), first.ClaimToken); err != nil || acked {
		t.Fatalf("stale Ack accepted=%t err=%v, want false", acked, err)
	}
	if acked, err := store.Ack(ctx, second.Event.ID(), second.ClaimToken); err != nil || !acked {
		t.Fatalf("current Ack accepted=%t err=%v, want true", acked, err)
	}

	appendEvent(eventIDs[1], 2)
	claim, err := store.Claim(ctx, 1)
	if err != nil || len(claim) != 1 || claim[0].Event.ID() != eventIDs[1] {
		t.Fatalf("claim retry fixture=%+v err=%v", claim, err)
	}
	for expectedAttempt := int32(1); expectedAttempt <= 20; expectedAttempt++ {
		disposition, err := store.Retry(ctx, eventIDs[1], claim[0].ClaimToken, "TEST_FAILURE")
		if err != nil {
			t.Fatalf("retry attempt %d: %v", expectedAttempt, err)
		}
		if expectedAttempt == 20 {
			if disposition != port.OutboxDeadLettered {
				t.Fatalf("attempt 20 disposition=%s, want DLQ", disposition)
			}
			break
		}
		if disposition != port.OutboxRetryScheduled {
			t.Fatalf("attempt %d disposition=%s, want retry scheduled", expectedAttempt, disposition)
		}
		if expectedAttempt == 1 || expectedAttempt == 11 {
			assertOutboxBackoff(t, ctx, pool, eventIDs[1], expectedAttempt)
		}
		if _, err := pool.Exec(ctx, `UPDATE raw.event_outbox SET available_at=clock_timestamp() WHERE event_id=$1`, eventIDs[1]); err != nil {
			t.Fatalf("advance fixture retry due time: %v", err)
		}
		claim, err = store.Claim(ctx, 1)
		if err != nil || len(claim) != 1 || claim[0].AttemptCount != expectedAttempt+1 {
			t.Fatalf("attempt %d Claim=%+v err=%v", expectedAttempt+1, claim, err)
		}
	}
	var attempts, redrives int32
	var isDeadLettered bool
	if err := pool.QueryRow(ctx, `SELECT attempt_count,redrive_count,dead_lettered_at IS NOT NULL FROM raw.event_outbox WHERE event_id=$1`, eventIDs[1]).Scan(&attempts, &redrives, &isDeadLettered); err != nil {
		t.Fatal(err)
	}
	if attempts != 20 || redrives != 0 || !isDeadLettered {
		t.Fatalf("first DLQ state attempts=%d redrives=%d dead=%t", attempts, redrives, isDeadLettered)
	}
	if _, err := pool.Exec(ctx, `UPDATE raw.event_outbox SET dead_lettered_at=clock_timestamp()-interval '25 hours' WHERE event_id=$1 AND redrive_count=0`, eventIDs[1]); err != nil {
		t.Fatal(err)
	}
	// Redrive housekeeping consumes this one-row batch; the next poll claims it.
	redriveBatch, err := store.Claim(ctx, 1)
	if err != nil || len(redriveBatch) != 0 {
		t.Fatalf("automatic redrive housekeeping claims=%+v err=%v, want empty batch", redriveBatch, err)
	}
	var redriveCountAfterHousekeeping int32
	var requeued, due bool
	if err := pool.QueryRow(ctx, `SELECT redrive_count,dead_lettered_at IS NULL,available_at<=clock_timestamp() FROM raw.event_outbox WHERE event_id=$1`, eventIDs[1]).Scan(&redriveCountAfterHousekeeping, &requeued, &due); err != nil {
		t.Fatal(err)
	}
	if redriveCountAfterHousekeeping != 1 || !requeued || !due {
		t.Fatalf("automatic redrive housekeeping state count=%d requeued=%t due=%t", redriveCountAfterHousekeeping, requeued, due)
	}
	claim, err = store.Claim(ctx, 1)
	if err != nil || len(claim) != 1 || claim[0].AttemptCount != 21 {
		t.Fatalf("automatic redrive Claim=%+v err=%v, want attempt 21", claim, err)
	}
	for expectedAttempt := int32(21); expectedAttempt <= 40; expectedAttempt++ {
		disposition, err := store.Retry(ctx, eventIDs[1], claim[0].ClaimToken, "TEST_FAILURE")
		if err != nil {
			t.Fatalf("redrive attempt %d: %v", expectedAttempt, err)
		}
		if expectedAttempt == 40 {
			if disposition != port.OutboxDeadLettered {
				t.Fatalf("attempt 40 disposition=%s, want terminal DLQ", disposition)
			}
			break
		}
		if disposition != port.OutboxRetryScheduled {
			t.Fatalf("attempt %d disposition=%s, want retry scheduled", expectedAttempt, disposition)
		}
		if expectedAttempt == 21 {
			assertOutboxBackoff(t, ctx, pool, eventIDs[1], expectedAttempt-20)
		}
		if _, err := pool.Exec(ctx, `UPDATE raw.event_outbox SET available_at=clock_timestamp() WHERE event_id=$1`, eventIDs[1]); err != nil {
			t.Fatalf("advance redrive due time: %v", err)
		}
		claim, err = store.Claim(ctx, 1)
		if err != nil || len(claim) != 1 || claim[0].AttemptCount != expectedAttempt+1 {
			t.Fatalf("attempt %d Claim=%+v err=%v", expectedAttempt+1, claim, err)
		}
	}
	var totalAttempts, redriveCount int32
	var terminalDead bool
	if err := pool.QueryRow(ctx, `SELECT attempt_count,redrive_count,dead_lettered_at IS NOT NULL FROM raw.event_outbox WHERE event_id=$1`, eventIDs[1]).Scan(&totalAttempts, &redriveCount, &terminalDead); err != nil {
		t.Fatal(err)
	}
	if totalAttempts != 40 || redriveCount != 1 || !terminalDead {
		t.Fatalf("terminal DLQ state attempts=%d redrives=%d dead=%t", totalAttempts, redriveCount, terminalDead)
	}
	terminalClaims, err := store.Claim(ctx, 1)
	if err != nil || len(terminalClaims) != 0 {
		t.Fatalf("terminal DLQ was claimed again: claims=%+v err=%v", terminalClaims, err)
	}
	var publishedAt pgtype.Timestamptz
	if err := pool.QueryRow(ctx, `SELECT published_at FROM raw.event_outbox WHERE event_id=$1`, eventIDs[1]).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	if publishedAt.Valid {
		t.Fatalf("terminal DLQ marked published at %v", publishedAt.Time)
	}
	var finalEvents, finalOutbox, finalPublished int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])),
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])),
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[]) AND published_at IS NOT NULL)`, eventIDs).Scan(&finalEvents, &finalOutbox, &finalPublished); err != nil {
		t.Fatal(err)
	}
	if finalEvents != 2 || finalOutbox != 2 || finalPublished != 1 {
		t.Fatalf("final fixture counts events=%d outbox=%d published=%d, want 2/2/1", finalEvents, finalOutbox, finalPublished)
	}
	t.Logf("Outbox lease/retry/redrive PASS: events=%d outbox=%d published=%d; total_attempts=%d redrives=%d terminal=%t", finalEvents, finalOutbox, finalPublished, totalAttempts, redriveCount, terminalDead)
}

func requireOutboxDispatchSchema(ctx context.Context, setupPool, appPool *pgxpool.Pool) error {
	var functionCount, safeFunctionCount, appExecuteCount, publicExecuteCount, otherExecuteCount int
	const functionACLQuery = `WITH funcs AS (
		SELECT p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig
		FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
		WHERE n.nspname='raw' AND p.proname IN ('claim_event_outbox','ack_event_outbox','retry_event_outbox','append_domain_event_and_outbox')
	) SELECT
		(SELECT count(*) FROM funcs),
		(SELECT count(*) FROM funcs f JOIN pg_catalog.pg_roles r ON r.oid=f.proowner WHERE r.rolname='paddock_migrator' AND f.prosecdef AND f.proconfig @> ARRAY['search_path=pg_catalog']::text[]),
		(SELECT count(*) FROM funcs f WHERE pg_catalog.has_function_privilege('paddock_app',f.oid,'EXECUTE')),
		(SELECT count(*) FROM funcs f CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'),
		(SELECT count(*) FROM funcs f CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) a WHERE a.grantee<>f.proowner AND a.grantee<>0 AND a.grantee<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app') AND a.privilege_type='EXECUTE')`
	if err := setupPool.QueryRow(ctx, functionACLQuery).Scan(&functionCount, &safeFunctionCount, &appExecuteCount, &publicExecuteCount, &otherExecuteCount); err != nil {
		return errors.New("Outbox function ACL read-only preflight failed")
	}
	if functionCount != 4 || safeFunctionCount != 4 || appExecuteCount != 4 || publicExecuteCount != 0 || otherExecuteCount != 0 {
		return fmt.Errorf("Outbox function ACL mismatch: functions=%d safe=%d app_exec=%d public_exec=%d other_exec=%d", functionCount, safeFunctionCount, appExecuteCount, publicExecuteCount, otherExecuteCount)
	}

	var hasColumns, hasConstraints, claimIndexValid, redriveIndexValid bool
	const schemaQuery = `SELECT
		(SELECT count(*)=4 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped AND ((a.attname='claim_token' AND a.atttypid='uuid'::regtype) OR (a.attname IN ('lease_expires_at','dead_lettered_at') AND a.atttypid='timestamptz'::regtype) OR (a.attname='redrive_count' AND a.atttypid='integer'::regtype))),
		(SELECT count(*)=4 FROM pg_catalog.pg_constraint c WHERE c.conrelid='raw.event_outbox'::regclass AND c.conname IN ('event_outbox_claim_pair_ck','event_outbox_dead_letter_unclaimed_ck','event_outbox_published_not_dead_lettered_ck','event_outbox_redrive_count_ck') AND c.convalidated),
		(SELECT i.indisvalid AND i.indisready FROM pg_catalog.pg_index i WHERE i.indexrelid=pg_catalog.to_regclass('raw.event_outbox_claimable_idx')),
		(SELECT i.indisvalid AND i.indisready FROM pg_catalog.pg_index i WHERE i.indexrelid=pg_catalog.to_regclass('raw.event_outbox_redrive_idx'))`
	if err := setupPool.QueryRow(ctx, schemaQuery).Scan(&hasColumns, &hasConstraints, &claimIndexValid, &redriveIndexValid); err != nil {
		return errors.New("Outbox schema/index read-only preflight failed")
	}
	if !hasColumns || !hasConstraints || !claimIndexValid || !redriveIndexValid {
		return fmt.Errorf("Outbox schema/index mismatch: columns=%t constraints=%t indexes=%t/%t", hasColumns, hasConstraints, claimIndexValid, redriveIndexValid)
	}

	var hasEventRead, noEventWrite, noOutboxTableAccess, noOutboxColumnAccess bool
	const privilegeQuery = `SELECT
		pg_catalog.has_table_privilege('paddock_app','raw.domain_events','SELECT'),
		NOT pg_catalog.has_table_privilege('paddock_app','raw.domain_events','INSERT'),
		NOT (pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','SELECT') OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','INSERT') OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','UPDATE') OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','DELETE')),
		NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped AND (pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'SELECT') OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'INSERT') OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'UPDATE') OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'REFERENCES')))`
	if err := setupPool.QueryRow(ctx, privilegeQuery).Scan(&hasEventRead, &noEventWrite, &noOutboxTableAccess, &noOutboxColumnAccess); err != nil {
		return errors.New("Outbox privilege read-only preflight failed")
	}
	if !hasEventRead || !noEventWrite || !noOutboxTableAccess || !noOutboxColumnAccess {
		return fmt.Errorf("Outbox privilege mismatch: event_read=%t event_insert_denied=%t outbox_table_denied=%t outbox_columns_denied=%t", hasEventRead, noEventWrite, noOutboxTableAccess, noOutboxColumnAccess)
	}

	var appDatabase, appCurrentUser, appSessionUser string
	if err := appPool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&appDatabase, &appCurrentUser, &appSessionUser); err != nil || appDatabase != "paddock_test" || appCurrentUser != "paddock_app" || appSessionUser != "paddock_app" {
		return errors.New("Outbox app-role preflight identity mismatch")
	}
	return nil
}

func assertOutboxBackoff(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventID string, cycleAttempt int32) {
	t.Helper()
	var remaining float64
	if err := pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM (available_at-clock_timestamp())) FROM raw.event_outbox WHERE event_id=$1`, eventID).Scan(&remaining); err != nil {
		t.Fatalf("read Outbox retry backoff: %v", err)
	}
	exponent := cycleAttempt - 1
	if exponent > 10 {
		exponent = 10
	}
	want := 5.0 * float64(uint64(1)<<exponent)
	if want > 3600 {
		want = 3600
	}
	if remaining < want-1 || remaining > want+1 {
		t.Fatalf("retry backoff remaining=%.3fs, want approximately %.0fs for cycle attempt %d", remaining, want, cycleAttempt)
	}
}
