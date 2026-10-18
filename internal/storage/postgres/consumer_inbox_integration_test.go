//go:build integration && paddock_test

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func TestPostgresConsumerInboxAppliesEventOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL must be set")
	}
	setupPool, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("unable to connect to the configured test database")
	}
	t.Cleanup(setupPool.Close)
	var database, currentUser, sessionUser string
	if err := setupPool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&database, &currentUser, &sessionUser); err != nil || database != "paddock_test" || currentUser != "paddock_migrator" || sessionUser != "paddock_migrator" {
		t.Fatalf("refusing setup identity: database=%q current_user=%q session_user=%q err=%v", database, currentUser, sessionUser, err)
	}
	if err := requireSchema(ctx, setupPool); err != nil {
		t.Fatal(err)
	}
	appPool, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to connect as paddock_app")
	}
	t.Cleanup(appPool.Close)
	if err := requireConsumerInboxSchema(ctx, setupPool, appPool); err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("unable to create unique consumer Inbox fixture IDs")
	}
	prefix := "it_m05_inbox_" + hex.EncodeToString(suffix)
	aggregateID := prefix + "_aggregate"
	eventIDs := []string{prefix + "_duplicate", prefix + "_retry"}
	consumerIDs := []string{prefix + "_consumer", prefix + "_second", prefix + "_failed"}
	var collisions, pending int
	if err := setupPool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.event_inbox WHERE event_id=ANY($1::text[])) +
		(SELECT count(*) FROM raw.event_inbox WHERE consumer_id=ANY($2::text[])) +
		(SELECT count(*) FROM raw.event_consumer_projection WHERE consumer_id=ANY($2::text[])) +
		(SELECT count(*) FROM raw.domain_events WHERE aggregate_kind='scope' AND aggregate_id=$3 AND aggregate_version IN (1,2))`, eventIDs, consumerIDs, aggregateID).Scan(&collisions); err != nil || collisions != 0 {
		t.Fatalf("refusing colliding consumer Inbox fixture: rows=%d err=%v", collisions, err)
	}
	if err := setupPool.QueryRow(ctx, `SELECT count(*) FROM raw.event_outbox WHERE published_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("refusing to run with existing unpublished Outbox work: rows=%d err=%v", pending, err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if _, err := setupPool.Exec(cleanCtx, `DELETE FROM raw.event_inbox WHERE event_id=ANY($1::text[]) AND consumer_id=ANY($2::text[])`, eventIDs, consumerIDs); err != nil {
			t.Errorf("consumer Inbox fixture cleanup failed: %v", err)
			return
		}
		if _, err := setupPool.Exec(cleanCtx, `DELETE FROM raw.event_consumer_projection WHERE consumer_id=ANY($1::text[])`, consumerIDs); err != nil {
			t.Errorf("consumer projection fixture cleanup failed: %v", err)
			return
		}
		if _, err := setupPool.Exec(cleanCtx, `DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("Outbox fixture cleanup failed: %v", err)
			return
		}
		if _, err := setupPool.Exec(cleanCtx, `DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])`, eventIDs); err != nil {
			t.Errorf("Event fixture cleanup failed: %v", err)
			return
		}
		var remaining int
		if err := setupPool.QueryRow(cleanCtx, `SELECT
			(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])) +
			(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])) +
			(SELECT count(*) FROM raw.event_inbox WHERE event_id=ANY($1::text[]) AND consumer_id=ANY($2::text[])) +
			(SELECT count(*) FROM raw.event_inbox WHERE consumer_id=ANY($2::text[])) +
			(SELECT count(*) FROM raw.event_consumer_projection WHERE consumer_id=ANY($2::text[]))`, eventIDs, consumerIDs).Scan(&remaining); err != nil || remaining != 0 {
			t.Errorf("consumer Inbox fixture absence check failed (rows=%d err=%v)", remaining, err)
		}
		if err := setupPool.QueryRow(cleanCtx, `SELECT count(*) FROM raw.event_outbox WHERE published_at IS NULL`).Scan(&remaining); err != nil || remaining != 0 {
			t.Errorf("unpublished Outbox rows remain after cleanup (rows=%d err=%v)", remaining, err)
		}
	})

	transactor, err := NewTransactor(appPool)
	if err != nil {
		t.Fatal(err)
	}
	for i, eventID := range eventIDs {
		event, err := domain.NewEvent(eventID, "scope", aggregateID, int64(i+1), "ConsumerInboxFixture", "event/1", []byte(`{"fixture":true}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := transactor.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
			return tx.AppendEvent(ctx, event)
		}); err != nil {
			t.Fatalf("append fixture Event %q: %v", eventID, err)
		}
	}
	store, err := NewPostgresConsumerInboxStore(appPool)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := application.NewConsumerInboxProcessor(store)
	if err != nil {
		t.Fatal(err)
	}
	duplicateEvent, err := domain.NewEvent(eventIDs[0], "scope", aggregateID, 1, "ConsumerInboxFixture", "event/1", []byte(`{"fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	for delivery, wantApplied := range []bool{true, false, false} {
		applied, err := processor.Process(ctx, consumerIDs[0], duplicateEvent)
		if err != nil || applied != wantApplied {
			t.Fatalf("delivery %d Process() = (%t, %v), want applied=%t", delivery+1, applied, err, wantApplied)
		}
	}
	assertConsumerInboxState(t, ctx, setupPool, consumerIDs[0], eventIDs[0], 1, 1)

	// A second consumer has an independent Inbox key and local effect for the
	// same Event; idempotency is scoped by (consumer_id,event_id).
	if applied, err := processor.Process(ctx, consumerIDs[1], duplicateEvent); err != nil || !applied {
		t.Fatalf("second consumer Process() = (%t, %v), want first application", applied, err)
	}
	assertConsumerInboxState(t, ctx, setupPool, consumerIDs[1], eventIDs[0], 1, 1)

	// Force the projection upsert to overflow after the Inbox insert. The whole
	// app-role transaction must roll back the Inbox marker, allowing redelivery.
	if _, err := setupPool.Exec(ctx, `INSERT INTO raw.event_consumer_projection (consumer_id,processed_event_count) VALUES ($1,$2)`, consumerIDs[2], int64(math.MaxInt64)); err != nil {
		t.Fatalf("seed overflow projection: %v", err)
	}
	retryEvent, err := domain.NewEvent(eventIDs[1], "scope", aggregateID, 2, "ConsumerInboxFixture", "event/1", []byte(`{"fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := processor.Process(ctx, consumerIDs[2], retryEvent); err == nil || applied {
		t.Fatalf("overflow Process() = (%t, %v), want effect error and rollback", applied, err)
	}
	var retryInboxRows int
	var retryCounter int64
	if err := setupPool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.event_inbox WHERE consumer_id=$1 AND event_id=$2),
		(SELECT processed_event_count FROM raw.event_consumer_projection WHERE consumer_id=$1)`, consumerIDs[2], eventIDs[1]).Scan(&retryInboxRows, &retryCounter); err != nil {
		t.Fatalf("read failed-effect rollback state: %v", err)
	}
	if retryInboxRows != 0 || retryCounter != int64(math.MaxInt64) {
		t.Fatalf("failed effect state inbox=%d counter=%d; want inbox=0 counter=MaxInt64", retryInboxRows, retryCounter)
	}
	if _, err := setupPool.Exec(ctx, `UPDATE raw.event_consumer_projection SET processed_event_count=0 WHERE consumer_id=$1`, consumerIDs[2]); err != nil {
		t.Fatalf("reset overflow fixture counter: %v", err)
	}
	if applied, err := processor.Process(ctx, consumerIDs[2], retryEvent); err != nil || !applied {
		t.Fatalf("redelivery after rollback Process() = (%t, %v), want applied=true", applied, err)
	}
	if applied, err := processor.Process(ctx, consumerIDs[2], retryEvent); err != nil || applied {
		t.Fatalf("duplicate after retry Process() = (%t, %v), want applied=false", applied, err)
	}
	assertConsumerInboxState(t, ctx, setupPool, consumerIDs[2], eventIDs[1], 1, 1)

	var finalEvents, finalOutbox, finalPending int
	if err := setupPool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])),
		(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])),
		(SELECT count(*) FROM raw.event_outbox WHERE published_at IS NULL)`, eventIDs).Scan(&finalEvents, &finalOutbox, &finalPending); err != nil {
		t.Fatal(err)
	}
	if finalEvents != 2 || finalOutbox != 2 || finalPending != 2 {
		t.Fatalf("final fixture counts events=%d outbox=%d pending=%d, want 2/2/2", finalEvents, finalOutbox, finalPending)
	}
	t.Logf("Consumer Inbox PASS: duplicate_deliveries=3 same_event_effects=1 second_consumer_effects=1 failed_effect_inbox_rows=0 retried_effects=1")
}

func assertConsumerInboxState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, consumerID, eventID string, wantInbox int, wantCount int64) {
	t.Helper()
	var inboxRows int
	var processedCount int64
	var processedAt bool
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM raw.event_inbox WHERE consumer_id=$1 AND event_id=$2),
		(SELECT processed_event_count FROM raw.event_consumer_projection WHERE consumer_id=$1),
		(SELECT processed_at IS NOT NULL FROM raw.event_inbox WHERE consumer_id=$1 AND event_id=$2)`, consumerID, eventID).Scan(&inboxRows, &processedCount, &processedAt); err != nil {
		t.Fatalf("read consumer Inbox state: %v", err)
	}
	if inboxRows != wantInbox || processedCount != wantCount || !processedAt {
		t.Fatalf("consumer Inbox state inbox=%d projection=%d processed_at=%t; want inbox=%d projection=%d processed_at=true", inboxRows, processedCount, processedAt, wantInbox, wantCount)
	}
}

func requireConsumerInboxSchema(ctx context.Context, setupPool, appPool *pgxpool.Pool) error {
	var db, currentUser, sessionUser string
	if err := appPool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &currentUser, &sessionUser); err != nil || db != "paddock_test" || currentUser != "paddock_app" || sessionUser != "paddock_app" {
		return fmt.Errorf("refusing app identity database=%q current_user=%q session_user=%q err=%v", db, currentUser, sessionUser, err)
	}
	var inboxShape, inboxPrimaryKey, inboxUniqueIndex, projectionShape, projectionConstraints, projectionPrimaryKey bool
	if err := setupPool.QueryRow(ctx, `SELECT
		(SELECT count(*)=4 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_inbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
		 AND ((a.attname='consumer_id' AND a.atttypid='text'::regtype AND a.attnotnull)
		   OR (a.attname='event_id' AND a.atttypid='text'::regtype AND a.attnotnull)
		   OR (a.attname='received_at' AND a.atttypid='timestamptz'::regtype AND a.attnotnull)
		   OR (a.attname='processed_at' AND a.atttypid='timestamptz'::regtype AND NOT a.attnotnull))
		 AND (SELECT count(*)=4 FROM pg_catalog.pg_attribute x WHERE x.attrelid='raw.event_inbox'::regclass AND x.attnum>0 AND NOT x.attisdropped)),
		EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='raw.event_inbox'::regclass AND c.contype='p' AND c.convalidated
		 AND c.conkey=ARRAY[(SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_inbox'::regclass AND a.attname='consumer_id' AND a.attnum>0 AND NOT a.attisdropped),
		                   (SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_inbox'::regclass AND a.attname='event_id' AND a.attnum>0 AND NOT a.attisdropped)]::smallint[]),
		((SELECT count(*)=2 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_consumer_projection'::regclass AND a.attnum>0 AND NOT a.attisdropped
		 AND ((a.attname='consumer_id' AND a.atttypid='text'::regtype AND a.attnotnull)
		   OR (a.attname='processed_event_count' AND a.atttypid='int8'::regtype AND a.attnotnull)))
		 AND (SELECT count(*)=2 FROM pg_catalog.pg_attribute x WHERE x.attrelid='raw.event_consumer_projection'::regclass AND x.attnum>0 AND NOT x.attisdropped)),
		(SELECT count(*)=3 FROM pg_catalog.pg_constraint c WHERE c.conrelid='raw.event_consumer_projection'::regclass AND c.convalidated
		 AND c.conname IN ('event_consumer_projection_consumer_pk','event_consumer_projection_consumer_ck','event_consumer_projection_count_ck')),
		EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='raw.event_consumer_projection'::regclass AND c.contype='p' AND c.convalidated
		 AND c.conkey=ARRAY[(SELECT a.attnum FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_consumer_projection'::regclass AND a.attname='consumer_id' AND a.attnum>0 AND NOT a.attisdropped)]::smallint[]),
		(SELECT count(*)=1 FROM pg_catalog.pg_index i WHERE i.indrelid='raw.event_inbox'::regclass AND i.indisunique AND i.indisvalid AND i.indisready)`).Scan(&inboxShape, &inboxPrimaryKey, &projectionShape, &projectionConstraints, &projectionPrimaryKey, &inboxUniqueIndex); err != nil {
		return errorsForConsumerInboxSchemaReadback(err)
	}
	if !inboxShape || !inboxPrimaryKey || !inboxUniqueIndex || !projectionShape || !projectionConstraints || !projectionPrimaryKey {
		return fmt.Errorf("Consumer Inbox schema mismatch inbox=%t inbox_pk=%t unique_index=%t projection=%t constraints=%t projection_pk=%t", inboxShape, inboxPrimaryKey, inboxUniqueIndex, projectionShape, projectionConstraints, projectionPrimaryKey)
	}
	var inboxInsert, inboxNoRead, inboxNoOtherInsert bool
	var projectionSelect, projectionInsert, projectionUpdate, projectionNoOther, noOutbox bool
	privilegeQuery := `SELECT
		pg_catalog.has_column_privilege('paddock_app','raw.event_inbox','consumer_id','INSERT')
		AND pg_catalog.has_column_privilege('paddock_app','raw.event_inbox','event_id','INSERT')
		AND pg_catalog.has_column_privilege('paddock_app','raw.event_inbox','processed_at','INSERT'),
		NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','SELECT')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','UPDATE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','DELETE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','TRUNCATE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','REFERENCES')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_inbox','TRIGGER')
		AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_inbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
		 AND (pg_catalog.has_column_privilege('paddock_app','raw.event_inbox',a.attname,'SELECT')
		   OR pg_catalog.has_column_privilege('paddock_app','raw.event_inbox',a.attname,'UPDATE')
		   OR pg_catalog.has_column_privilege('paddock_app','raw.event_inbox',a.attname,'REFERENCES'))),
		NOT pg_catalog.has_column_privilege('paddock_app','raw.event_inbox','received_at','INSERT'),
		pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','consumer_id','SELECT')
		AND pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','processed_event_count','SELECT'),
		pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','consumer_id','INSERT')
		AND pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','processed_event_count','INSERT'),
		pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','processed_event_count','UPDATE'),
		NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','SELECT')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','INSERT')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','UPDATE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','DELETE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','TRUNCATE')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','REFERENCES')
		AND NOT pg_catalog.has_table_privilege('paddock_app','raw.event_consumer_projection','TRIGGER')
		AND NOT pg_catalog.has_column_privilege('paddock_app','raw.event_consumer_projection','consumer_id','UPDATE'),
		NOT (pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','SELECT') OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','INSERT')
		 OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','UPDATE') OR pg_catalog.has_table_privilege('paddock_app','raw.event_outbox','DELETE'))
		AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='raw.event_outbox'::regclass AND a.attnum>0 AND NOT a.attisdropped
		 AND (pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'SELECT')
		   OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'INSERT')
		   OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'UPDATE')
		   OR pg_catalog.has_column_privilege('paddock_app','raw.event_outbox',a.attname,'REFERENCES')))`
	if err := setupPool.QueryRow(ctx, privilegeQuery).Scan(&inboxInsert, &inboxNoRead, &inboxNoOtherInsert, &projectionSelect, &projectionInsert, &projectionUpdate, &projectionNoOther, &noOutbox); err != nil {
		return errorsForConsumerInboxSchemaReadback(err)
	}
	if !inboxInsert || !inboxNoRead || !inboxNoOtherInsert || !projectionSelect || !projectionInsert || !projectionUpdate || !projectionNoOther || !noOutbox {
		return fmt.Errorf("Consumer Inbox privilege mismatch inbox_insert=%t inbox_no_read=%t inbox_no_other_insert=%t projection_select=%t projection_insert=%t projection_update=%t projection_no_other=%t no_outbox=%t", inboxInsert, inboxNoRead, inboxNoOtherInsert, projectionSelect, projectionInsert, projectionUpdate, projectionNoOther, noOutbox)
	}
	return nil
}

func errorsForConsumerInboxSchemaReadback(err error) error {
	return fmt.Errorf("Consumer Inbox read-only schema/ACL preflight failed: %w", err)
}
