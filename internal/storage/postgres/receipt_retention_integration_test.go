//go:build integration && paddock_test && receipt_retention

package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SOURCE ONLY for M04-S05. Running requires separate exact approval for this
// body against a quiescent isolated paddock_test with the updated Safety API
// already installed. This test installs nothing. It retains its fixture IDs and
// intentionally exercises the global bounded sweep of existing due receipts.
// Offline compile checks must select no test bodies (-run '^$').
func TestReceiptRetentionAppOnlyIntegration(t *testing.T) {
	if os.Getenv("PADDOCK_RECEIPT_RETENTION_INTEGRATION") != "1" {
		t.Skip("receipt retention integration requires explicit opt-in and separate approval")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	migratorURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if migratorURL == "" || appURL == "" {
		t.Fatal("isolated migrator and app connection configuration required")
	}
	migrator, err := openPullPool(ctx, migratorURL, false)
	if err != nil {
		t.Fatal("cannot open fixture pool")
	}
	t.Cleanup(migrator.Close)
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("cannot open app pool")
	}
	t.Cleanup(app.Close)
	for _, entry := range []struct {
		pool *pgxpool.Pool
		role string
	}{{migrator, "paddock_migrator"}, {app, "paddock_app"}} {
		var db, user, session string
		if err := entry.pool.QueryRow(ctx, `SELECT current_database(), current_user, session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != entry.role || session != entry.role {
			t.Fatal("refusing unexpected database/session identity")
		}
	}
	var badACL bool
	if err := migrator.QueryRow(ctx, `SELECT
 pg_catalog.has_table_privilege('paddock_app','raw.command_receipts','SELECT,INSERT,UPDATE,DELETE')
 OR pg_catalog.has_any_column_privilege('paddock_app','raw.command_receipts','SELECT,INSERT,UPDATE')`).Scan(&badACL); err != nil || badACL {
		t.Fatal("receipt API requires no direct app table or column privileges")
	}

	prefix := fmt.Sprintf("m04_s05_it_%d_", time.Now().UnixNano()) // identifier only, never a deadline
	var prefixCollisions int
	if err := migrator.QueryRow(ctx, `SELECT count(*) FROM raw.command_receipts WHERE left(command_id,char_length($1))=$1`, prefix).Scan(&prefixCollisions); err != nil || prefixCollisions != 0 {
		t.Fatal("receipt retention fixture prefix collision preflight failed")
	}
	// This cleanup is test-fixture-only: it removes only the unique run prefix
	// after all retention assertions, without changing production retention.
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := migrator.Exec(cleanupCtx, `DELETE FROM raw.command_receipts WHERE left(command_id,char_length($1))=$1`, prefix); err != nil {
			t.Error("receipt retention fixture cleanup failed")
			return
		}
		var remaining int
		if err := migrator.QueryRow(cleanupCtx, `SELECT count(*) FROM raw.command_receipts WHERE left(command_id,char_length($1))=$1`, prefix).Scan(&remaining); err != nil || remaining != 0 {
			t.Errorf("receipt retention fixture cleanup readback: remaining=%d err=%v", remaining, err)
		}
	})
	digest := domain.Digest(strings.Repeat("a", 64))
	full := []byte(`{"schema_version":"paddock.command-response/1","kind":"SUCCEEDED","code":"SUCCEEDED","detail":"The command completed successfully.","result":{}}`)
	negative := []byte(`{"schema_version":"paddock.command-response/1","kind":"FORBIDDEN","code":"FORBIDDEN","detail":"The command is not authorized for the requested transition."}`)
	safety, err := NewSafetyTransactor(app)
	if err != nil {
		t.Fatal("cannot construct Safety transactor")
	}
	insert := func(id, status string, body []byte) {
		t.Helper()
		if err := safety.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
			return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: id, RequestDigest: digest, Status: status, Response: body})
		}); err != nil {
			t.Fatal("cannot insert terminal receipt through app API")
		}
	}
	lookup := func(id string) port.CommandReceipt {
		t.Helper()
		var receipt port.CommandReceipt
		err := safety.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
			var found bool
			var err error
			receipt, found, err = tx.LookupCommandReceipt(ctx, id)
			if err == nil && !found {
				return fmt.Errorf("fixture receipt missing")
			}
			return err
		})
		if err != nil {
			t.Fatal("cannot look up receipt through app API")
		}
		return receipt
	}

	// A terminal response is retained strictly before the DB-clock deadline.
	beforeID := prefix + "before"
	insert(beforeID, "SUCCEEDED", full)
	if _, err := migrator.Exec(ctx, `UPDATE raw.command_receipts SET completed_at=clock_timestamp()-interval '365 days'+interval '1 minute' WHERE command_id=$1`, beforeID); err != nil {
		t.Fatal("cannot set pre-deadline fixture")
	}
	before := lookup(beforeID)
	if before.Expired || string(before.Response) != string(full) {
		t.Fatal("response expired before deadline")
	}
	// Exercise PostgreSQL's exact half-open boundary independently of scheduling.
	var justBefore, equal, justAfter bool
	if err := migrator.QueryRow(ctx, `SELECT
 (completed_at+interval '365 days'-interval '1 microsecond') >= completed_at+interval '365 days',
 (completed_at+interval '365 days') >= completed_at+interval '365 days',
 (completed_at+interval '365 days'+interval '1 microsecond') >= completed_at+interval '365 days'
 FROM raw.command_receipts WHERE command_id=$1`, beforeID).Scan(&justBefore, &equal, &justAfter); err != nil || justBefore || !equal || !justAfter {
		t.Fatal("PostgreSQL deadline boundary is not half-open")
	}

	// A transaction that began before expiry must use wall clock, not now().
	longTx, err := app.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal("cannot begin wall-clock test")
	}
	defer func() { _ = longTx.Rollback(ctx) }()
	var transactionStart time.Time
	if err := longTx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&transactionStart); err != nil {
		t.Fatal("cannot read transaction anchor")
	}
	if _, err := migrator.Exec(ctx, `UPDATE raw.command_receipts SET completed_at=$2::timestamptz-interval '365 days'+interval '100 milliseconds' WHERE command_id=$1`, beforeID, transactionStart); err != nil {
		t.Fatal("cannot set wall-clock fixture")
	}
	if _, err := longTx.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal("cannot cross wall-clock deadline")
	}
	wallReceipt, found, err := newSafetyGovernanceTx(longTx).LookupCommandReceipt(ctx, beforeID)
	if err != nil || !found || !wallReceipt.Expired || wallReceipt.Status != "SUCCEEDED" || wallReceipt.RequestDigest != digest || string(wallReceipt.Response) != port.ReceiptTombstoneResponse {
		t.Fatal("long transaction returned an expired full response")
	}
	if err := longTx.Commit(ctx); err != nil {
		t.Fatal("cannot commit wall-clock maintenance")
	}

	// Exact deadline is inclusive; keep original rejection and digest forever.
	negativeID := prefix + "negative"
	insert(negativeID, "REJECTED", negative)
	if _, err := migrator.Exec(ctx, `UPDATE raw.command_receipts SET completed_at=clock_timestamp()-interval '365 days' WHERE command_id=$1`, negativeID); err != nil {
		t.Fatal("cannot set exact-deadline fixture")
	}
	r := lookup(negativeID)
	if !r.Expired || r.Status != "REJECTED" || r.RequestDigest != digest || string(r.Response) != port.ReceiptTombstoneResponse {
		t.Fatal("expired rejection lost terminal identity")
	}
	for _, candidateDigest := range []domain.Digest{digest, domain.Digest(strings.Repeat("b", 64))} {
		if err := safety.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
			return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: negativeID, RequestDigest: candidateDigest, Status: "SUCCEEDED", Response: full})
		}); err == nil {
			t.Fatal("expired command ID was reusable")
		}
	}
	if again := lookup(negativeID); !again.Expired || again.Status != r.Status || again.RequestDigest != r.RequestDigest || string(again.Response) != string(r.Response) {
		t.Fatal("permanent tombstone was overwritten")
	}

	// Backlog: requested ID is newer than 1,002 other due fixtures, so a plain
	// LIMIT 1000 sweep would miss it. A lookup must process it plus 999 oldest.
	requestedID := prefix + "requested"
	insert(requestedID, "SUCCEEDED", full)
	if _, err := migrator.Exec(ctx, `UPDATE raw.command_receipts SET completed_at=clock_timestamp()-interval '400 days' WHERE command_id=$1`, requestedID); err != nil {
		t.Fatal("cannot set requested expiry fixture")
	}
	if _, err := migrator.Exec(ctx, `INSERT INTO raw.command_receipts(command_id,request_digest,status,response_bytes,completed_at)
 SELECT $1||g::text,$2,'REJECTED',$3,clock_timestamp()-interval '800 days'+g*interval '1 microsecond'
 FROM generate_series(1,1002) g`, prefix+"old_", string(digest), negative); err != nil {
		t.Fatal("cannot insert retention backlog fixtures")
	}
	var expected []string
	if err := migrator.QueryRow(ctx, `SELECT ARRAY(SELECT command_id FROM raw.command_receipts
 WHERE command_id<>$1 AND status IN ('SUCCEEDED','REJECTED') AND clock_timestamp()>=completed_at+interval '365 days'
 AND response_bytes<>$2 ORDER BY completed_at,command_id LIMIT 999)`, requestedID, []byte(port.ReceiptTombstoneResponse)).Scan(&expected); err != nil || len(expected) != 999 {
		t.Fatal("cannot snapshot oldest due receipts")
	}
	countTombstones := func() int {
		t.Helper()
		var count int
		if err := migrator.QueryRow(ctx, `SELECT count(*) FROM raw.command_receipts WHERE response_bytes=$1`, []byte(port.ReceiptTombstoneResponse)).Scan(&count); err != nil {
			t.Fatal("cannot count tombstones")
		}
		return count
	}
	countBefore := countTombstones()
	if r := lookup(requestedID); !r.Expired {
		t.Fatal("requested expiry was hidden behind backlog")
	}
	if delta := countTombstones() - countBefore; delta != 1000 {
		t.Fatalf("lookup changed %d bodies, expected requested+999", delta)
	}
	var oldestExpired int
	if err := migrator.QueryRow(ctx, `SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[]) AND response_bytes=$2`, expected, []byte(port.ReceiptTombstoneResponse)).Scan(&oldestExpired); err != nil || oldestExpired != 999 {
		t.Fatal("sweep did not select oldest due terminal receipts")
	}
}
