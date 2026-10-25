//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// These fixture helpers also extend M06/M07 sources. Their old live receipts
// do not attest the changed sources: rehash/review and separately authorize a
// current-hash M06 rollback-only + M07 shared body run before claiming revalidation.
// Compilation with -run '^$' never opens a pool or executes any fixture body.
type credentialIntegrationIssuerProvider struct {
	current domain.CredentialIssuerContext
	err     error
}

func (p *credentialIntegrationIssuerProvider) CurrentCredentialIssuer(context.Context, string) (domain.CredentialIssuerContext, error) {
	return p.current, p.err
}

// Fixture-only migrator seeding, not a deployment update API. Each test owns
// one random exact Issuer ID and deletes only that row, then reads back zero.
func seedCredentialIntegrationIssuer(t *testing.T, ctx context.Context, migrator *pgxpool.Pool) *credentialIntegrationIssuerProvider {
	t.Helper()
	var db, user, session string
	if err := migrator.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != "paddock_migrator" || session != "paddock_migrator" {
		t.Fatal("refusing unexpected issuer fixture database/session")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("issuer fixture identity generation")
	}
	p := &credentialIntegrationIssuerProvider{current: domain.CredentialIssuerContext{IssuerID: "credential_fixture_" + hex.EncodeToString(id[:]), Revision: 1, CeilingDigest: domain.Digest(strings.Repeat("c", 64))}}
	if tag, err := migrator.Exec(ctx, `INSERT INTO raw.worker_issuer_context(issuer_id,issuer_revision,ceiling_digest) VALUES($1,$2::numeric,$3)`, p.current.IssuerID, "1", string(p.current.CeilingDigest)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("issuer fixture seed")
	}
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := migrator.Exec(cleanCtx, `DELETE FROM raw.worker_issuer_context WHERE issuer_id=$1`, p.current.IssuerID); err != nil {
			t.Error("issuer fixture cleanup")
			return
		}
		var remaining int
		if err := migrator.QueryRow(cleanCtx, `SELECT count(*) FROM raw.worker_issuer_context WHERE issuer_id=$1`, p.current.IssuerID).Scan(&remaining); err != nil || remaining != 0 {
			t.Error("issuer cleanup readback")
		}
	})
	return p
}
func credentialIntegrationRequest() domain.CredentialRequest {
	r, err := domain.NewCanonicalRequest("credential-fixture-command", "credential-fixture-nonce", []byte(`{"operation":"credential-fixture"}`))
	if err != nil {
		panic(err)
	}
	return domain.CredentialRequest{CommandID: "credential-fixture-command", Nonce: "credential-fixture-nonce", RequestDigest: r.Digest()}
}
func credentialIntegrationAuthorization(t *testing.T, c domain.WorkerCredential, key ed25519.PrivateKey, scope domain.ScopeID, grant domain.Grant) domain.HighRiskAuthorization {
	t.Helper()
	message, err := c.SigningBytes(scope, grant, credentialIntegrationRequest())
	if err != nil {
		t.Fatal("cannot encode credential fixture proof")
	}
	return domain.HighRiskAuthorization{Grant: grant, Lease: c.Lease, Credential: domain.WorkerCredentialBinding{ID: c.ID, Signature: ed25519.Sign(key, message)}}
}

// db may be an already-open rollback-only app transaction; cleanup=nil then
// leaves all credential/enrollment effects inside that transaction's rollback.
func credentialIntegrationEnrollment(t *testing.T, ctx context.Context, db workerEnrollmentDB, cleanup *pgxpool.Pool) (domain.QuarantinedWorker, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("credential fixture key generation")
	}
	fp, err := domain.FingerprintWorkerKey(public)
	if err != nil {
		t.Fatal("credential fixture fingerprint")
	}
	store := NewWorkerEnrollmentStore(db)
	service := application.NewWorkerEnrollmentService(store, canonical.NewJCSCodec())
	challenge, err := service.IssueChallenge(ctx, fp)
	if err != nil {
		t.Fatal("credential fixture enrollment challenge")
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("credential fixture identity generation")
	}
	workerID := domain.WorkerID("worker_" + hex.EncodeToString(id[:]))
	if cleanup != nil {
		t.Cleanup(func() {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			tx, err := cleanup.Begin(cleanCtx)
			if err != nil {
				t.Error("credential cleanup begin")
				return
			}
			defer tx.Rollback(cleanCtx)
			for _, q := range []struct {
				sql string
				arg string
			}{{`DELETE FROM raw.worker_credentials WHERE worker_id=$1`, string(workerID)}, {`DELETE FROM raw.worker_enrollment_challenges WHERE challenge_id=$1`, challenge.ID}, {`DELETE FROM raw.worker_enrollment_workers WHERE worker_id=$1`, string(workerID)}} {
				if _, err := tx.Exec(cleanCtx, q.sql, q.arg); err != nil {
					t.Error("credential fixture cleanup")
					return
				}
			}
			if err := tx.Commit(cleanCtx); err != nil {
				t.Error("credential cleanup commit unknown")
				return
			}
			var remaining int
			if err := cleanup.QueryRow(cleanCtx, `SELECT (SELECT count(*) FROM raw.worker_credentials WHERE worker_id=$1)+(SELECT count(*) FROM raw.worker_enrollment_workers WHERE worker_id=$1)+(SELECT count(*) FROM raw.worker_enrollment_challenges WHERE challenge_id=$2)`, string(workerID), challenge.ID).Scan(&remaining); err != nil || remaining != 0 {
				t.Error("credential fixture cleanup readback")
			}
		})
	}
	message, err := challenge.SigningBytes(canonical.NewJCSCodec())
	if err != nil {
		t.Fatal("enrollment fixture encoding")
	}
	verified, err := domain.VerifyWorkerEnrollment(canonical.NewJCSCodec(), challenge, public, ed25519.Sign(key, message))
	if err != nil {
		t.Fatal("enrollment fixture verification")
	}
	worker, err := store.ConsumeEnrollment(ctx, verified, workerID)
	if err != nil {
		t.Fatal("credential fixture enrollment")
	}
	return worker, key
}
func issueCredentialIntegration(t *testing.T, ctx context.Context, db workerCredentialDB, worker domain.QuarantinedWorker, lease domain.AttemptLeaseBinding, issuer *credentialIntegrationIssuerProvider) domain.WorkerCredential {
	t.Helper()
	service := application.NewWorkerCredentialService(NewWorkerCredentialStore(db), issuer, "paddock.coordinator", issuer.current.IssuerID)
	c, err := service.Issue(ctx, worker.Fingerprint, lease)
	if err != nil {
		t.Fatal("credential fixture issue")
	}
	return c
}

// Opt-in source only. No migrations are applied. Requires independently
// approved enrollment/credential/Lease/Safety API migrations in paddock_test.
func TestWorkerCredentialGateIntegration(t *testing.T) {
	if os.Getenv("PADDOCK_WORKER_CREDENTIAL_INTEGRATION") != "1" {
		t.Skip("explicit credential integration opt-in required")
	}
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("both fixture and app DB configuration required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	setup, err := pgxpool.New(ctx, setupURL)
	if err != nil {
		t.Fatal("cannot configure fixture pool")
	}
	t.Cleanup(setup.Close)
	app, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal("cannot configure app pool")
	}
	t.Cleanup(app.Close)
	for _, entry := range []struct {
		pool *pgxpool.Pool
		role string
	}{{setup, "paddock_migrator"}, {app, "paddock_app"}} {
		var db, user, session string
		if err := entry.pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != entry.role || session != entry.role {
			t.Fatal("refusing unexpected credential test database/session")
		}
	}
	// Check owner/path and execute-only app access, not just successful calls.
	for _, signature := range []string{"raw.issue_worker_credential(text,text,text,text,text,text,bigint,text,text,text,text)", "raw.lock_worker_credential(text)", "raw.lock_current_worker_issuer_context(text)", "raw.revoke_worker_credential(text)"} {
		var valid bool
		if err := setup.QueryRow(ctx, `SELECT p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']::text[] AND r.rolname='paddock_migrator' AND pg_catalog.has_function_privilege('paddock_app',p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee NOT IN(p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app'))) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE p.oid=pg_catalog.to_regprocedure($1)`, signature).Scan(&valid); err != nil || !valid {
			t.Fatal("credential API ACL/owner/path")
		}
	}
	for _, table := range []string{"raw.worker_credentials", "raw.worker_issuer_context"} {
		var direct bool
		if err := setup.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege('paddock_app',$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR pg_catalog.has_any_column_privilege('paddock_app',$1,'SELECT,INSERT,UPDATE,REFERENCES')`, table).Scan(&direct); err != nil || direct {
			t.Fatal("direct credential/issuer table privileges forbidden")
		}
	}
	issuer := seedCredentialIntegrationIssuer(t, ctx, setup)
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("fixture generation")
	}
	prefix := "credential_" + hex.EncodeToString(entropy[:])
	f := fixture{bundle: strings.Repeat("d", 64), scope: prefix + "_scope", root: prefix + "_root", otherRoot: prefix + "_other", otherScope: prefix + "_other_scope", otherScopeRoot: prefix + "_other_scope_root", rollout: prefix + "_rollout"}
	// A random canonical bundle digest avoids collisions with every prior run.
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(`{"fixture":"`+prefix+`"}`))
	if err != nil {
		t.Fatal("fixture bundle")
	}
	f.bundle = string(bundle.Digest())
	cleanupFixtures(t, ctx, setup, f)
	if err := seedFixtures(ctx, setup, f); err != nil {
		t.Fatal("credential authority fixture seed")
	}
	work := prefix + "_work"
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, q := range []string{`DELETE FROM raw.work_order_leases WHERE work_order_id=$1`, `DELETE FROM raw.work_order_pull_slots WHERE work_order_id=$1`, `DELETE FROM raw.work_order_attempts WHERE work_order_id=$1`, `DELETE FROM raw.work_orders WHERE work_order_id=$1`} {
			if _, err := setup.Exec(cleanCtx, q, work); err != nil {
				t.Error("credential work cleanup")
				return
			}
		}
		var count int
		if err := setup.QueryRow(cleanCtx, `SELECT (SELECT count(*) FROM raw.work_orders WHERE work_order_id=$1)+(SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=$1)+(SELECT count(*) FROM raw.work_order_leases WHERE work_order_id=$1)+(SELECT count(*) FROM raw.work_order_pull_slots WHERE work_order_id=$1)`, work).Scan(&count); err != nil || count != 0 {
			t.Error("credential work cleanup readback")
		}
	})
	if _, err := setup.Exec(ctx, `INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$2,NULL)`, work, f.root); err != nil {
		t.Fatal("credential work seed")
	}
	worker, key := credentialIntegrationEnrollment(t, ctx, app, setup)
	lease := domain.AttemptLeaseBinding{WorkOrderID: domain.WorkOrderID(work), AttemptID: domain.AttemptID(work + "_attempt"), WorkerID: worker.ID, SessionID: domain.SessionID(work + "_session")}
	for _, q := range []string{`SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, `SELECT raw.mark_work_order_pull_ready($1)`} {
		var ok bool
		if err := app.QueryRow(ctx, q, work).Scan(&ok); err != nil || !ok {
			t.Fatal("credential lease ready")
		}
	}
	var attempt, slot string
	var expires time.Time
	if err := app.QueryRow(ctx, `SELECT attempt_id,slot_id,lease_epoch,expires_at FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,interval '10 minutes')`, work, string(worker.ID), string(lease.SessionID), string(lease.AttemptID), work+"_slot").Scan(&attempt, &slot, &lease.LeaseEpoch, &expires); err != nil {
		t.Fatal("credential lease issue")
	}
	c := issueCredentialIntegration(t, ctx, app, worker, lease, issuer)
	transactor, err := NewSafetyGateTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	gate := application.NewSafetyGate(transactor, "paddock.coordinator")
	var snapshot port.ScopeSnapshot
	if err := transactor.WithinSafetyGateTransaction(ctx, func(tx port.SafetyGateTx) error {
		var e error
		snapshot, e = tx.LockScope(ctx, domain.ScopeID(f.scope))
		return e
	}); err != nil {
		t.Fatal("credential authority read")
	}
	current := snapshot.Roots[domain.RootID(f.root)]
	grant := domain.Grant{Root: domain.RootID(f.root), Policy: current.Policy, AuthorizationEpoch: current.AuthorizationEpoch, SecurityEpoch: snapshot.SecurityEpoch}
	command := prefix + "_receipt"
	canonicalRequest, err := domain.NewCanonicalRequest(command, "credential-fixture-nonce", []byte(`{"operation":"credential-fixture"}`))
	if err != nil {
		t.Fatal("command fixture encoding")
	}
	request := domain.CredentialRequest{CommandID: command, Nonce: "credential-fixture-nonce", RequestDigest: canonicalRequest.Digest()}
	authorization := func() domain.HighRiskAuthorization {
		message, err := c.SigningBytes(domain.ScopeID(f.scope), grant, request)
		if err != nil {
			t.Fatal("command proof encoding")
		}
		return domain.HighRiskAuthorization{Grant: grant, Lease: c.Lease, Credential: domain.WorkerCredentialBinding{ID: c.ID, Signature: ed25519.Sign(key, message)}}
	}
	check := func(a domain.HighRiskAuthorization) error {
		return gate.CheckHighRiskAction(ctx, domain.ScopeID(f.scope), a, request)
	}
	if err := check(authorization()); err != nil {
		t.Fatal("valid credential denied")
	}
	bad := authorization()
	bad.Credential.Signature[0] ^= 1
	if err := check(bad); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("bad signature accepted")
	}
	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("wrong fixture key")
	}
	message, err := c.SigningBytes(domain.ScopeID(f.scope), grant, request)
	if err != nil {
		t.Fatal(err)
	}
	bad = authorization()
	bad.Credential.Signature = ed25519.Sign(wrong, message)
	if err := check(bad); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("wrong key accepted")
	}
	// Simulate guarded deployment replacement using ONLY the migrator pool,
	// deleting/seeding this test's exact ID. No application update API exists.
	replaceIssuer := func(current *domain.CredentialIssuerContext) {
		t.Helper()
		tx, err := setup.Begin(ctx)
		if err != nil {
			t.Fatal("issuer replacement begin")
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `DELETE FROM raw.worker_issuer_context WHERE issuer_id=$1`, c.Issuer.IssuerID); err != nil {
			t.Fatal("issuer replacement delete")
		}
		if current != nil {
			if current.IssuerID != c.Issuer.IssuerID {
				t.Fatal("issuer fixture identity mismatch")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO raw.worker_issuer_context(issuer_id,issuer_revision,ceiling_digest) VALUES($1,$2::numeric,$3)`, current.IssuerID, strconv.FormatUint(current.Revision, 10), string(current.CeilingDigest)); err != nil {
				t.Fatal("issuer replacement seed")
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("issuer replacement commit")
		}
	}
	changedIssuer := c.Issuer
	changedIssuer.Revision++
	replaceIssuer(&changedIssuer)
	if err := check(authorization()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("stale issuer revision accepted")
	}
	service := application.NewWorkerCredentialService(NewWorkerCredentialStore(app), issuer, "paddock.coordinator", issuer.current.IssuerID)
	if _, err := service.Issue(ctx, worker.Fingerprint, lease); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("stale issuance context accepted")
	}
	changedIssuer = c.Issuer
	changedIssuer.CeilingDigest = domain.Digest(strings.Repeat("e", 64))
	replaceIssuer(&changedIssuer)
	if err := check(authorization()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("stale issuer ceiling accepted")
	}
	if _, err := service.Issue(ctx, worker.Fingerprint, lease); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("stale issuance digest accepted")
	}
	replaceIssuer(nil)
	if err := check(authorization()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("unavailable issuer accepted")
	}
	if _, err := service.Issue(ctx, worker.Fingerprint, lease); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("missing issuance issuer accepted")
	}
	replaceIssuer(&c.Issuer)
	stale := c
	stale.Lease.LeaseEpoch++
	// Use fresh Coordinator randomness for the stale-credential fixture too.
	stale = issueCredentialIntegration(t, ctx, app, worker, stale.Lease, issuer)
	staleMessage, err := stale.SigningBytes(domain.ScopeID(f.scope), grant, request)
	if err != nil {
		t.Fatal("stale credential encoding")
	}
	bad = domain.HighRiskAuthorization{Grant: grant, Lease: lease, Credential: domain.WorkerCredentialBinding{ID: stale.ID, Signature: ed25519.Sign(key, staleMessage)}}
	if err := check(bad); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("stale credential epoch accepted")
	}
	// Identical authenticated command retry is allowed by the Gate; durable
	// mutation replay/conflict is handled by the existing command Receipt API.

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := setup.Exec(cleanCtx, `DELETE FROM raw.command_receipts WHERE command_id=$1`, command); err != nil {
			t.Error("credential receipt cleanup")
		}
		var count int
		if err := setup.QueryRow(cleanCtx, `SELECT count(*) FROM raw.command_receipts WHERE command_id=$1`, command).Scan(&count); err != nil || count != 0 {
			t.Error("credential receipt cleanup readback")
		}
	})
	if err := check(authorization()); err != nil {
		t.Fatal("authenticated retry denied")
	}
	receipts, err := NewSafetyTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: command, RequestDigest: request.RequestDigest, Status: "SUCCEEDED", Response: []byte(`{"done":true}`)})
	}); err != nil {
		t.Fatal("credential command receipt insert")
	}
	if err := receipts.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		got, found, err := tx.LookupCommandReceipt(ctx, command)
		if err != nil {
			return err
		}
		if !found || got.RequestDigest != request.RequestDigest || string(got.Response) != `{"done":true}` {
			return errors.New("receipt replay mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal("credential command receipt replay")
	}
	// Reusing the committed command identity cannot replace its outcome, even
	// with a different digest. No credential-specific replay storage is involved.
	if err := receipts.WithinTransaction(ctx, func(tx port.GovernanceTx) error {
		return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: command, RequestDigest: domain.Digest(strings.Repeat("a", 64)), Status: "SUCCEEDED", Response: []byte(`{"changed":true}`)})
	}); err == nil {
		t.Fatal("replayed command replaced receipt")
	}
	var receiptCount int
	if err := setup.QueryRow(ctx, `SELECT count(*) FROM raw.command_receipts WHERE command_id=$1 AND request_digest=$2 AND response_bytes=$3`, command, string(request.RequestDigest), []byte(`{"done":true}`)).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatal("replayed command changed stored outcome")
	}

	if err := NewWorkerCredentialStore(app).RevokeWorkerCredential(ctx, c.ID); err != nil {
		t.Fatal("credential revoke")
	}
	if err := check(authorization()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("revoked credential accepted")
	}
	// Stale live Lease still wins over proof, including for an unrevoked row.
	c = issueCredentialIntegration(t, ctx, app, worker, lease, issuer)
	if _, err := setup.Exec(ctx, `UPDATE raw.work_order_leases SET expires_at=heartbeat_at+interval '1 microsecond' WHERE work_order_id=$1`, work); err != nil {
		t.Fatal("expire fixture lease")
	}
	if err := check(authorization()); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatal("expired lease accepted")
	}
}
