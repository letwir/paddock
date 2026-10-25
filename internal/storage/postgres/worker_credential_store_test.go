package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/letwir/paddock/internal/governance/domain"
)

func storageCredentialFixture(t *testing.T) (domain.WorkerCredential, []byte) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32)).Public().(ed25519.PublicKey)
	fp, err := domain.FingerprintWorkerKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return domain.WorkerCredential{ID: strings.Repeat("1", 64), Fingerprint: fp, Lease: domain.AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: domain.WorkerID("worker_" + strings.Repeat("2", 64)), SessionID: "session", LeaseEpoch: 1}, Audience: "coordinator", Issuer: domain.CredentialIssuerContext{IssuerID: "issuer", Revision: 1, CeilingDigest: domain.Digest(strings.Repeat("a", 64))}}, key
}
func credentialScanValues(c domain.WorkerCredential, key []byte) []any {
	return []any{c.ID, string(c.Fingerprint), string(c.Lease.WorkOrderID), string(c.Lease.AttemptID), string(c.Lease.WorkerID), string(c.Lease.SessionID), int64(c.Lease.LeaseEpoch), c.Audience, c.Issuer.IssuerID, "1", string(c.Issuer.CeilingDigest), c.Revoked, key}
}

func TestWorkerCredentialStoreOnlyParameterizedCapabilities(t *testing.T) {
	c, key := storageCredentialFixture(t)
	db := &enrollmentDBStub{row: enrollmentScan{values: []any{true}}}
	store := NewWorkerCredentialStore(db)
	ctx := context.Background()
	if err := store.IssueWorkerCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	want := []any{c.ID, string(c.Fingerprint), string(c.Lease.WorkOrderID), string(c.Lease.AttemptID), string(c.Lease.WorkerID), string(c.Lease.SessionID), int64(1), c.Audience, c.Issuer.IssuerID, "1", string(c.Issuer.CeilingDigest)}
	if db.query != `SELECT raw.issue_worker_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)` || !reflect.DeepEqual(db.args, want) {
		t.Fatal("unsafe issue capability")
	}
	if err := store.RevokeWorkerCredential(ctx, c.ID); err != nil || db.query != `SELECT raw.revoke_worker_credential($1)` || !reflect.DeepEqual(db.args, []any{c.ID}) {
		t.Fatal("unsafe revoke capability")
	}
	db.row = enrollmentScan{values: credentialScanValues(c, key)}
	got, pub, err := lockWorkerCredential(ctx, db, c.ID)
	if err != nil || got != c || !bytes.Equal(pub, key) || !strings.HasSuffix(db.query, `FROM raw.lock_worker_credential($1)`) || !reflect.DeepEqual(db.args, []any{c.ID}) {
		t.Fatalf("unsafe lock capability: %v", err)
	}
	pub[0] ^= 1
	if bytes.Equal(pub, key) {
		t.Fatal("public key aliases driver bytes")
	}
}

func TestWorkerCredentialStoreFailsClosedOnMalformedRows(t *testing.T) {
	c, key := storageCredentialFixture(t)
	for _, entry := range []struct {
		index int
		value any
	}{{0, strings.Repeat("9", 64)}, {1, strings.Repeat("f", 64)}, {2, ""}, {3, ""}, {4, "other"}, {5, ""}, {6, int64(0)}, {7, ""}, {8, ""}, {9, "0"}, {9, "18446744073709551616"}, {9, "bad"}, {10, "bad"}, {12, []byte{1}}} {
		values := credentialScanValues(c, key)
		values[entry.index] = entry.value
		db := &enrollmentDBStub{row: enrollmentScan{values: values}}
		if _, _, err := lockWorkerCredential(context.Background(), db, c.ID); !errors.Is(err, domain.ErrWorkerCredential) {
			t.Fatal("malformed row accepted")
		}
	}
	// Revoked rows are returned faithfully; Domain/Gate deny their use.
	c.Revoked = true
	db := &enrollmentDBStub{row: enrollmentScan{values: credentialScanValues(c, key)}}
	got, _, err := lockWorkerCredential(context.Background(), db, c.ID)
	if err != nil || !got.Revoked {
		t.Fatal("revocation status lost")
	}
}

func TestWorkerCredentialStoreNoInvalidIOAndPropagatesFailure(t *testing.T) {
	c, _ := storageCredentialFixture(t)
	ctx := context.Background()
	cause := errors.New("offline")
	for _, failure := range []error{cause, pgx.ErrNoRows} {
		db := &enrollmentDBStub{row: enrollmentScan{err: failure}}
		store := NewWorkerCredentialStore(db)
		if err := store.IssueWorkerCredential(ctx, c); !errors.Is(err, failure) || !errors.Is(err, domain.ErrWorkerCredential) {
			t.Fatal(err)
		}
		if err := store.RevokeWorkerCredential(ctx, c.ID); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if _, _, err := lockWorkerCredential(ctx, db, c.ID); !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	db := &enrollmentDBStub{row: enrollmentScan{values: []any{false}}}
	store := NewWorkerCredentialStore(db)
	if err := store.IssueWorkerCredential(ctx, c); err == nil {
		t.Fatal("false issue accepted")
	}
	if err := store.RevokeWorkerCredential(ctx, c.ID); err == nil {
		t.Fatal("false revoke accepted")
	}
	db.calls = 0
	c.Revoked = true
	if err := store.IssueWorkerCredential(ctx, c); err == nil {
		t.Fatal("revoked issuance")
	}
	if err := store.RevokeWorkerCredential(ctx, "bad"); err == nil {
		t.Fatal("invalid revoke")
	}
	if _, _, err := lockWorkerCredential(ctx, db, "bad"); err == nil {
		t.Fatal("invalid lock")
	}
	if db.calls != 0 {
		t.Fatal("invalid input reached DB")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.RevokeWorkerCredential(canceled, c.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var nilStore *WorkerCredentialStore
	if err := nilStore.RevokeWorkerCredential(ctx, c.ID); err == nil {
		t.Fatal("nil store")
	}
}

func TestCurrentCredentialIssuerLockFailsClosed(t *testing.T) {
	c, _ := storageCredentialFixture(t)
	ctx := context.Background()
	for _, values := range [][]any{
		{"other", "1", string(c.Issuer.CeilingDigest)},
		{c.Issuer.IssuerID, "0", string(c.Issuer.CeilingDigest)},
		{c.Issuer.IssuerID, "-1", string(c.Issuer.CeilingDigest)},
		{c.Issuer.IssuerID, "18446744073709551616", string(c.Issuer.CeilingDigest)},
		{c.Issuer.IssuerID, "bad", string(c.Issuer.CeilingDigest)},
		{c.Issuer.IssuerID, "1", "bad"},
	} {
		db := &enrollmentDBStub{row: enrollmentScan{values: values}}
		if _, err := lockCurrentCredentialIssuer(ctx, db, c.Issuer.IssuerID); !errors.Is(err, domain.ErrWorkerCredential) {
			t.Fatal("invalid current issuer accepted")
		}
	}
	for _, cause := range []error{pgx.ErrNoRows, domain.ErrDatabaseUnavailable, errors.New("lock failed")} {
		db := &enrollmentDBStub{row: enrollmentScan{err: cause}}
		if _, err := lockCurrentCredentialIssuer(ctx, db, c.Issuer.IssuerID); !errors.Is(err, cause) || !errors.Is(err, domain.ErrWorkerCredential) {
			t.Fatal("current issuer failure lost")
		}
	}
	db := &enrollmentDBStub{row: enrollmentScan{values: []any{c.Issuer.IssuerID, "18446744073709551615", string(c.Issuer.CeilingDigest)}}}
	issuer, err := lockCurrentCredentialIssuer(ctx, db, c.Issuer.IssuerID)
	if err != nil || issuer.Revision != ^uint64(0) {
		t.Fatal("valid uint64 issuer revision lost")
	}
	db.calls = 0
	for _, id := range []string{"", " bad", "bad\x00", string([]byte{0xff})} {
		if _, err := lockCurrentCredentialIssuer(ctx, db, id); err == nil {
			t.Fatal("invalid issuer ID accepted")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := lockCurrentCredentialIssuer(canceled, db, c.Issuer.IssuerID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, err := lockCurrentCredentialIssuer(nil, db, c.Issuer.IssuerID); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := lockCurrentCredentialIssuer(ctx, nil, c.Issuer.IssuerID); err == nil || db.calls != 0 {
		t.Fatal("invalid input reached DB")
	}
}
