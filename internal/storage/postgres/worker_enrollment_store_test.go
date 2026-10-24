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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/domain"
)

type enrollmentScan struct {
	values []any
	err    error
}

func (r enrollmentScan) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan shape mismatch")
	}
	for i, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.values[i]))
	}
	return nil
}

type enrollmentDBStub struct {
	row   pgx.Row
	calls int
	query string
	args  []any
}

func (s *enrollmentDBStub) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	s.calls++
	s.query = q
	s.args = args
	return s.row
}
func enrollmentStoreFixture(t *testing.T) (domain.EnrollmentChallenge, domain.VerifiedWorkerEnrollment, domain.WorkerID) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	pub := key.Public().(ed25519.PublicKey)
	fp, err := domain.FingerprintWorkerKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c := domain.EnrollmentChallenge{ID: strings.Repeat("1", 64), Nonce: strings.Repeat("2", 64), Fingerprint: fp, Schema: domain.WorkerEnrollmentSchema, Audience: domain.WorkerEnrollmentAudience}
	message, err := c.SigningBytes(canonical.NewJCSCodec())
	if err != nil {
		t.Fatal(err)
	}
	v, err := domain.VerifyWorkerEnrollment(canonical.NewJCSCodec(), c, pub, ed25519.Sign(key, message))
	if err != nil {
		t.Fatal(err)
	}
	return c, v, domain.WorkerID("worker_" + strings.Repeat("3", 64))
}
func TestWorkerEnrollmentStoreUsesOnlyBoundCapabilities(t *testing.T) {
	c, v, id := enrollmentStoreFixture(t)
	ctx := context.Background()
	db := &enrollmentDBStub{row: enrollmentScan{values: []any{true}}}
	store := NewWorkerEnrollmentStore(db)
	if err := store.CreateEnrollmentChallenge(ctx, c); err != nil {
		t.Fatal(err)
	}
	if db.calls != 1 || db.query != `SELECT raw.issue_worker_enrollment_challenge($1,$2,$3,$4,$5)` || !reflect.DeepEqual(db.args, []any{c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience}) {
		t.Fatal("challenge not parameterized")
	}
	db.row = enrollmentScan{values: []any{c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience}}
	got, err := store.ReadEnrollmentChallenge(ctx, c.ID)
	if err != nil || got != c {
		t.Fatalf("read: %v", err)
	}
	if db.query != `SELECT challenge_id,nonce,fingerprint,schema_version,audience FROM raw.read_worker_enrollment_challenge($1)` || !reflect.DeepEqual(db.args, []any{c.ID}) {
		t.Fatal("read capability mismatch")
	}
	db.row = enrollmentScan{values: []any{string(id), string(c.Fingerprint), domain.WorkerQuarantineTier, domain.WorkerQuarantined}}
	w, err := store.ConsumeEnrollment(ctx, v, id)
	if err != nil || w.Validate() != nil {
		t.Fatalf("consume: %v", err)
	}
	key := v.PublicKey()
	if db.calls != 3 || db.query != `SELECT worker_id,fingerprint,quarantine_tier,state FROM raw.consume_worker_enrollment($1,$2,$3,$4,$5,$6,$7)` || !reflect.DeepEqual(db.args, []any{c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience, key[:], string(id)}) {
		t.Fatal("consume must be one bound capability call")
	}
}
func TestWorkerEnrollmentStoreFailsClosedOnUnsafeResults(t *testing.T) {
	c, v, id := enrollmentStoreFixture(t)
	ctx := context.Background()
	for _, values := range [][]any{
		{"worker_" + strings.Repeat("4", 64), string(c.Fingerprint), "Q0", "QUARANTINED"},
		{string(id), strings.Repeat("f", 64), "Q0", "QUARANTINED"},
		{string(id), string(c.Fingerprint), "Q1", "QUARANTINED"},
		{string(id), string(c.Fingerprint), "Q0", "ACTIVE"},
	} {
		db := &enrollmentDBStub{row: enrollmentScan{values: values}}
		if _, err := NewWorkerEnrollmentStore(db).ConsumeEnrollment(ctx, v, id); !errors.Is(err, domain.ErrWorkerEnrollment) {
			t.Fatalf("unsafe result: %v", err)
		}
	}
	for _, values := range [][]any{
		{strings.Repeat("4", 64), c.Nonce, string(c.Fingerprint), c.Schema, c.Audience},
		{c.ID, "bad", string(c.Fingerprint), c.Schema, c.Audience},
		{c.ID, c.Nonce, string(c.Fingerprint), "other", c.Audience},
	} {
		db := &enrollmentDBStub{row: enrollmentScan{values: values}}
		if _, err := NewWorkerEnrollmentStore(db).ReadEnrollmentChallenge(ctx, c.ID); !errors.Is(err, domain.ErrEnrollmentTicket) {
			t.Fatalf("unsafe ticket: %v", err)
		}
	}
	db := &enrollmentDBStub{row: enrollmentScan{values: []any{false}}}
	if err := NewWorkerEnrollmentStore(db).CreateEnrollmentChallenge(ctx, c); !errors.Is(err, domain.ErrEnrollmentTicket) {
		t.Fatal(err)
	}
}
func TestWorkerEnrollmentStoreErrorMappingAndNoInvalidIO(t *testing.T) {
	c, v, id := enrollmentStoreFixture(t)
	ctx := context.Background()
	boom := errors.New("offline transport failed")
	for _, tc := range []struct{ err, want error }{
		{pgx.ErrNoRows, domain.ErrEnrollmentTicket},
		{&pgconn.PgError{Code: "P1001"}, domain.ErrEnrollmentTicket},
		{&pgconn.PgError{Code: "P1002"}, domain.ErrWorkerAlreadyEnrolled},
		{&pgconn.PgError{Code: "23505"}, nil}, {boom, boom}, {context.Canceled, context.Canceled},
	} {
		db := &enrollmentDBStub{row: enrollmentScan{err: tc.err}}
		store := NewWorkerEnrollmentStore(db)
		errs := []error{store.CreateEnrollmentChallenge(ctx, c)}
		_, err := store.ReadEnrollmentChallenge(ctx, c.ID)
		errs = append(errs, err)
		_, err = store.ConsumeEnrollment(ctx, v, id)
		errs = append(errs, err)
		for _, got := range errs {
			if got == nil || tc.want != nil && !errors.Is(got, tc.want) {
				t.Fatalf("mapping %v: %v", tc.err, got)
			}
		}
	}
	db := &enrollmentDBStub{}
	store := NewWorkerEnrollmentStore(db)
	if err := store.CreateEnrollmentChallenge(ctx, domain.EnrollmentChallenge{}); err == nil {
		t.Fatal("empty ticket")
	}
	if _, err := store.ReadEnrollmentChallenge(ctx, "bad"); err == nil {
		t.Fatal("invalid id")
	}
	if _, err := store.ConsumeEnrollment(ctx, domain.VerifiedWorkerEnrollment{}, id); err == nil {
		t.Fatal("unverified proof")
	}
	if _, err := store.ConsumeEnrollment(ctx, v, domain.WorkerID(c.Fingerprint)); err == nil {
		t.Fatal("fingerprint identity")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ConsumeEnrollment(cancelled, v, id); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := store.ReadEnrollmentChallenge(nil, c.ID); err == nil {
		t.Fatal("nil context")
	}
	var absent *WorkerEnrollmentStore
	if err := absent.CreateEnrollmentChallenge(ctx, c); err == nil {
		t.Fatal("nil store")
	}
	if db.calls != 0 {
		t.Fatal("invalid input reached DB")
	}
}
