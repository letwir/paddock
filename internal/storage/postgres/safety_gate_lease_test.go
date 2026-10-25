package postgres

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func safetyLeaseBinding() domain.AttemptLeaseBinding {
	return domain.AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: "worker", SessionID: "session", LeaseEpoch: 3}
}

func TestSafetyGateLeaseUsesOnlyParameterizedCapability(t *testing.T) {
	tx := &rolloutRecordingTx{}
	gate := newSafetyGateTx(tx)
	if err := gate.ValidateCurrentLease(context.Background(), "scope", "root", safetyLeaseBinding()); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 1 || tx.calls[0].sql != `SELECT raw.safety_validate_current_lease($1,$2,$3,$4,$5,$6,$7)` || !reflect.DeepEqual(tx.calls[0].args, []any{"scope", "root", "work", "attempt", "worker", "session", int64(3)}) {
		t.Fatalf("unexpected call: %+v", tx.calls)
	}
	if tx.commits != 0 || tx.rollbacks != 0 {
		t.Fatal("lease adapter took transaction ownership")
	}
}

func TestSafetyGateLeaseDeniesFalseAndPropagatesDatabaseFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		tx   *rolloutRecordingTx
		want error
	}{
		{"denied", &rolloutRecordingTx{results: []bool{false}}, domain.ErrInvalidLease},
		{"database", &rolloutRecordingTx{rowErrAt: 1}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newSafetyGateTx(tc.tx).ValidateCurrentLease(context.Background(), "scope", "root", safetyLeaseBinding())
			if err == nil {
				t.Fatal("failed open")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if tc.want == nil && (!strings.Contains(err.Error(), "validate SafetyGate current lease") || errors.Is(err, domain.ErrInvalidLease)) {
				t.Fatalf("database error hidden: %v", err)
			}
		})
	}
	tx := &rolloutRecordingTx{}
	if err := newSafetyGateTx(tx).ValidateCurrentLease(context.Background(), "scope", "root", domain.AttemptLeaseBinding{}); !errors.Is(err, domain.ErrInvalidLease) || len(tx.calls) != 0 {
		t.Fatalf("malformed binding queried DB: %v", err)
	}
}

type safetyLeaseErrorTx struct {
	fakeTransaction
	err error
}

func (tx *safetyLeaseErrorTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return rolloutBoolRow{err: tx.err}
}

func TestSafetyGateLeasePreservesErrorCause(t *testing.T) {
	cause := &pgconn.PgError{Code: "55P03", Message: "lock unavailable"}
	err := newSafetyGateTx(&safetyLeaseErrorTx{err: cause}).ValidateCurrentLease(context.Background(), "scope", "root", safetyLeaseBinding())
	if !errors.Is(err, cause) {
		t.Fatalf("lost error cause: %v", err)
	}
}

func TestSafetyGateTransactionLifecycle(t *testing.T) {
	ctx := context.Background()
	denied := domain.ErrInvalidLease
	for _, tc := range []struct {
		name               string
		callback           error
		commit             error
		rollback           error
		want               error
		commits, rollbacks int
	}{
		{name: "commit", commits: 1},
		{name: "denial rolls back", callback: denied, want: port.ErrTransactionRolledBack, rollbacks: 1},
		{name: "rollback failure", callback: denied, rollback: io.EOF, want: io.EOF, rollbacks: 1},
		{name: "unknown commit", commit: io.EOF, want: port.ErrCommitOutcomeUnknown, commits: 1},
		{name: "known abort", commit: &pgconn.PgError{Code: "40001"}, want: port.ErrTransactionRolledBack, commits: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeTransaction{commitErr: tc.commit, rollbackErr: tc.rollback}
			transactor := &SafetyGateTransactor{pool: fakeBeginner{tx: tx}}
			err := transactor.WithinSafetyGateTransaction(ctx, func(gate port.SafetyGateTx) error {
				// The typed adapter carries this exact transaction, not a second connection.
				if gate.(*safetyGateTx).tx != tx {
					t.Fatal("wrong transaction")
				}
				return tc.callback
			})
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.callback != nil && !errors.Is(err, tc.callback) {
				t.Fatal("lost callback error")
			}
			if tx.commits != tc.commits || tx.rollbacks != tc.rollbacks {
				t.Fatalf("commit/rollback=%d/%d", tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestSafetyGateTransactionRejectsInvalidInputsAndBeginFailure(t *testing.T) {
	if _, err := NewSafetyGateTransactor(nil); err == nil {
		t.Fatal("nil pool accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx := &fakeTransaction{}
	gate := &SafetyGateTransactor{pool: fakeBeginner{tx: tx}}
	callback := func(port.SafetyGateTx) error { t.Fatal("unexpected callback"); return nil }
	for _, err := range []error{gate.WithinSafetyGateTransaction(nil, callback), gate.WithinSafetyGateTransaction(ctx, callback), gate.WithinSafetyGateTransaction(context.Background(), nil), (*SafetyGateTransactor)(nil).WithinSafetyGateTransaction(context.Background(), callback)} {
		if err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	cause := errors.New("begin unavailable")
	err := (&SafetyGateTransactor{pool: fakeBeginner{err: cause}}).WithinSafetyGateTransaction(context.Background(), callback)
	if !errors.Is(err, cause) {
		t.Fatal(err)
	}
}

func TestSafetyGateTransactionCancellationAndPanicRollback(t *testing.T) {
	tx := &fakeTransaction{}
	gate := &SafetyGateTransactor{pool: fakeBeginner{tx: tx}}
	ctx, cancel := context.WithCancel(context.Background())
	err := gate.WithinSafetyGateTransaction(ctx, func(port.SafetyGateTx) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || tx.rollbacks != 1 || tx.commits != 0 {
		t.Fatalf("cancellation: %v %+v", err, tx)
	}
	defer func() {
		if recover() != "panic fixture" || tx.rollbacks != 2 {
			t.Fatal("panic not propagated after rollback")
		}
	}()
	_ = gate.WithinSafetyGateTransaction(context.Background(), func(port.SafetyGateTx) error { panic("panic fixture") })
}

// The additional credential read borrows exactly the same underlying tx and
// never starts/commits an independent transaction after Lease validation.
type credentialGateRecordingTx struct {
	fakeTransaction
	row   pgx.Row
	query string
	args  []any
}

func (tx *credentialGateRecordingTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	tx.query = q
	tx.args = args
	return tx.row
}
func TestSafetyGateCredentialUsesBorrowedAuthorityTransaction(t *testing.T) {
	c, key := storageCredentialFixture(t)
	tx := &credentialGateRecordingTx{row: enrollmentScan{values: credentialScanValues(c, key)}}
	gate := newSafetyGateTx(tx)
	got, pub, err := gate.LockWorkerCredential(context.Background(), c.ID)
	if err != nil || got != c || !reflect.DeepEqual(pub, key) || !reflect.DeepEqual(tx.args, []any{c.ID}) {
		t.Fatalf("credential lookup failed: %v", err)
	}
	tx.row = enrollmentScan{values: []any{c.Issuer.IssuerID, "1", string(c.Issuer.CeilingDigest)}}
	issuer, err := gate.LockCurrentCredentialIssuer(context.Background(), c.Issuer.IssuerID)
	if err != nil || issuer != c.Issuer || tx.query != `SELECT issuer_id,issuer_revision,ceiling_digest FROM raw.lock_current_worker_issuer_context($1)` || !reflect.DeepEqual(tx.args, []any{c.Issuer.IssuerID}) {
		t.Fatalf("issuer not read on borrowed transaction: %v", err)
	}
	if gate.tx != tx || tx.commits != 0 || tx.rollbacks != 0 {
		t.Fatal("credential read took transaction ownership")
	}
}
