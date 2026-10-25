package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type eventAppendTransaction struct {
	statements      []string
	arguments       [][]any
	queryStatements []string
	queryArguments  [][]any
	execErrAt       int
	row             pgx.Row
	commits         int
	rollbacks       int
}

func TestSafetyTransactorSelectsScopedFunctionOnlyAdapter(t *testing.T) {
	tx := &eventAppendTransaction{}
	transactor := newTransactor(fakeBeginner{tx: tx})
	transactor.safetyAPI = true
	if err := transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		if _, ok := gov.(*safetyGovernanceTx); !ok {
			t.Fatalf("Safety callback received %T, want *safetyGovernanceTx", gov)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d, want one commit in the selected adapter's transaction", tx.commits, tx.rollbacks)
	}
}

func TestCommandReceiptDigestInsertValidatesAndPersistsCanonicalText(t *testing.T) {
	digest, err := domain.ParseDigest(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	tx := &eventAppendTransaction{}
	receipt := port.CommandReceipt{CommandID: "command-1", RequestDigest: digest, Status: "SUCCEEDED", Response: []byte(`{}`)}
	transactor := newTransactor(fakeBeginner{tx: tx})
	transactor.safetyAPI = true
	err = transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.InsertCommandReceipt(context.Background(), receipt)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.statements) != 1 || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("statements=%d commits=%d rollbacks=%d", len(tx.statements), tx.commits, tx.rollbacks)
	}
	if !strings.Contains(tx.statements[0], "raw.safety_insert_command_receipt($1, $2, $3, $4)") || tx.arguments[0][1] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected SQL/arguments: %s %#v", tx.statements[0], tx.arguments[0])
	}

	for _, invalid := range []domain.Digest{"", "not-a-digest"} {
		t.Run("reject-"+string(invalid), func(t *testing.T) {
			invalidTx := &eventAppendTransaction{}
			transactor := newTransactor(fakeBeginner{tx: invalidTx})
			transactor.safetyAPI = true
			err := transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
				return gov.InsertCommandReceipt(context.Background(), port.CommandReceipt{CommandID: "command-1", RequestDigest: invalid, Status: "SUCCEEDED", Response: []byte(`{}`)})
			})
			if err == nil || len(invalidTx.statements) != 0 || invalidTx.commits != 0 || invalidTx.rollbacks != 1 {
				t.Fatalf("err=%v statements=%d commits=%d rollbacks=%d", err, len(invalidTx.statements), invalidTx.commits, invalidTx.rollbacks)
			}
		})
	}
}

func TestCommandReceiptDigestLookupParsesStoredDigest(t *testing.T) {
	want, err := domain.ParseDigest(strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		digest    string
		rowErr    error
		wantFound bool
		wantErr   bool
	}{
		{name: "valid", digest: string(want), wantFound: true},
		{name: "malformed", digest: "malformed", wantErr: true},
		{name: "no rows", rowErr: pgx.ErrNoRows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &eventAppendTransaction{row: commandReceiptRow{values: []any{"command-1", tc.digest, "SUCCEEDED", []byte(`{}`)}, err: tc.rowErr}}
			transactor := newTransactor(fakeBeginner{tx: tx})
			transactor.safetyAPI = true
			var got port.CommandReceipt
			var found bool
			err := transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
				var lookupErr error
				got, found, lookupErr = gov.LookupCommandReceipt(context.Background(), "command-1")
				return lookupErr
			})
			if tc.wantErr {
				if err == nil || found || got.CommandID != "" || got.RequestDigest != "" || got.Status != "" || len(got.Response) != 0 {
					t.Fatalf("receipt=%#v found=%v err=%v; want error and no result", got, found, err)
				}
				return
			}
			if err != nil || found != tc.wantFound {
				t.Fatalf("receipt=%#v found=%v err=%v", got, found, err)
			}
			if len(tx.queryStatements) != 1 || !strings.Contains(tx.queryStatements[0], "raw.safety_lookup_command_receipt($1)") {
				t.Fatalf("receipt lookup bypassed the app-only function: %v", tx.queryStatements)
			}
			if tc.wantFound && (got.RequestDigest != want || got.CommandID != "command-1") {
				t.Fatalf("receipt=%#v, want digest %q", got, want)
			}
		})
	}
}

type commandReceiptRow struct {
	values []any
	err    error
}

func (r commandReceiptRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != len(r.values) {
		return errors.New("unexpected scan destination count")
	}
	for i, value := range r.values {
		switch destination := destinations[i].(type) {
		case *string:
			*destination = value.(string)
		case *[]byte:
			*destination = append([]byte(nil), value.([]byte)...)
		case *bool:
			*destination = value.(bool)
		default:
			return errors.New("unexpected scan destination type")
		}
	}
	return nil
}

func TestInsertPolicyBundlePersistsExactCanonicalEnvelope(t *testing.T) {
	tx := &eventAppendTransaction{}
	bundle, err := domain.NewCanonicalBundle("paddock.bundle/1", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte{1, 2, 3}
	err = newTransactor(fakeBeginner{tx: tx}).WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.InsertPolicyBundle(context.Background(), bundle, "signer-a", signature)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.statements) != 1 || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("statements=%d commits=%d rollbacks=%d", len(tx.statements), tx.commits, tx.rollbacks)
	}
	if !strings.Contains(tx.statements[0], "INSERT INTO raw.policy_bundles") || !strings.Contains(tx.statements[0], "(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature)") {
		t.Fatalf("unexpected SQL: %s", tx.statements[0])
	}
	args := tx.arguments[0]
	if len(args) != 5 || args[0] != string(bundle.Digest()) || string(args[1].([]byte)) != string(bundle.CanonicalBytes()) || args[2] != bundle.SchemaVersion() || args[3] != "signer-a" || string(args[4].([]byte)) != string(signature) {
		t.Fatalf("unexpected args: %#v", args)
	}
	args[4].([]byte)[0] = 9
	if signature[0] != 1 {
		t.Fatal("signature argument aliases caller memory")
	}
}

func TestInsertPolicyBundleRejectsInvalidInputsBeforeExec(t *testing.T) {
	valid, err := domain.NewCanonicalBundle("paddock.bundle/1", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	tampered := valid
	tampered = domain.CanonicalBundle{}
	for _, tc := range []struct {
		name      string
		bundle    domain.CanonicalBundle
		signer    string
		signature []byte
	}{
		{"invalid bundle", tampered, "signer-a", []byte{1}},
		{"blank signer", valid, " ", []byte{1}},
		{"empty signature", valid, "signer-a", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &eventAppendTransaction{}
			err := newTransactor(fakeBeginner{tx: tx}).WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
				return gov.InsertPolicyBundle(context.Background(), tc.bundle, tc.signer, tc.signature)
			})
			if err == nil || len(tx.statements) != 0 || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("err=%v statements=%d commits=%d rollbacks=%d", err, len(tx.statements), tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestInsertPolicyBundleFailureRollsBack(t *testing.T) {
	tx := &eventAppendTransaction{execErrAt: 1}
	bundle, err := domain.NewCanonicalBundle("paddock.bundle/1", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	err = newTransactor(fakeBeginner{tx: tx}).WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.InsertPolicyBundle(context.Background(), bundle, "signer-a", []byte{1})
	})
	if err == nil || !strings.Contains(err.Error(), "insert policy bundle") || tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("err=%v commits=%d rollbacks=%d", err, tx.commits, tx.rollbacks)
	}
}

func (f *eventAppendTransaction) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.statements = append(f.statements, sql)
	f.arguments = append(f.arguments, args)
	if f.execErrAt == len(f.statements) {
		return pgconn.CommandTag{}, errors.New("injected exec failure")
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}
func (*eventAppendTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}
func (f *eventAppendTransaction) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.queryStatements = append(f.queryStatements, sql)
	f.queryArguments = append(f.queryArguments, args)
	return f.row
}
func (f *eventAppendTransaction) Commit(context.Context) error {
	f.commits++
	return nil
}
func (f *eventAppendTransaction) Rollback(context.Context) error {
	f.rollbacks++
	return nil
}

var _ transaction = (*eventAppendTransaction)(nil)

func TestSafetyCASUsesOnlyAppFunctionBoundDatabaseAPI(t *testing.T) {
	tx := &eventAppendTransaction{row: commandReceiptRow{values: []any{true}}}
	gov := newSafetyGovernanceTx(tx)
	digest := domain.Digest(strings.Repeat("c", 64))
	scopeID := domain.ScopeID("scope-cas")
	rootID := domain.RootID("root-cas")
	expected := port.ScopeSnapshot{
		ScopeID: scopeID, ActivationEpoch: 4, Mode: domain.ScopeActive,
		BaselineBundle: &digest, SecurityEpoch: 7,
		Roots: map[domain.RootID]domain.RootAuthority{
			rootID: {Policy: domain.PolicyBinding{Digest: digest}, AuthorizationEpoch: 2},
		},
	}
	gov.lockedScopes[scopeID] = cloneScope(expected)
	gov.validatedScopes[scopeID] = true
	next := cloneScope(expected)
	next.Mode = domain.ScopeSafeStop
	if err := gov.CompareAndSwapScope(context.Background(), expected, next); err != nil {
		t.Fatal(err)
	}
	if err := gov.CompareAndSwapSecurityEpoch(context.Background(), 7, 8); err != nil {
		t.Fatal(err)
	}
	wantFunctions := []string{
		"raw.safety_cas_scope(",
		"raw.safety_cas_root(",
		"raw.safety_cas_security_epoch(",
	}
	if len(tx.queryStatements) != len(wantFunctions) {
		t.Fatalf("function calls=%v", tx.queryStatements)
	}
	for i, function := range wantFunctions {
		if !strings.Contains(tx.queryStatements[i], function) || strings.Contains(tx.queryStatements[i], "UPDATE raw.") {
			t.Fatalf("query %d bypasses restricted app function: %s", i, tx.queryStatements[i])
		}
	}
	if tx.queryArguments[0][0] != string(scopeID) || tx.queryArguments[0][1] != domain.Epoch(4) || tx.queryArguments[0][5] != domain.Epoch(4) || tx.queryArguments[0][9] != domain.Epoch(7) {
		t.Fatalf("unexpected Scope CAS arguments: %#v", tx.queryArguments[0])
	}
	if tx.queryArguments[1][0] != string(rootID) || tx.queryArguments[1][1] != string(scopeID) || tx.queryArguments[1][2] != domain.Epoch(2) {
		t.Fatalf("unexpected Root CAS arguments: %#v", tx.queryArguments[1])
	}
	if tx.queryArguments[2][0] != domain.Epoch(7) || tx.queryArguments[2][1] != domain.Epoch(8) {
		t.Fatalf("unexpected Security Epoch CAS arguments: %#v", tx.queryArguments[2])
	}
}

func TestAppendEventCallsAtomicFunctionWithExactEnvelopeArguments(t *testing.T) {
	tx := &eventAppendTransaction{}
	payload := []byte{1, 2}
	event, err := domain.NewEvent("event-1", "rollout", "rollout-7", 3, "Started", "event/1", payload)
	if err != nil {
		t.Fatal(err)
	}
	transactor := newTransactor(fakeBeginner{tx: tx})
	err = transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.AppendEvent(context.Background(), event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.statements) != 1 || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("statements=%d commit=%d rollback=%d, want 1/1/0", len(tx.statements), tx.commits, tx.rollbacks)
	}
	if !strings.Contains(tx.statements[0], "SELECT raw.append_domain_event_and_outbox($1, $2, $3, $4, $5, $6, $7)") {
		t.Fatalf("unexpected append function SQL: %s", tx.statements[0])
	}
	args := tx.arguments[0]
	if len(args) != 7 || args[0] != "event-1" || args[1] != "rollout" || args[2] != "rollout-7" || args[3] != int64(3) || args[4] != "Started" || args[5] != "event/1" || string(args[6].([]byte)) != string(payload) {
		t.Fatalf("event function arguments do not exactly map the envelope: %#v", args)
	}
	args[6].([]byte)[0] = 9
	if payload[0] != 1 {
		t.Fatal("payload argument aliases caller memory")
	}
}

func TestAppendEventFunctionFailureRollsBackTransaction(t *testing.T) {
	tx := &eventAppendTransaction{execErrAt: 1}
	event, err := domain.NewEvent("event-1", "rollout", "rollout-7", 3, "Started", "event/1", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	transactor := newTransactor(fakeBeginner{tx: tx})
	err = transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.AppendEvent(context.Background(), event)
	})
	if err == nil || !strings.Contains(err.Error(), "append event/outbox") {
		t.Fatalf("AppendEvent error = %v, want function failure", err)
	}
	if len(tx.statements) != 1 || tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("statements=%d commit=%d rollback=%d, want 1/0/1", len(tx.statements), tx.commits, tx.rollbacks)
	}
}

func TestAppendEventCallbackFailureRollsBackOuterTransaction(t *testing.T) {
	tx := &eventAppendTransaction{}
	event, err := domain.NewEvent("event-1", "rollout", "rollout-7", 3, "Started", "event/1", []byte{})
	if err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("callback failed")
	transactor := newTransactor(fakeBeginner{tx: tx})
	err = transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		if err := gov.AppendEvent(context.Background(), event); err != nil {
			return err
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) || len(tx.statements) != 1 || tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("err=%v statements=%d commits=%d rollbacks=%d", err, len(tx.statements), tx.commits, tx.rollbacks)
	}
}

func TestAppendEventRejectsInvalidEnvelopeBeforeWrites(t *testing.T) {
	tx := &eventAppendTransaction{}
	transactor := newTransactor(fakeBeginner{tx: tx})
	err := transactor.WithinTransaction(context.Background(), func(gov port.GovernanceTx) error {
		return gov.AppendEvent(context.Background(), domain.Event{})
	})
	if err == nil || len(tx.statements) != 0 || tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("AppendEvent invalid event: err=%v statements=%d commits=%d rollbacks=%d", err, len(tx.statements), tx.commits, tx.rollbacks)
	}
}

func TestCommandReceiptTerminalReadWriteAndTombstone(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, status := range []string{"SUCCEEDED", "REJECTED"} {
		for _, expired := range []bool{false, true} {
			t.Run(status+"/expired="+fmt.Sprint(expired), func(t *testing.T) {
				body := []byte(`{"schema_version":"paddock.command-response/1"}`)
				if expired {
					body = []byte(port.ReceiptTombstoneResponse)
				}
				tx := &eventAppendTransaction{row: commandReceiptRow{values: []any{"command", digest, status, body}}}
				got, found, err := newSafetyGovernanceTx(tx).LookupCommandReceipt(context.Background(), "command")
				if err != nil || !found || got.Expired != expired || got.Status != status || string(got.RequestDigest) != digest || !bytes.Equal(got.Response, body) {
					t.Fatalf("got=%+v found=%v err=%v", got, found, err)
				}
				if err := newSafetyGovernanceTx(tx).InsertCommandReceipt(context.Background(), got); (err != nil) != expired {
					t.Fatalf("insert expired=%v error=%v", expired, err)
				}
				if expired && len(tx.statements) != 0 {
					t.Fatal("tombstone insert reached SQL")
				}
			})
		}
	}
	for _, status := range []string{"IN_PROGRESS", "TRANSIENT", "UNKNOWN_COMMIT", "invalid"} {
		tx := &eventAppendTransaction{row: commandReceiptRow{values: []any{"command", digest, status, []byte(`{}`)}}}
		if _, _, err := newSafetyGovernanceTx(tx).LookupCommandReceipt(context.Background(), "command"); err == nil {
			t.Fatalf("nonterminal status %s returned", status)
		}
		if err := newSafetyGovernanceTx(tx).InsertCommandReceipt(context.Background(), port.CommandReceipt{CommandID: "command", RequestDigest: domain.Digest(digest), Status: status, Response: []byte(`{}`)}); err == nil || len(tx.statements) != 0 {
			t.Fatalf("nonterminal status %s inserted", status)
		}
	}
	// Even a caller omitting Expired cannot forge the reserved retention marker.
	tx := &eventAppendTransaction{}
	if err := newSafetyGovernanceTx(tx).InsertCommandReceipt(context.Background(), port.CommandReceipt{CommandID: "command", RequestDigest: domain.Digest(digest), Status: "REJECTED", Response: []byte(port.ReceiptTombstoneResponse)}); err == nil || len(tx.statements) != 0 {
		t.Fatal("forged tombstone inserted")
	}
}
