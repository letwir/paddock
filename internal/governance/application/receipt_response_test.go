package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type receiptHarness struct {
	port.GovernanceTx
	receipt                      port.CommandReceipt
	lookupErr, insertErr, endErr error
	found                        bool
	inserts, commits, rollbacks  int
}

func (h *receiptHarness) LookupCommandReceipt(context.Context, string) (port.CommandReceipt, bool, error) {
	return h.receipt, h.found, h.lookupErr
}
func (h *receiptHarness) InsertCommandReceipt(_ context.Context, r port.CommandReceipt) error {
	h.inserts++
	if h.insertErr != nil {
		return h.insertErr
	}
	h.receipt, h.found = r, true
	return nil
}
func (h *receiptHarness) within(_ context.Context, fn func(port.GovernanceTx) error) error {
	previous, found := h.receipt, h.found
	if err := fn(h); err != nil {
		h.receipt, h.found = previous, found
		h.rollbacks++
		return err
	}
	h.commits++
	return h.endErr
}
func (h *receiptHarness) run(apply func(port.GovernanceTx) error) error {
	return withinReceiptCommand(context.Background(), "command", testDigest(), h.within,
		func(port.GovernanceTx, []byte) error { return nil }, apply)
}

func TestReceiptFailureTaxonomyAndSanitization(t *testing.T) {
	secretDiagnostic := errors.New("SQLSTATE 42501 driver failure private relation stack trace")
	for _, tc := range []struct {
		name     string
		err      error
		code     string
		terminal bool
	}{
		{"invalid", commandFailure(FailureInvalid, secretDiagnostic), "VALIDATION_DENIED", true},
		{"forbidden", commandFailure(FailureForbidden, secretDiagnostic), "FORBIDDEN", true},
		{"stale", port.ErrStaleWrite, "TRANSIENT", false},
		{"busy", commandFailure(FailureBusy, secretDiagnostic), "TRANSIENT", false},
		{"retryable", commandFailure(FailureRetryable, secretDiagnostic), "TRANSIENT", false},
		{"unclassified", secretDiagnostic, "TRANSIENT", false},
		{"unknown", errors.Join(port.ErrCommitOutcomeUnknown, secretDiagnostic), "UNKNOWN_COMMIT", false},
		{"unknown beats forbidden", commandFailure(FailureForbidden, errors.Join(port.ErrCommitOutcomeUnknown, secretDiagnostic)), "UNKNOWN_COMMIT", false},
		{"known aborted ACL", errors.Join(port.ErrTransactionRolledBack, stateErr{"42501"}), "FORBIDDEN", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := CommandErrorResponse(tc.err)
			if response.SchemaVersion != CommandResponseSchema || response.Code != tc.code || response.Detail == "" {
				t.Fatalf("response=%+v", response)
			}
			b, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			for _, diagnostic := range []string{"SQLSTATE", "42501", "driver", "private relation", "stack trace", "cause", "Cause"} {
				if strings.Contains(string(b), diagnostic) {
					t.Fatalf("diagnostic leaked: %s", b)
				}
			}
			h := &receiptHarness{}
			first := h.run(func(port.GovernanceTx) error { return denyReceipt(tc.err) })
			if !errors.Is(first, tc.err) {
				t.Fatalf("internal cause lost: %v", first)
			}
			if !tc.terminal {
				if h.inserts != 0 || h.found || h.commits != 0 || h.rollbacks != 1 {
					t.Fatalf("nonterminal persisted: %+v", h)
				}
				return
			}
			if h.inserts != 1 || h.commits != 1 || h.receipt.Status != "REJECTED" || string(h.receipt.Response) != string(b) {
				t.Fatalf("denial not committed: %+v", h)
			}
			if strings.Contains(first.Error(), secretDiagnostic.Error()) {
				t.Fatal("public denial error leaked its internal cause")
			}
			second := h.run(func(port.GovernanceTx) error { t.Fatal("replayed command ran"); return nil })
			if !reflect.DeepEqual(CommandErrorResponse(first), CommandErrorResponse(second)) || first.Error() != second.Error() || h.inserts != 1 || h.commits != 2 {
				t.Fatalf("unstable replay: first=%v second=%v", first, second)
			}
		})
	}
}

func TestReceiptOnlyExplicitPreWriteDenialsCanCommit(t *testing.T) {
	h := &receiptHarness{}
	internal := commandFailure(FailureForbidden, errors.New("post-write failure"))
	if err := h.run(func(port.GovernanceTx) error { return internal }); !errors.Is(err, internal) || h.inserts != 0 || h.rollbacks != 1 {
		t.Fatalf("unmarked error became durable: %v %+v", err, h)
	}
	for _, where := range []string{"lookup", "insert", "commit"} {
		t.Run(where, func(t *testing.T) {
			h := &receiptHarness{}
			failure := errors.New("injected persistence failure")
			switch where {
			case "lookup":
				h.lookupErr = failure
			case "insert":
				h.insertErr = failure
			case "commit":
				h.endErr = errors.Join(port.ErrCommitOutcomeUnknown, failure)
			}
			err := h.run(func(port.GovernanceTx) error { return denyReceipt(domain.ErrInvalidApproval) })
			if !errors.Is(err, failure) {
				t.Fatalf("persistence failure hidden by denial: %v", err)
			}
			if where == "commit" && CommandErrorResponse(err).Kind != "UNKNOWN_COMMIT" {
				t.Fatalf("commit uncertainty lost: %v", err)
			}
			if where == "insert" && h.found {
				t.Fatal("failed insert persisted")
			}
		})
	}
}

func TestReceiptDigestPrecedesExpiryForEveryTerminalStatus(t *testing.T) {
	for _, status := range []string{"SUCCEEDED", "REJECTED"} {
		for _, changed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/modified=%v", status, changed), func(t *testing.T) {
				r := port.CommandReceipt{CommandID: "command", RequestDigest: testDigest(), Status: status, Expired: true, Response: []byte(port.ReceiptTombstoneResponse)}
				if changed {
					r.RequestDigest = domain.Digest(strings.Repeat("b", 64))
				}
				h := &receiptHarness{receipt: r, found: true}
				err := h.run(func(port.GovernanceTx) error { t.Fatal("expired ID reused"); return nil })
				want := "RECEIPT_EXPIRED"
				if changed {
					want = "COMMAND_ID_CONFLICT"
				}
				if CommandErrorResponse(err).Code != want || errors.Is(err, port.ErrReceiptExpired) == changed || h.inserts != 0 || h.commits != 1 || !reflect.DeepEqual(h.receipt, r) {
					t.Fatalf("err=%v receipt=%+v", err, h.receipt)
				}
			})
		}
	}
}

func TestReceiptSuccessfulEnvelopeAndHistoricalCompatibility(t *testing.T) {
	want := PromoteResult{CommandID: "command", State: domain.RolloutMonitoring, ScopeEpoch: 42}
	modern, err := marshalCommandResult(want)
	if err != nil {
		t.Fatal(err)
	}
	var envelope CommandResponse
	if json.Unmarshal(modern, &envelope) != nil || envelope.SchemaVersion != CommandResponseSchema || envelope.Kind != "SUCCEEDED" || envelope.Code != "SUCCEEDED" {
		t.Fatalf("response=%s", modern)
	}
	legacy, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{modern, legacy} {
		var got PromoteResult
		if err := unmarshalCommandResult(b, &got); err != nil || got != want {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	}
	tombstone, err := json.Marshal(responseForCode("RECEIPT_EXPIRED"))
	if err != nil || string(tombstone) != port.ReceiptTombstoneResponse {
		t.Fatalf("tombstone drift: %s %v", tombstone, err)
	}
}

func TestReceiptRejectsMalformedOrUnsafeNegativeResponses(t *testing.T) {
	for _, body := range []string{
		`{`, `{}`, `{"schema_version":"unknown","kind":"FORBIDDEN","code":"FORBIDDEN"}`,
		`{"schema_version":"paddock.command-response/1","kind":"FORBIDDEN","code":"FORBIDDEN","detail":"SQLSTATE 42501 stack trace"}`,
	} {
		h := &receiptHarness{found: true, receipt: port.CommandReceipt{CommandID: "command", RequestDigest: testDigest(), Status: "REJECTED", Response: []byte(body)}}
		err := h.run(func(port.GovernanceTx) error { t.Fatal("invalid receipt reran"); return nil })
		if err == nil || CommandErrorResponse(err).Kind != "TRANSIENT" || h.inserts != 0 {
			t.Fatalf("unsafe negative accepted: %v", err)
		}
	}
}

func TestReceiptProjectionDoesNotTrustExternallyConstructedErrorDetail(t *testing.T) {
	err := &CommandResponse{SchemaVersion: CommandResponseSchema, Kind: "FORBIDDEN", Code: "FORBIDDEN", Detail: "SQLSTATE 42501 private driver trace", Result: json.RawMessage(`{"stack":"private"}`)}
	got := CommandErrorResponse(err)
	if !reflect.DeepEqual(got, responseForCode("FORBIDDEN")) {
		t.Fatalf("external error detail was trusted: %+v", got)
	}
}

func TestReceiptSuccessfulReplayReadFailureRollsBackAndPreservesCause(t *testing.T) {
	b, err := marshalCommandResult(PromoteResult{CommandID: "command"})
	if err != nil {
		t.Fatal(err)
	}
	h := &receiptHarness{found: true, receipt: port.CommandReceipt{CommandID: "command", RequestDigest: testDigest(), Status: "SUCCEEDED", Response: b}}
	readErr := stateErr{"40001"}
	err = withinReceiptCommand(context.Background(), "command", testDigest(), h.within,
		func(port.GovernanceTx, []byte) error { return readErr },
		func(port.GovernanceTx) error { t.Fatal("success replay reapplied"); return nil })
	if !errors.Is(err, readErr) || h.commits != 0 || h.rollbacks != 1 || h.inserts != 0 {
		t.Fatalf("replay read failure attempted commit or lost cause: %v %+v", err, h)
	}
}
