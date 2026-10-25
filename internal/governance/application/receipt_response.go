package application

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

const CommandResponseSchema = "paddock.command-response/1"

// CommandResponse is the serialized, user-safe command outcome. Detail is chosen
// from a closed vocabulary, never from an error, request, or driver diagnostic.
// Internal causes remain available through errors.Is/As, not through JSON.
type CommandResponse struct {
	SchemaVersion string          `json:"schema_version"`
	Kind          string          `json:"kind"`
	Code          string          `json:"code"`
	Detail        string          `json:"detail"`
	Result        json.RawMessage `json:"result,omitempty"`
	cause         error
}

func (r *CommandResponse) Error() string { return r.Code + ": " + r.Detail }
func (r *CommandResponse) Unwrap() error { return r.cause }

func responseForCode(code string) CommandResponse {
	r := CommandResponse{SchemaVersion: CommandResponseSchema, Code: code}
	switch code {
	case "VALIDATION_DENIED":
		r.Kind, r.Detail = "VALIDATION_DENIED", "The command failed request validation. Submit a corrected request with a new command ID."
	case "FORBIDDEN":
		r.Kind, r.Detail = "FORBIDDEN", "The command is not authorized for the requested transition."
	case "COMMAND_ID_CONFLICT":
		r.Kind, r.Detail = "VALIDATION_DENIED", "The command ID is already bound to a different request."
	case "RECEIPT_EXPIRED":
		r.Kind, r.Detail = "EXPIRED", "The command response retention period has expired; this command ID cannot be reused."
	case "UNKNOWN_COMMIT":
		r.Kind, r.Detail = "UNKNOWN_COMMIT", "The commit outcome is unknown. Reconcile using the same command ID and request."
	case "TRANSIENT":
		r.Kind, r.Detail = "TRANSIENT", "The command could not complete. Retry or reconcile using the same command ID and request."
	case "SUCCEEDED":
		r.Kind, r.Detail = "SUCCEEDED", "The command completed successfully."
	}
	return r
}

// CommandErrorResponse projects an internal failure to a safe wire response.
// Unclassified operational errors are nonterminal TRANSIENT, not validation
// denials. This projection is not a retry policy or permission to retry.
func CommandErrorResponse(err error) CommandResponse {
	if errors.Is(err, port.ErrCommitOutcomeUnknown) {
		return responseForCode("UNKNOWN_COMMIT")
	}
	var response *CommandResponse
	if errors.As(err, &response) {
		// CommandResponse is exported for wire use. Even an externally
		// constructed error must not inject arbitrary detail or result bytes.
		switch response.Code {
		case "VALIDATION_DENIED", "FORBIDDEN", "COMMAND_ID_CONFLICT", "RECEIPT_EXPIRED", "UNKNOWN_COMMIT", "TRANSIENT":
			return responseForCode(response.Code)
		}
	}
	var failure *CommandFailure
	if errors.As(normalizeCommandFailure(err), &failure) {
		switch failure.Kind {
		case FailureInvalid:
			return responseForCode("VALIDATION_DENIED")
		case FailureForbidden:
			return responseForCode("FORBIDDEN")
		}
	}
	return responseForCode("TRANSIENT")
}

func responseError(r CommandResponse, cause error) error {
	r.cause = cause
	switch r.Kind {
	case "VALIDATION_DENIED", "EXPIRED":
		return commandFailure(FailureInvalid, &r)
	case "FORBIDDEN":
		return commandFailure(FailureForbidden, &r)
	default:
		return &r
	}
}

// receiptDenial marks only pure, pre-write validation/authorization failures.
// Never mark an adapter/transaction failure or an error after attempting writes.
type receiptDenial struct{ error }

func denyReceipt(err error) error {
	var databaseError sqlStateError
	if errors.Is(err, port.ErrCommitOutcomeUnknown) || errors.Is(err, port.ErrTransactionRolledBack) || errors.As(err, &databaseError) {
		return err
	}
	r := CommandErrorResponse(err)
	if r.Code == "VALIDATION_DENIED" || r.Code == "FORBIDDEN" {
		return &receiptDenial{err}
	}
	return err
}

func commandReplay(ctx context.Context, tx port.GovernanceTx, id string, d domain.Digest) ([]byte, bool, error) {
	r, found, err := tx.LookupCommandReceipt(ctx, id)
	if err != nil || !found {
		return nil, false, err
	}
	// Digest equality always precedes expiry, even for permanent tombstones.
	if r.RequestDigest != d {
		return nil, true, responseError(responseForCode("COMMAND_ID_CONFLICT"), nil)
	}
	if r.Expired {
		return nil, true, responseError(responseForCode("RECEIPT_EXPIRED"), port.ErrReceiptExpired)
	}
	if r.Status == "REJECTED" {
		var recorded CommandResponse
		if json.Unmarshal(r.Response, &recorded) != nil || (recorded.Code != "VALIDATION_DENIED" && recorded.Code != "FORBIDDEN") {
			return nil, true, errors.New("invalid negative command receipt")
		}
		// Require exactly the selected vocabulary; never trust stored detail as
		// a source for a public error message.
		safe := responseForCode(recorded.Code)
		if recorded.SchemaVersion != safe.SchemaVersion || recorded.Kind != safe.Kind || recorded.Detail != safe.Detail || len(recorded.Result) != 0 {
			return nil, true, errors.New("invalid negative command receipt response")
		}
		return nil, true, responseError(safe, nil)
	}
	if r.Status != "SUCCEEDED" || len(r.Response) == 0 {
		return nil, true, errors.New("invalid command receipt")
	}
	return r.Response, true, nil
}

// withinReceiptCommand commits lookup maintenance and deterministic negative
// receipts while returning the command denial separately. A failed commit always
// takes precedence, notably UNKNOWN_COMMIT; no denial is claimed durable then.
func withinReceiptCommand[T port.GovernanceTx](ctx context.Context, id string, digest domain.Digest,
	within func(context.Context, func(T) error) error, replay func(T, []byte) error, apply func(T) error,
) error {
	var outcome error
	err := within(ctx, func(tx T) error {
		outcome = nil
		b, found, err := commandReplay(ctx, tx, id, digest)
		if found {
			outcome = err
			if err == nil {
				// Safety replay reads/locks current authority. Propagate read or
				// reconciliation errors through rollback, not a commit attempt on
				// an aborted transaction that could hide the original SQLSTATE.
				return replay(tx, b)
			}
			return nil
		}
		if err != nil {
			return err
		}
		err = apply(tx)
		var denial *receiptDenial
		if !errors.As(err, &denial) {
			return err
		}
		response := CommandErrorResponse(denial.error)
		b, err = json.Marshal(response)
		if err != nil {
			return err
		}
		if err = tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: id, RequestDigest: digest, Status: "REJECTED", Response: b}); err != nil {
			return err
		}
		outcome = responseError(response, denial.error)
		return nil
	})
	if err != nil {
		return err
	}
	return outcome
}

func marshalCommandResult(result any) ([]byte, error) {
	b, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	r := responseForCode("SUCCEEDED")
	r.Result = b
	return json.Marshal(r)
}

func unmarshalCommandResult(b []byte, out any) error {
	var r CommandResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	// Historical successful receipts predate the envelope. Retain their replay
	// compatibility, including Safety's subsequent state reconciliation.
	if r.SchemaVersion == "" {
		return json.Unmarshal(b, out)
	}
	if r.SchemaVersion != CommandResponseSchema || r.Kind != "SUCCEEDED" || r.Code != "SUCCEEDED" || len(r.Result) == 0 {
		return errors.New("invalid successful command receipt response")
	}
	return json.Unmarshal(r.Result, out)
}

// BundleRegistrationService combines verification with insertion. This guard
// distinguishes pre-write verifier failures from failures of the insert itself.
type receiptBundleTx struct {
	port.GovernanceTx
	writeAttempted bool
}

func (t *receiptBundleTx) InsertPolicyBundle(ctx context.Context, b domain.CanonicalBundle, key string, sig []byte) error {
	t.writeAttempted = true
	return t.GovernanceTx.InsertPolicyBundle(ctx, b, key, sig)
}
