package application

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type gatewayAuthorizer struct {
	calls  int
	err    error
	mutate func(GatewayOperation)
}

func (a *gatewayAuthorizer) AuthorizeOnline(_ context.Context, op GatewayOperation) error {
	a.calls++
	if a.mutate != nil {
		a.mutate(op)
	}
	return a.err
}

type gatewayAdapter struct {
	calls int
	err   error
	op    GatewayOperation
}

func (a *gatewayAdapter) DispatchExternal(_ context.Context, op GatewayOperation) error {
	a.calls++
	a.op = op
	return a.err
}

func validGatewayOperation() GatewayOperation {
	digest, _ := domain.ParseDigest(strings.Repeat("a", 64))
	return GatewayOperation{
		RootID: "root-1", WorkOrderID: "work-1", AttemptID: "attempt-1",
		WorkerID: "worker-1", SessionID: "session-1", LeaseEpoch: 1,
		PolicyDigest: digest, OperationID: "operation-1", Action: "publish", Payload: []byte{1, 2, 3},
	}
}

type testOfflineClock struct{ elapsed time.Duration }

func (c *testOfflineClock) Elapsed() time.Duration { return c.elapsed }

type testOfflineVerifier struct{ claims domain.OfflineGrantClaims }

func (v testOfflineVerifier) VerifyOfflineGrant([]byte) (domain.OfflineGrantClaims, error) {
	return v.claims, nil
}

func actualOfflineSession(t *testing.T) *domain.OfflineSession {
	t.Helper()
	digest, _ := domain.ParseDigest(strings.Repeat("b", 64))
	binding := domain.OfflineGrantBinding{
		GrantID: "grant-1", RootID: "root-1", WorkOrderID: "work-1", AttemptID: "attempt-1",
		LeaseEpoch: 1, WorkerID: "worker-1", SessionID: "session-1", PolicyDigest: digest,
		Policy: domain.OfflineCompute, Checkpointability: domain.Checkpointable,
	}
	clock := &testOfflineClock{}
	session, err := domain.VerifyOfflineGrant(binding, []byte("opaque-test-token"), testOfflineVerifier{claims: domain.OfflineGrantClaims{
		Binding: binding, TTL: time.Minute, AllowedOperations: []domain.OperationClass{domain.LocalCompute, domain.LocalCheckpoint},
	}}, clock)
	if err != nil {
		t.Fatalf("construct offline session: %v", err)
	}
	return session
}

func TestGatewayOfflineSessionDeniesWithoutCallingPorts(t *testing.T) {
	authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{}
	gateway := NewGateway(authorizer, adapter)
	err := gateway.ExecuteExternal(context.Background(), validGatewayOperation(), actualOfflineSession(t))
	if !errors.Is(err, ErrGatewayDenied) || authorizer.calls != 0 || adapter.calls != 0 {
		t.Fatalf("err=%v authorizer calls=%d adapter calls=%d", err, authorizer.calls, adapter.calls)
	}
}

func TestGatewayMissingPortsFailClosed(t *testing.T) {
	op := validGatewayOperation()
	for _, gateway := range []*Gateway{nil, NewGateway(nil, &gatewayAdapter{}), NewGateway(&gatewayAuthorizer{}, nil)} {
		if err := gateway.ExecuteExternal(context.Background(), op, nil); !errors.Is(err, ErrGatewayUnavailable) {
			t.Fatalf("expected unavailable sentinel, got %v", err)
		}
	}
}

func TestGatewayAuthorizationFailureDoesNotDispatchAndSanitizes(t *testing.T) {
	authorizer, adapter := &gatewayAuthorizer{err: errors.New("secret db detail")}, &gatewayAdapter{}
	err := NewGateway(authorizer, adapter).ExecuteExternal(context.Background(), validGatewayOperation(), nil)
	if !errors.Is(err, ErrGatewayDenied) || strings.Contains(err.Error(), "secret db detail") || adapter.calls != 0 {
		t.Fatalf("err=%v adapter calls=%d", err, adapter.calls)
	}
}

func TestGatewayOnlineAuthorizationDispatchesExactlyOnce(t *testing.T) {
	authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{}
	if err := NewGateway(authorizer, adapter).ExecuteExternal(context.Background(), validGatewayOperation(), nil); err != nil {
		t.Fatalf("ExecuteExternal: %v", err)
	}
	if authorizer.calls != 1 || adapter.calls != 1 {
		t.Fatalf("authorizer calls=%d adapter calls=%d", authorizer.calls, adapter.calls)
	}
}

func TestGatewayInvalidIdentityFailsClosed(t *testing.T) {
	for _, mutate := range []func(*GatewayOperation){
		func(op *GatewayOperation) { op.RootID = " " },
		func(op *GatewayOperation) { op.WorkOrderID = "" },
		func(op *GatewayOperation) { op.AttemptID = "" },
		func(op *GatewayOperation) { op.WorkerID = "" },
		func(op *GatewayOperation) { op.SessionID = "" },
		func(op *GatewayOperation) { op.LeaseEpoch = 0 },
		func(op *GatewayOperation) { op.PolicyDigest = "bad" },
		func(op *GatewayOperation) { op.OperationID = "" },
		func(op *GatewayOperation) { op.Action = "" },
	} {
		op := validGatewayOperation()
		mutate(&op)
		authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{}
		err := NewGateway(authorizer, adapter).ExecuteExternal(context.Background(), op, nil)
		if !errors.Is(err, ErrGatewayInvalid) || authorizer.calls != 0 || adapter.calls != 0 {
			t.Fatalf("err=%v authorizer=%d adapter=%d", err, authorizer.calls, adapter.calls)
		}
	}
}

func TestGatewayAuthorizerCannotMutateDispatchedRequest(t *testing.T) {
	op := validGatewayOperation()
	authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{}
	authorizer.mutate = func(request GatewayOperation) {
		request.Payload[0] = 99
	}
	if err := NewGateway(authorizer, adapter).ExecuteExternal(context.Background(), op, nil); err != nil {
		t.Fatalf("ExecuteExternal: %v", err)
	}
	if adapter.calls != 1 || adapter.op.Payload[0] != 1 || op.Payload[0] != 1 {
		t.Fatalf("payload isolation failed: adapter=%v caller=%v", adapter.op.Payload, op.Payload)
	}
}

func TestGatewayAdapterErrorHasUnknownOutcomeAndIsSanitized(t *testing.T) {
	authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{err: errors.New("credential leaked")}
	err := NewGateway(authorizer, adapter).ExecuteExternal(context.Background(), validGatewayOperation(), nil)
	if !errors.Is(err, ErrGatewayOutcomeUnknown) || errors.Is(err, ErrGatewayDenied) || strings.Contains(err.Error(), "credential leaked") || adapter.calls != 1 {
		t.Fatalf("err=%v adapter calls=%d", err, adapter.calls)
	}
}

func TestGatewayInvalidContextFailsClosed(t *testing.T) {
	authorizer, adapter := &gatewayAuthorizer{}, &gatewayAdapter{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewGateway(authorizer, adapter).ExecuteExternal(ctx, validGatewayOperation(), nil)
	if !errors.Is(err, ErrGatewayDenied) || authorizer.calls != 0 || adapter.calls != 0 {
		t.Fatalf("err=%v authorizer=%d adapter=%d", err, authorizer.calls, adapter.calls)
	}
}
