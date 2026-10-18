package application

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type testElapsedClock struct {
	mu  sync.Mutex
	now time.Duration
}

func TestCachedAuthorizerSlowUnavailableReadUsesPostReadTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		postRead  time.Duration
		wantAllow bool
	}{
		{name: "exact deadline", postRead: 10 * time.Second},
		{name: "past deadline", postRead: 11 * time.Second},
		{name: "still before deadline", postRead: 9 * time.Second, wantAllow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &testElapsedClock{}
			reader := &testAuthorizationReader{}
			authorizer := NewCachedOnlineAuthorizer(reader, clock)
			reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: 10 * time.Second}, nil)
			if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
				t.Fatal(err)
			}
			clock.set(time.Second)
			reader.onRead = func() { clock.set(tc.postRead) }
			reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
			gotAllow := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()) == nil
			if gotAllow != tc.wantAllow {
				t.Fatalf("allowed=%v, want %v", gotAllow, tc.wantAllow)
			}
			if got, want := authorizer.lastTime, tc.postRead; got != want {
				t.Fatalf("tracked time = %v, want post-read %v", got, want)
			}
		})
	}
}

func TestCachedAuthorizerSuccessfulReadUsesPostReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		risk      AuthorizationRisk
		postRead  time.Duration
		wantAllow bool
		wantCache bool
	}{
		{name: "HIGH exact deadline denied", risk: AuthorizationRiskHigh, postRead: 10 * time.Second},
		{name: "HIGH past deadline denied", risk: AuthorizationRiskHigh, postRead: 11 * time.Second},
		{name: "LOW exact deadline denied", risk: AuthorizationRiskLow, postRead: 10 * time.Second},
		{name: "LOW past deadline denied", risk: AuthorizationRiskLow, postRead: 11 * time.Second},
		{name: "LOW before deadline cached", risk: AuthorizationRiskLow, postRead: 9 * time.Second, wantAllow: true, wantCache: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &testElapsedClock{}
			reader := &testAuthorizationReader{onRead: func() { clock.set(tc.postRead) }}
			reader.push(AuthorizationSnapshot{Allowed: true, Risk: tc.risk, LeaseRemaining: 10 * time.Second}, nil)
			authorizer := NewCachedOnlineAuthorizer(reader, clock)
			gotAllow := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()) == nil
			if gotAllow != tc.wantAllow {
				t.Fatalf("allowed=%v, want %v", gotAllow, tc.wantAllow)
			}
			key, _ := authorizationKey(cacheTestOperation())
			_, gotCache := authorizer.lowCache[key]
			if gotCache != tc.wantCache {
				t.Fatalf("cached=%v, want %v", gotCache, tc.wantCache)
			}
			if got, want := authorizer.lastTime, tc.postRead; got != want {
				t.Fatalf("tracked time = %v, want post-read %v", got, want)
			}
		})
	}
}

func (c *testElapsedClock) set(now time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type cacheTestAdapter struct{ calls int }

func (a *cacheTestAdapter) DispatchExternal(context.Context, GatewayOperation) error {
	a.calls++
	return nil
}

func TestCachedAuthorizerDenialPreventsExternalEffect(t *testing.T) {
	reader := &testAuthorizationReader{}
	reader.push(AuthorizationSnapshot{Allowed: false, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, nil)
	adapter := &cacheTestAdapter{}
	gateway := NewGateway(NewCachedOnlineAuthorizer(reader, &testElapsedClock{}), adapter)
	if err := gateway.ExecuteExternal(context.Background(), cacheTestOperation(), nil); err == nil {
		t.Fatal("denied authorization dispatched effect")
	}
	if adapter.calls != 0 {
		t.Fatalf("external dispatches = %d, want 0", adapter.calls)
	}
}

func (c *testElapsedClock) Elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type testAuthorizationReader struct {
	mu        sync.Mutex
	calls     int
	responses []authorizationResponse
	lastOp    GatewayOperation
	onRead    func()
}

type authorizationResponse struct {
	snapshot AuthorizationSnapshot
	err      error
}

func (r *testAuthorizationReader) ReadAuthorization(_ context.Context, op GatewayOperation) (AuthorizationSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.lastOp = cloneGatewayOperation(op)
	if r.onRead != nil {
		r.onRead()
	}
	if len(r.responses) == 0 {
		return AuthorizationSnapshot{}, fmt.Errorf("unexpected read")
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	return response.snapshot, response.err
}

func (r *testAuthorizationReader) push(snapshot AuthorizationSnapshot, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses = append(r.responses, authorizationResponse{snapshot: snapshot, err: err})
}

func (r *testAuthorizationReader) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func cacheTestOperation() GatewayOperation {
	digest, _ := domain.ParseDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	return GatewayOperation{
		RootID: "root", WorkOrderID: "work", AttemptID: "attempt", WorkerID: "worker",
		SessionID: "session", LeaseEpoch: 1, PolicyDigest: digest, Action: "read", Payload: []byte("secret payload"),
	}
}

func TestCachedAuthorizerHighAlwaysReadsAndFailsClosed(t *testing.T) {
	reader := &testAuthorizationReader{}
	clock := &testElapsedClock{}
	authorizer := NewCachedOnlineAuthorizer(reader, clock)
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskHigh, LeaseRemaining: time.Hour}, nil)
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskHigh, LeaseRemaining: time.Hour}, nil)
	reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
	for i := 0; i < 3; i++ {
		err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation())
		if (i < 2 && err != nil) || (i == 2 && err == nil) {
			t.Fatalf("call %d unexpected result: %v", i, err)
		}
	}
	if got := reader.callCount(); got != 3 {
		t.Fatalf("HIGH call count = %d, want 3", got)
	}
}

func TestCachedAuthorizerLowOutageUntilExactLeaseDeadline(t *testing.T) {
	reader := &testAuthorizationReader{}
	clock := &testElapsedClock{}
	authorizer := NewCachedOnlineAuthorizer(reader, clock)
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: 10 * time.Second}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
		t.Fatal(err)
	}
	reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
	clock.now = 10*time.Second - time.Nanosecond
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
		t.Fatalf("before deadline denied: %v", err)
	}
	reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
	clock.now = 10 * time.Second
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("authorization allowed at exact deadline")
	}
	if got := reader.callCount(); got != 3 {
		t.Fatalf("reader calls = %d, want 3", got)
	}
}

func TestCachedAuthorizerRecoveryRefreshAndInvalidate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fresh      AuthorizationSnapshot
		wantFresh  bool
		wantOutage bool
	}{
		{name: "fresh allow refreshes", fresh: AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, wantFresh: true, wantOutage: true},
		{name: "fresh deny invalidates", fresh: AuthorizationSnapshot{Allowed: false, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &testAuthorizationReader{}
			clock := &testElapsedClock{}
			authorizer := NewCachedOnlineAuthorizer(reader, clock)
			reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: 10 * time.Second}, nil)
			if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
				t.Fatal(err)
			}
			reader.push(tc.fresh, nil)
			clock.now = time.Second
			gotFresh := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()) == nil
			if gotFresh != tc.wantFresh {
				t.Fatalf("fresh result allowed=%v", gotFresh)
			}
			reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
			gotOutage := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()) == nil
			if gotOutage != tc.wantOutage {
				t.Fatalf("outage result allowed=%v", gotOutage)
			}
		})
	}
}

func TestCachedAuthorizerKeySeparatesEpochDigestAndAction(t *testing.T) {
	for _, mutate := range []func(*GatewayOperation){
		func(op *GatewayOperation) { op.LeaseEpoch++ },
		func(op *GatewayOperation) {
			op.PolicyDigest = domain.Digest("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
		},
		func(op *GatewayOperation) { op.Action = "other" },
	} {
		reader := &testAuthorizationReader{}
		clock := &testElapsedClock{}
		authorizer := NewCachedOnlineAuthorizer(reader, clock)
		reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, nil)
		if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
			t.Fatal(err)
		}
		reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
		op := cacheTestOperation()
		mutate(&op)
		if err := authorizer.AuthorizeOnline(context.Background(), op); err == nil {
			t.Fatal("different key used cached grant")
		}
	}
}

func TestCachedAuthorizerClockRewindInvalidatesCache(t *testing.T) {
	reader := &testAuthorizationReader{}
	clock := &testElapsedClock{}
	authorizer := NewCachedOnlineAuthorizer(reader, clock)
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
		t.Fatal(err)
	}
	clock.now = -time.Nanosecond
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("negative elapsed time allowed")
	}
	clock.now = 0
	reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("rewind did not invalidate cache")
	}
}

func TestCachedAuthorizerRejectsContextNilMalformedAndTypedNil(t *testing.T) {
	reader := &testAuthorizationReader{}
	clock := &testElapsedClock{}
	authorizer := NewCachedOnlineAuthorizer(reader, clock)
	if err := authorizer.AuthorizeOnline(nil, cacheTestOperation()); err == nil {
		t.Fatal("nil context allowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := authorizer.AuthorizeOnline(ctx, cacheTestOperation()); err == nil {
		t.Fatal("cancelled context allowed")
	}
	if err := authorizer.AuthorizeOnline(context.Background(), GatewayOperation{}); err == nil {
		t.Fatal("malformed tuple allowed")
	}
	var nilReader *testAuthorizationReader
	if err := NewCachedOnlineAuthorizer(nilReader, clock).AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("typed nil reader allowed")
	}
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRisk("UNKNOWN"), LeaseRemaining: time.Second}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("unknown risk allowed")
	}
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: 0}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("zero lease allowed")
	}
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: -time.Second}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("negative lease allowed")
	}
}

func TestCachedAuthorizerUnavailableOnlyAndContextCancelInvalidate(t *testing.T) {
	for _, failure := range []error{errors.New("other failure"), context.Canceled} {
		reader := &testAuthorizationReader{}
		clock := &testElapsedClock{}
		authorizer := NewCachedOnlineAuthorizer(reader, clock)
		reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, nil)
		if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err != nil {
			t.Fatal(err)
		}
		reader.push(AuthorizationSnapshot{}, failure)
		if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
			t.Fatal("non-unavailable error allowed")
		}
		reader.push(AuthorizationSnapshot{}, ErrAuthorizationUnavailable)
		if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
			t.Fatal("failed call retained cache")
		}
	}
}

func TestCachedAuthorizerOverflowAndPayloadIsolation(t *testing.T) {
	reader := &testAuthorizationReader{}
	clock := &testElapsedClock{now: time.Duration(math.MaxInt64)}
	authorizer := NewCachedOnlineAuthorizer(reader, clock)
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Nanosecond}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), cacheTestOperation()); err == nil {
		t.Fatal("deadline overflow allowed")
	}

	reader = &testAuthorizationReader{}
	clock = &testElapsedClock{}
	authorizer = NewCachedOnlineAuthorizer(reader, clock)
	op := cacheTestOperation()
	reader.push(AuthorizationSnapshot{Allowed: true, Risk: AuthorizationRiskLow, LeaseRemaining: time.Minute}, nil)
	if err := authorizer.AuthorizeOnline(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if string(op.Payload) != "secret payload" {
		t.Fatal("caller payload mutated")
	}
	reader.mu.Lock()
	reader.lastOp.Payload[0] = 'X'
	reader.mu.Unlock()
	if string(op.Payload) != "secret payload" {
		t.Fatal("reader mutation escaped request copy")
	}
	if reader.callCount() != 1 {
		t.Fatal("unexpected side-effecting read")
	}
}
