package application

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/port"
)

type fakeTransactor struct {
	calls int
	fn    func(int) error
}

func (t *fakeTransactor) WithinTransaction(_ context.Context, fn func(port.GovernanceTx) error) error {
	t.calls++
	if err := fn(nil); err != nil {
		return err
	}
	return t.fn(t.calls)
}

type stateErr struct{ state string }

func (e stateErr) Error() string    { return "sql failure " + e.state }
func (e stateErr) SQLState() string { return e.state }

func TestRetryEventuallySucceeds(t *testing.T) {
	tx := &fakeTransactor{fn: func(call int) error {
		if call < 3 {
			return stateErr{"40001"}
		}
		return nil
	}}
	waits := 0
	err := retryWithWait(context.Background(), tx, 3, time.Second, func(port.GovernanceTx) error { return nil }, func(context.Context, time.Duration) error {
		waits++
		return nil
	})
	if err != nil || tx.calls != 3 || waits != 2 {
		t.Fatalf("err=%v calls=%d waits=%d; want nil, 3, 2", err, tx.calls, waits)
	}
}

func TestRetryWrappedRetryableSQLStatesRetryWholeTransaction(t *testing.T) {
	for _, sqlState := range []string{"40001", "40P01"} {
		t.Run(sqlState, func(t *testing.T) {
			wrapped := fmt.Errorf("transaction failed: %w", stateErr{sqlState})
			tx := &fakeTransactor{fn: func(call int) error {
				if call == 1 {
					return wrapped
				}
				return nil
			}}
			callbackCalls := 0
			err := Retry(context.Background(), tx, 3, 0, func(port.GovernanceTx) error {
				callbackCalls++
				return nil
			})
			if err != nil || tx.calls != 2 || callbackCalls != 2 {
				t.Fatalf("err=%v transactions=%d callbacks=%d; want nil, 2, 2", err, tx.calls, callbackCalls)
			}
		})
	}
}

func TestRetryStopsOnNonretryableErrorOnce(t *testing.T) {
	want := errors.New("bad input")
	tx := &fakeTransactor{fn: func(int) error { return want }}
	err := Retry(context.Background(), tx, 5, 0, func(port.GovernanceTx) error { return nil })
	if err != want || tx.calls != 1 {
		t.Fatalf("err=%v calls=%d; want original error and one call", err, tx.calls)
	}
}

func TestRetryStopsAtMaximumAttemptsAndPreservesFinalError(t *testing.T) {
	want := stateErr{"40P01"}
	tx := &fakeTransactor{fn: func(int) error { return want }}
	err := Retry(context.Background(), tx, 4, 0, func(port.GovernanceTx) error { return nil })
	if err != want || tx.calls != 4 {
		t.Fatalf("err=%v calls=%d; want final error and 4 calls", err, tx.calls)
	}
}

func TestRetryCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tx := &fakeTransactor{fn: func(int) error { return stateErr{"40001"} }}
	waits := 0
	err := retryWithWait(ctx, tx, 5, time.Hour, func(port.GovernanceTx) error { return nil }, func(ctx context.Context, _ time.Duration) error {
		waits++
		cancel()
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || tx.calls != 1 || waits != 1 {
		t.Fatalf("err=%v calls=%d waits=%d; want canceled, 1, 1", err, tx.calls, waits)
	}
}

func TestRetryUnknownSQLStateOnce(t *testing.T) {
	want := stateErr{"23505"}
	tx := &fakeTransactor{fn: func(int) error { return want }}
	err := Retry(context.Background(), tx, 5, 0, func(port.GovernanceTx) error { return nil })
	if err != want || tx.calls != 1 {
		t.Fatalf("err=%v calls=%d; want original error and one call", err, tx.calls)
	}
}

func TestRetryDoesNotSilentlySwallowWaitFailure(t *testing.T) {
	want := fmt.Errorf("wait failed")
	tx := &fakeTransactor{fn: func(int) error { return stateErr{"40001"} }}
	err := retryWithWait(context.Background(), tx, 3, time.Second, func(port.GovernanceTx) error { return nil }, func(context.Context, time.Duration) error { return want })
	if err != want || tx.calls != 1 {
		t.Fatalf("err=%v calls=%d; want wait error and one call", err, tx.calls)
	}
}

func TestRetryZeroAttemptsDoesNotInvokeCallback(t *testing.T) {
	tx := &fakeTransactor{fn: func(int) error { return nil }}
	err := Retry(context.Background(), tx, 0, 0, func(port.GovernanceTx) error { return nil })
	if !errors.Is(err, ErrInvalidMaxAttempts) || tx.calls != 0 {
		t.Fatalf("err=%v calls=%d; want invalid attempts and no call", err, tx.calls)
	}
}
