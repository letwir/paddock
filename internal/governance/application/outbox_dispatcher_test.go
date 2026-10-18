package application

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type outboxStoreFake struct {
	claims       []port.OutboxClaim
	claimErr     error
	ackErr       error
	acknowledged bool
	retryErr     error
	retryResult  port.OutboxRetryDisposition
	retryCode    string
	claimCalls   int
	events       *[]string
}

func (f *outboxStoreFake) Claim(context.Context, int) ([]port.OutboxClaim, error) {
	f.claimCalls++
	if f.events != nil {
		*f.events = append(*f.events, "claim")
	}
	return append([]port.OutboxClaim(nil), f.claims...), f.claimErr
}

func (f *outboxStoreFake) Ack(context.Context, string, string) (bool, error) {
	return f.acknowledged, f.ackErr
}

func (f *outboxStoreFake) Retry(_ context.Context, _, _, errorCode string) (port.OutboxRetryDisposition, error) {
	f.retryCode = errorCode
	return f.retryResult, f.retryErr
}

type eventPublisherFake struct {
	err    error
	events []domain.Event
}

func (p *eventPublisherFake) Publish(_ context.Context, event domain.Event) error {
	p.events = append(p.events, event.Clone())
	return p.err
}

type notificationListenerFake struct {
	wait   func(context.Context) error
	events *[]string
}

func (l *notificationListenerFake) Wait(ctx context.Context) error {
	if l.events != nil {
		*l.events = append(*l.events, "wait")
	}
	if l.wait != nil {
		return l.wait(ctx)
	}
	return nil
}

func (l *notificationListenerFake) Close(context.Context) error {
	if l.events != nil {
		*l.events = append(*l.events, "close")
	}
	return nil
}

type outboxNotifierFake struct {
	listeners []port.OutboxNotificationListener
	errs      []error
	events    *[]string
	calls     int
}

func (n *outboxNotifierFake) Listen(context.Context) (port.OutboxNotificationListener, error) {
	index := n.calls
	n.calls++
	if n.events != nil {
		*n.events = append(*n.events, "listen")
	}
	var listener port.OutboxNotificationListener
	if index < len(n.listeners) {
		listener = n.listeners[index]
	}
	var err error
	if index < len(n.errs) {
		err = n.errs[index]
	}
	return listener, err
}

func testOutboxClaim(t *testing.T) port.OutboxClaim {
	t.Helper()
	event, err := domain.NewEvent("event-1", "scope", "scope-1", 1, "Started", "event/1", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	return port.OutboxClaim{Event: event, ClaimToken: "123e4567-e89b-12d3-a456-426614174000", AttemptCount: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestOutboxDispatcherDispatchOnceAcknowledgesPublishedEvent(t *testing.T) {
	store := &outboxStoreFake{claims: []port.OutboxClaim{testOutboxClaim(t)}, acknowledged: true}
	publisher := &eventPublisherFake{}
	dispatcher, err := NewOutboxDispatcher(store, &outboxNotifierFake{}, publisher, 10)
	if err != nil {
		t.Fatal(err)
	}
	report, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Claimed != 1 || report.Acknowledged != 1 || report.Retried != 0 || len(publisher.events) != 1 || store.claimCalls != 1 {
		t.Fatalf("report=%+v published=%d claims=%d", report, len(publisher.events), store.claimCalls)
	}
}

func TestOutboxDispatcherRetryUsesSanitizedCode(t *testing.T) {
	store := &outboxStoreFake{claims: []port.OutboxClaim{testOutboxClaim(t)}, retryResult: port.OutboxRetryScheduled}
	publisher := &eventPublisherFake{err: errors.New("remote response contained sensitive details")}
	dispatcher, err := NewOutboxDispatcher(store, &outboxNotifierFake{}, publisher, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Claimed != 1 || report.Retried != 1 || report.DeadLettered != 0 || store.retryCode != outboxDeliveryFailureCode {
		t.Fatalf("report=%+v retry_code=%q", report, store.retryCode)
	}
	if store.retryCode == publisher.err.Error() {
		t.Fatal("raw publisher error was passed to persistent Outbox diagnostics")
	}
}

func TestOutboxDispatcherReportsStaleClaimAfterPublish(t *testing.T) {
	store := &outboxStoreFake{claims: []port.OutboxClaim{testOutboxClaim(t)}, acknowledged: false}
	dispatcher, err := NewOutboxDispatcher(store, &outboxNotifierFake{}, &eventPublisherFake{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Claimed != 1 || report.StaleClaims != 1 || report.Acknowledged != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestOutboxDispatcherListensBeforePollingAndPollsAfterTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []string
	store := &outboxStoreFake{events: &events}
	firstListener := &notificationListenerFake{events: &events, wait: func(context.Context) error { return context.DeadlineExceeded }}
	secondListener := &notificationListenerFake{events: &events, wait: func(context.Context) error {
		cancel()
		return context.Canceled
	}}
	notifier := &outboxNotifierFake{events: &events, listeners: []port.OutboxNotificationListener{firstListener, secondListener}}
	dispatcher, err := NewOutboxDispatcher(store, notifier, &eventPublisherFake{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = dispatcher.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v, want context cancellation", err)
	}
	wantPrefix := []string{"listen", "claim", "wait", "close", "listen", "claim", "wait", "close"}
	if len(events) < len(wantPrefix) || !reflect.DeepEqual(events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("Run order=%v, want prefix=%v", events, wantPrefix)
	}
	if notifier.calls != 2 || store.claimCalls != 2 {
		t.Fatalf("listen calls=%d claim calls=%d; wanted polling after the timeout", notifier.calls, store.claimCalls)
	}
}

func TestNewOutboxDispatcherRejectsInvalidConfiguration(t *testing.T) {
	store := &outboxStoreFake{}
	notifier := &outboxNotifierFake{listeners: []port.OutboxNotificationListener{&notificationListenerFake{}}}
	publisher := &eventPublisherFake{}
	for _, limit := range []int{0, port.MaxOutboxClaimBatch + 1} {
		if _, err := NewOutboxDispatcher(store, notifier, publisher, limit); err == nil {
			t.Fatalf("claim limit %d accepted", limit)
		}
	}
}
