package application

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
	"reflect"
	"testing"
	"time"
)

type safetyFake struct {
	snapshot                                              port.ScopeSnapshot
	lockErr, validateErr, scopeErr, epochErr, insertErr   error
	eventErr                                              error
	scopeCalls, epochCalls, validateCalls, callbackErrors int
	epochExpected, epochNext                              domain.Epoch
	nextScope                                             port.ScopeSnapshot
	receipts                                              map[string]port.CommandReceipt
	events                                                []domain.Event
	operations                                            []string
}

func TestSafetyRequestDigestUsesJCSCanonicalPayload(t *testing.T) {
	first, err := domain.NewCanonicalRequest("command", "nonce", []byte(`{"action":"EMERGENCY_STOP","scope":"scope"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := domain.NewCanonicalRequest("command", "nonce", []byte("{ \"scope\" : \"scope\", \"action\" : \"EMERGENCY_STOP\" }"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() {
		t.Fatal("JSON-equivalent canonical payloads produced different request digests")
	}
}

func (*safetyFake) InsertPolicyBundle(context.Context, domain.CanonicalBundle, string, []byte) error {
	return errors.New("unexpected policy bundle insert")
}

func (f *safetyFake) LookupCommandReceipt(_ context.Context, id string) (port.CommandReceipt, bool, error) {
	r, ok := f.receipts[id]
	return r, ok, nil
}
func (f *safetyFake) InsertCommandReceipt(_ context.Context, r port.CommandReceipt) error {
	f.operations = append(f.operations, "receipt")
	if f.insertErr != nil {
		return f.insertErr
	}
	if f.receipts == nil {
		f.receipts = map[string]port.CommandReceipt{}
	}
	f.receipts[r.CommandID] = r
	return nil
}
func (f *safetyFake) AppendEvent(_ context.Context, event domain.Event) error {
	f.operations = append(f.operations, "event")
	if f.eventErr != nil {
		return f.eventErr
	}
	f.events = append(f.events, event.Clone())
	return nil
}
func (f *safetyFake) WithinTransaction(_ context.Context, fn func(port.GovernanceTx) error) error {
	previousScope := f.nextScope
	previousReceipts := make(map[string]port.CommandReceipt, len(f.receipts))
	for id, receipt := range f.receipts {
		receipt.Response = append([]byte(nil), receipt.Response...)
		previousReceipts[id] = receipt
	}
	previousEvents := make([]domain.Event, len(f.events))
	for i, event := range f.events {
		previousEvents[i] = event.Clone()
	}
	err := fn(f)
	if err != nil {
		f.callbackErrors++
		f.nextScope = previousScope
		f.receipts = previousReceipts
		f.events = previousEvents
	}
	return err
}
func (f *safetyFake) DatabaseTime(context.Context) (time.Time, error) { return time.Time{}, nil }
func (f *safetyFake) LockScope(context.Context, domain.ScopeID) (port.ScopeSnapshot, error) {
	if f.lockErr != nil {
		return port.ScopeSnapshot{}, f.lockErr
	}
	return f.snapshot, nil
}
func (f *safetyFake) LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (port.RolloutSnapshot, error) {
	return port.RolloutSnapshot{}, errors.New("unexpected rollout lock")
}
func (f *safetyFake) ValidateTargets(_ context.Context, _ domain.ScopeID, ids []domain.RootID) error {
	f.validateCalls++
	if !reflect.DeepEqual(ids, []domain.RootID{"root-a", "root-b"}) {
		return errors.New("unexpected roots")
	}
	return f.validateErr
}
func (f *safetyFake) CompareAndSwapScope(_ context.Context, old, next port.ScopeSnapshot) error {
	f.operations = append(f.operations, "scope")
	f.scopeCalls++
	if !reflect.DeepEqual(old, f.snapshot) {
		return errors.New("unexpected expected snapshot")
	}
	f.nextScope = next
	return f.scopeErr
}
func (f *safetyFake) CompareAndSwapRollout(context.Context, port.RolloutSnapshot, port.RolloutSnapshot) error {
	return errors.New("unexpected rollout CAS")
}
func (f *safetyFake) CompareAndSwapSecurityEpoch(_ context.Context, old, next domain.Epoch) error {
	f.operations = append(f.operations, "epoch")
	f.epochCalls++
	f.epochExpected = old
	f.epochNext = next
	return f.epochErr
}

func TestSafetyServiceStopPersistsQuorumTransition(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "stop", "nonce-fixture", nil)
	got, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs)
	if err != nil {
		t.Fatal(err)
	}
	if got.State.Mode != domain.ScopeSafeStop || got.State.SecurityEpoch != f.snapshot.SecurityEpoch+1 {
		t.Fatalf("%+v", got)
	}
	if !reflect.DeepEqual(f.operations, []string{"scope", "epoch", "receipt", "event"}) {
		t.Fatal(f.operations)
	}
	if len(f.events) != 1 {
		t.Fatalf("events=%d, want one safety Event", len(f.events))
	}
	event := f.events[0]
	wantPayload := `{"previous_scope_activation_epoch":4,"scope_activation_epoch":4,"previous_security_epoch":7,"security_epoch":8}`
	if event.ID() != "safety/stop" || event.AggregateKind() != "scope" || event.AggregateID() != "scope" || event.AggregateVersion() != 8 || event.Type() != "SafetyStopped" || event.SchemaVersion() != "paddock.safety-event/1" || string(event.Payload()) != wantPayload {
		t.Fatalf("unexpected safety-stop event: id=%q kind=%q aggregate=%q version=%d type=%q schema=%q payload=%s", event.ID(), event.AggregateKind(), event.AggregateID(), event.AggregateVersion(), event.Type(), event.SchemaVersion(), event.Payload())
	}
}
func TestSafetyServiceReleasePersistsSignedActivation(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeSafeStop)
	activation := domain.AuthorityState{Scope: f.snapshot.ScopeID, ScopeActivationEpoch: f.snapshot.ActivationEpoch + 1, SecurityEpoch: f.snapshot.SecurityEpoch + 1, Mode: domain.ScopeActive, DatabaseAvailable: true, Roots: f.snapshot.Roots}
	cmd, sigs := signSafety(t, k, domain.SafetyActionRelease, f.snapshot, "release", "nonce-fixture", &activation)
	got, err := s.Release(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", activation, sigs)
	if err != nil {
		t.Fatal(err)
	}
	if got.State.ScopeActivationEpoch != activation.ScopeActivationEpoch || f.scopeCalls != 1 || f.epochCalls != 1 {
		t.Fatalf("%+v", got)
	}
	if len(f.events) != 1 {
		t.Fatalf("events=%d, want one safety Event", len(f.events))
	}
	event := f.events[0]
	wantPayload := `{"previous_scope_activation_epoch":4,"scope_activation_epoch":5,"previous_security_epoch":7,"security_epoch":8}`
	if event.ID() != "safety/release" || event.AggregateKind() != "scope" || event.AggregateID() != "scope" || event.AggregateVersion() != 8 || event.Type() != "SafetyReleased" || event.SchemaVersion() != "paddock.safety-event/1" || string(event.Payload()) != wantPayload {
		t.Fatalf("unexpected safety-release event: id=%q kind=%q aggregate=%q version=%d type=%q schema=%q payload=%s", event.ID(), event.AggregateKind(), event.AggregateID(), event.AggregateVersion(), event.Type(), event.SchemaVersion(), event.Payload())
	}
}
func TestSafetyServiceFailuresDoNotAttemptCAS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		n     int
		epoch domain.Epoch
		mode  domain.ScopeMode
		db    bool
	}{{"quorum", 1, 7, domain.ScopeActive, true}, {"epoch", 2, 8, domain.ScopeActive, true}, {"state", 2, 7, domain.ScopeSafeStop, true}, {"db", 2, 7, domain.ScopeActive, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, k := safetyFixture(t, tc.mode)
			cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "cmd", "nonce-fixture", nil)
			sigs = sigs[:tc.n]
			if !tc.db {
				f.lockErr = domain.ErrDatabaseUnavailable
			}
			if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, tc.epoch, cmd, "nonce-fixture", sigs); err == nil {
				t.Fatal("expected failure")
			}
			if f.scopeCalls != 0 || f.epochCalls != 0 {
				t.Fatal("CAS attempted")
			}
		})
	}
}
func TestSafetyServiceTransactionErrors(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "cmd", "nonce-fixture", nil)
	f.scopeErr = errors.New("CAS failed")
	if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); !errors.Is(err, f.scopeErr) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Stop(ctx, f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestSafetyServiceNilInputs(t *testing.T) {
	var s *SafetyService
	if _, err := s.Stop(context.Background(), "scope", 0, "cmd", "nonce-fixture", nil); err == nil {
		t.Fatal("nil accepted")
	}
	s = NewSafetyService(nil, domain.SafetyQuorum{})
	if _, err := s.Stop(context.Background(), "scope", 0, "cmd", "nonce-fixture", nil); err == nil {
		t.Fatal("nil transactor accepted")
	}
}
func safetyFixture(t *testing.T, mode domain.ScopeMode) (*SafetyService, *safetyFake, []ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	signers := make([]domain.SafetySigner, 3)
	for i := range keys {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = priv
		signers[i] = domain.SafetySigner{ID: string(rune('a' + i)), PublicKey: pub}
	}
	q, err := domain.NewSafetyQuorum(signers)
	if err != nil {
		t.Fatal(err)
	}
	f := &safetyFake{snapshot: port.ScopeSnapshot{ScopeID: "scope", ActivationEpoch: 4, Mode: mode, SecurityEpoch: 7, Roots: map[domain.RootID]domain.RootAuthority{"root-a": {Policy: domain.PolicyBinding{Digest: testDigest()}, AuthorizationEpoch: 1}, "root-b": {Policy: domain.PolicyBinding{Digest: testDigest()}, AuthorizationEpoch: 2}}}}
	return NewSafetyService(f, q), f, keys
}
func signSafety(t *testing.T, keys []ed25519.PrivateKey, action domain.SafetyAction, s port.ScopeSnapshot, cmd, nonce string, activation *domain.AuthorityState) (string, []domain.SafetySignature) {
	t.Helper()
	var msg []byte
	var err error
	if activation == nil {
		msg, err = domain.SafetyApprovalMessage(action, s.ScopeID, s.SecurityEpoch, cmd, nonce)
	} else {
		d, e := domain.ActivationDigest(*activation)
		if e != nil {
			t.Fatal(e)
		}
		msg, err = domain.SafetyApprovalMessage(action, s.ScopeID, s.SecurityEpoch, cmd, nonce, d)
	}
	if err != nil {
		t.Fatal(err)
	}
	out := []domain.SafetySignature{}
	for i := 0; i < 2; i++ {
		out = append(out, domain.SafetySignature{SignerID: string(rune('a' + i)), Signature: ed25519.Sign(keys[i], msg)})
	}
	return cmd, out
}
func testDigest() domain.Digest {
	return domain.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

func TestSafetyReceiptIdempotencyConflictAndValidation(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "receipt", "nonce-fixture", nil)
	first, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot = f.nextScope
	f.snapshot.SecurityEpoch = f.epochNext
	second, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch-1, cmd, "nonce-fixture", sigs)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("%+v %v", second, err)
	}
	changed := append([]domain.SafetySignature(nil), sigs...)
	changed[0].Signature = append([]byte(nil), changed[0].Signature...)
	changed[0].Signature[0] ^= 1
	if _, err = s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch-1, cmd, "nonce-fixture", changed); err == nil {
		t.Fatal("digest conflict accepted")
	}
	if _, err = s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch-1, cmd, "different-nonce", sigs); err == nil {
		t.Fatal("changed nonce accepted for an existing command ID")
	}
	if f.scopeCalls != 1 || f.epochCalls != 1 {
		t.Fatal("CAS on replay/conflict")
	}
	r := f.receipts[cmd]
	r.Response = []byte("{")
	f.receipts[cmd] = r
	if _, err = s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch-1, cmd, "nonce-fixture", sigs); err == nil {
		t.Fatal("malformed receipt accepted")
	}
}
func TestSafetyReceiptTamperedAndSuperseded(t *testing.T) {
	for _, tamper := range []bool{true, false} {
		s, f, k := safetyFixture(t, domain.ScopeActive)
		cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "receipt", "nonce-fixture", nil)
		if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); err != nil {
			t.Fatal(err)
		}
		f.snapshot = f.nextScope
		f.snapshot.SecurityEpoch = f.epochNext
		r := f.receipts[cmd]
		if tamper {
			r.Response = append([]byte(nil), r.Response...)
			r.Response[0] ^= 1
			f.receipts[cmd] = r
		} else {
			f.snapshot.ActivationEpoch++
		}
		if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch-1, cmd, "nonce-fixture", sigs); err == nil {
			t.Fatal("invalid receipt/current state accepted")
		}
	}
}
func TestSafetyReceiptDBUnavailableAndStoreFailure(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "receipt", "nonce-fixture", nil)
	f.lockErr = domain.ErrDatabaseUnavailable
	if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); !errors.Is(err, domain.ErrDatabaseUnavailable) {
		t.Fatal(err)
	}
	f.lockErr = nil
	f.insertErr = errors.New("receipt write failed")
	if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); !errors.Is(err, f.insertErr) {
		t.Fatal(err)
	}
	if f.scopeCalls != 1 || f.epochCalls != 1 {
		t.Fatal("expected both CAS before receipt failure")
	}
	if f.nextScope.ScopeID != "" || len(f.receipts) != 0 || len(f.events) != 0 {
		t.Fatalf("transactional writes survived receipt failure: next_scope=%+v receipts=%d events=%d", f.nextScope, len(f.receipts), len(f.events))
	}
}

func TestSafetyServiceAppendEventFailureRollsBackTransitionAndReceipt(t *testing.T) {
	s, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "event-failure", "nonce-fixture", nil)
	f.eventErr = errors.New("event append failed")
	if _, err := s.Stop(context.Background(), f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", sigs); !errors.Is(err, f.eventErr) {
		t.Fatalf("Stop error=%v, want event failure", err)
	}
	if !reflect.DeepEqual(f.operations, []string{"scope", "epoch", "receipt", "event"}) {
		t.Fatalf("operations=%v", f.operations)
	}
	if f.nextScope.ScopeID != "" || len(f.receipts) != 0 || len(f.events) != 0 {
		t.Fatalf("transactional writes survived event failure: next_scope=%+v receipts=%d events=%d", f.nextScope, len(f.receipts), len(f.events))
	}
}
func TestSafetyRequestDigestSignatureOrderAndContent(t *testing.T) {
	_, f, k := safetyFixture(t, domain.ScopeActive)
	cmd, sigs := signSafety(t, k, domain.SafetyActionStop, f.snapshot, "digest", "nonce-fixture", nil)
	a, e := safetyRequestDigest(domain.SafetyActionStop, f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", nil, sigs)
	if e != nil {
		t.Fatal(e)
	}
	b, e := safetyRequestDigest(domain.SafetyActionStop, f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", nil, []domain.SafetySignature{sigs[1], sigs[0]})
	if e != nil {
		t.Fatal(e)
	}
	changed := append([]domain.SafetySignature(nil), sigs...)
	changed[0].Signature = append([]byte(nil), changed[0].Signature...)
	changed[0].Signature[0] ^= 1
	c, e := safetyRequestDigest(domain.SafetyActionStop, f.snapshot.ScopeID, f.snapshot.SecurityEpoch, cmd, "nonce-fixture", nil, changed)
	if e != nil {
		t.Fatal(e)
	}
	if a == b || a == c {
		t.Fatal("signature order/content omitted from digest")
	}
}
