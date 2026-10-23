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

func newHoldExtendFixture(t *testing.T) (*SafetyService, *monitoringTxFake, HoldExtendRequest) {
	t.Helper()
	monitor, tx, record := newMonitoringFixture(t)
	record.Gate.Checks = nil
	if _, err := monitor.RecordDecision(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	safety, _, keys := safetyFixture(t, domain.ScopeActive)
	safety.transactor = tx
	q := HoldExtendRequest{CommandID: "extend", Nonce: "extension-nonce", Scope: tx.scope.ScopeID, Rollout: tx.rollout.ID, ExpectedSecurityEpoch: tx.scope.SecurityEpoch, ExpectedDecisionRevision: 1}
	message, err := domain.HoldExtendApprovalMessage(rolloutDomain(tx.scope, tx.rollout), q.ExpectedSecurityEpoch, q.CommandID, q.Nonce, domain.MonitoringExtendedCap)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		q.Signatures = append(q.Signatures, domain.SafetySignature{SignerID: string(rune('a' + i)), Signature: ed25519.Sign(keys[i], message)})
	}
	return safety, tx, q
}

func TestSafetyHoldExtendCurrentRevisionAndReplay(t *testing.T) {
	svc, tx, q := newHoldExtendFixture(t)
	oldEpoch, oldRevision := tx.scope.SecurityEpoch, tx.rollout.Monitoring.DecisionRevision
	out, err := svc.HoldExtend(context.Background(), q)
	if err != nil || !out.Monitoring.ExtensionUsed || out.Monitoring.HoldBudget != domain.MonitoringExtendedCap || out.Monitoring.DecisionRevision != oldRevision || tx.scope.SecurityEpoch != oldEpoch {
		t.Fatal(out, err)
	}
	if len(tx.events) != 2 || tx.events[1].Type() != "MonitoringHoldExtended" || len(tx.receipts) != 2 {
		t.Fatal("missing atomic extension receipt/event")
	}
	if replay, err := svc.HoldExtend(context.Background(), q); err != nil || !reflect.DeepEqual(replay, out) || len(tx.events) != 2 {
		t.Fatal("extension replay changed state", err)
	}
	q.CommandID = "extend-again"
	if _, err := svc.HoldExtend(context.Background(), q); err == nil || tx.rollout.Monitoring.HoldBudget != domain.MonitoringExtendedCap || len(tx.events) != 2 {
		t.Fatal("second extension accepted", err)
	}
}

func TestSafetyHoldExtendRejectsStaleExpiredAndInvalidQuorum(t *testing.T) {
	for _, change := range []string{"stale revision", "rerecorded equal time", "expired", "duplicate signer", "invalid signature", "one signer", "security epoch"} {
		t.Run(change, func(t *testing.T) {
			svc, tx, q := newHoldExtendFixture(t)
			switch change {
			case "stale revision":
				q.ExpectedDecisionRevision = 0
			case "rerecorded equal time":
				tx.rollout.Monitoring.DecisionRevision++
				q.ExpectedDecisionRevision++
			case "expired":
				tx.now = tx.rollout.Monitoring.HoldDeadline
			case "duplicate signer":
				q.Signatures[1] = q.Signatures[0]
			case "invalid signature":
				q.Signatures[1].Signature[0] ^= 1
			case "one signer":
				q.Signatures = q.Signatures[:1]
			case "security epoch":
				q.ExpectedSecurityEpoch++
			}
			old := tx.rollout
			if _, err := svc.HoldExtend(context.Background(), q); err == nil {
				t.Fatal("invalid approval accepted")
			}
			if !reflect.DeepEqual(old, tx.rollout) || len(tx.events) != 1 {
				t.Fatal("denied approval changed monitoring")
			}
		})
	}
}

func TestSafetyHoldExtendAtomicFailuresAndUnknownCommit(t *testing.T) {
	for _, operation := range []string{"DB clock", "rollout CAS", "MonitoringHoldExtended", "receipt", "commit"} {
		t.Run(operation, func(t *testing.T) {
			svc, tx, q := newHoldExtendFixture(t)
			old := tx.rollout
			tx.fail = operation
			if operation == "commit" {
				tx.commitErr = tx.cause
			}
			if _, err := svc.HoldExtend(context.Background(), q); !errors.Is(err, tx.cause) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tx.rollout, old) || len(tx.events) != 1 || len(tx.receipts) != 1 {
				t.Fatal("partial extension persisted")
			}
		})
	}
	svc, tx, q := newHoldExtendFixture(t)
	tx.commitErr = errors.Join(port.ErrCommitOutcomeUnknown, tx.cause)
	if _, err := svc.HoldExtend(context.Background(), q); !errors.Is(err, port.ErrCommitOutcomeUnknown) {
		t.Fatal(err)
	}
	tx.commitErr = nil
	if out, err := svc.HoldExtend(context.Background(), q); err != nil || out.Monitoring.DecisionRevision != 1 || len(tx.events) != 2 {
		t.Fatal("unknown extension replay reapplied", err)
	}
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

func TestSafetyNegativeReceiptsPreserveAuthorizationAndReplay(t *testing.T) {
	for _, action := range []domain.SafetyAction{domain.SafetyActionStop, domain.SafetyActionRelease} {
		t.Run(string(action), func(t *testing.T) {
			mode := domain.ScopeActive
			if action == domain.SafetyActionRelease {
				mode = domain.ScopeSafeStop
			}
			s, f, _ := safetyFixture(t, mode)
			activation := domain.AuthorityState{Scope: f.snapshot.ScopeID, ScopeActivationEpoch: f.snapshot.ActivationEpoch + 1, SecurityEpoch: f.snapshot.SecurityEpoch + 1, Mode: domain.ScopeActive, DatabaseAvailable: true, Roots: f.snapshot.Roots}
			nonce := "negative-nonce"
			invoke := func() error {
				if action == domain.SafetyActionStop {
					_, err := s.Stop(context.Background(), "scope", 7, "negative-safety", nonce, nil)
					return err
				}
				_, err := s.Release(context.Background(), "scope", 7, "negative-safety", nonce, activation, nil)
				return err
			}
			first := invoke()
			if CommandErrorResponse(first).Code != "FORBIDDEN" || !errors.Is(first, domain.ErrInvalidApproval) || f.scopeCalls != 0 || f.epochCalls != 0 || len(f.events) != 0 {
				t.Fatalf("authorization changed: %v %+v", first, f)
			}
			original := f.receipts["negative-safety"]
			if original.Status != "REJECTED" || len(original.Response) == 0 {
				t.Fatalf("denial not persisted: %+v", original)
			}
			// A negative replay never becomes authorized because current state or
			// quorum circumstances changed. It does not need a state transition.
			f.lockErr = domain.ErrDatabaseUnavailable
			if second := invoke(); !reflect.DeepEqual(CommandErrorResponse(first), CommandErrorResponse(second)) {
				t.Fatalf("unstable negative replay: %v", second)
			}
			nonce = "modified-nonce"
			if err := invoke(); CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
				t.Fatalf("modified Safety payload accepted: %v", err)
			}
			expired := original
			expired.Expired, expired.Response = true, []byte(port.ReceiptTombstoneResponse)
			f.receipts["negative-safety"] = expired
			if err := invoke(); errors.Is(err, port.ErrReceiptExpired) || CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
				t.Fatalf("expiry hid conflict: %v", err)
			}
			nonce = "negative-nonce"
			if err := invoke(); !errors.Is(err, port.ErrReceiptExpired) {
				t.Fatalf("expired denial not returned: %v", err)
			}
			if !reflect.DeepEqual(f.receipts["negative-safety"], expired) || !reflect.DeepEqual(f.operations, []string{"receipt"}) {
				t.Fatal("Safety denial replay mutated state or reused command ID")
			}
		})
	}
}

func TestSafetySuccessfulReceiptExpiryDoesNotReapplyTransition(t *testing.T) {
	s, f, keys := safetyFixture(t, domain.ScopeActive)
	id, sigs := signSafety(t, keys, domain.SafetyActionStop, f.snapshot, "expired-stop", "nonce", nil)
	if _, err := s.Stop(context.Background(), "scope", 7, id, "nonce", sigs); err != nil {
		t.Fatal(err)
	}
	r := f.receipts[id]
	r.Expired, r.Response = true, []byte(port.ReceiptTombstoneResponse)
	f.receipts[id] = r
	if _, err := s.Stop(context.Background(), "scope", 7, id, "nonce", sigs); !errors.Is(err, port.ErrReceiptExpired) {
		t.Fatal(err)
	}
	if f.scopeCalls != 1 || f.epochCalls != 1 || len(f.events) != 1 || !reflect.DeepEqual(f.receipts[id], r) {
		t.Fatal("expired success was reapplied")
	}
}

func TestSafetyMalformedActivationReceiptBindsCompleteRejectedPayload(t *testing.T) {
	s, f, _ := safetyFixture(t, domain.ScopeSafeStop)
	activation := domain.AuthorityState{Scope: "scope"} // no valid mode or Roots
	invoke := func() error {
		_, err := s.Release(context.Background(), "scope", 7, "malformed-activation", "nonce", activation, nil)
		return err
	}
	first := invoke()
	if !errors.Is(first, domain.ErrInvalidApproval) || CommandErrorResponse(first).Code != "FORBIDDEN" {
		t.Fatalf("invalid activation accepted: %v", first)
	}
	original := f.receipts["malformed-activation"]
	if original.Status != "REJECTED" || f.scopeCalls != 0 || f.epochCalls != 0 {
		t.Fatal("malformed activation affected authority")
	}
	if second := invoke(); !reflect.DeepEqual(CommandErrorResponse(first), CommandErrorResponse(second)) {
		t.Fatal("malformed activation denial did not replay")
	}
	activation.SecurityEpoch++
	if err := invoke(); CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
		t.Fatalf("malformed activation payload was not bound: %v", err)
	}
	if !reflect.DeepEqual(f.receipts["malformed-activation"], original) {
		t.Fatal("modified activation replaced terminal denial")
	}
}
