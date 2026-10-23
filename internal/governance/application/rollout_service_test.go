package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type constructorTx struct{ port.RolloutTransactor }

func TestDistinctProposalsUseProposalAggregates(t *testing.T) {
	tx := &eventCaptureTx{}
	for _, id := range []string{"proposal-a", "proposal-b"} {
		result := ProposeResult{CommandID: "command-" + id, ProposalID: id, BundleDigest: domain.Digest("digest")}
		if err := persistCommand(context.Background(), tx, result.CommandID, "request", result, "PolicyProposed", "scope-a", 1); err != nil {
			t.Fatal(err)
		}
	}
	if len(tx.events) != 2 {
		t.Fatalf("events=%d", len(tx.events))
	}
	for i, want := range []string{"proposal-a", "proposal-b"} {
		if tx.events[i].AggregateKind() != "proposal" || tx.events[i].AggregateID() != want || tx.events[i].AggregateVersion() != 1 {
			t.Fatalf("event %d: kind=%q id=%q version=%d", i, tx.events[i].AggregateKind(), tx.events[i].AggregateID(), tx.events[i].AggregateVersion())
		}
	}
}

type eventCaptureTx struct {
	port.RolloutTx
	events []domain.Event
}

func (f *eventCaptureTx) InsertCommandReceipt(context.Context, port.CommandReceipt) error { return nil }
func (f *eventCaptureTx) AppendEvent(_ context.Context, e domain.Event) error {
	f.events = append(f.events, e)
	return nil
}

func kernelFixture() domain.KernelSnapshot {
	return domain.KernelSnapshot{SchemaVersion: domain.KernelSnapshotSchema, Version: 1,
		Signers:        []domain.KernelSigner{{ID: "signer", PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}},
		Thresholds:     []domain.TierThreshold{{Tier: domain.TierG0, Threshold: 1}, {Tier: domain.TierG1, Threshold: 1}},
		Capabilities:   []string{"governance"},
		IssuerCeilings: []domain.IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"governance"}}}}
}

func TestNewRolloutServiceValidatesAndPinsDeepCopy(t *testing.T) {
	k := kernelFixture()
	d, err := k.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewRolloutService(constructorTx{}, nil, nil, k, "bad"); err == nil {
		t.Fatal("mismatched digest accepted")
	}
	malformed := cloneKernelSnapshot(k)
	malformed.Signers[0].PublicKey = []byte{1}
	badDigest, err := malformed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewRolloutService(constructorTx{}, nil, nil, malformed, badDigest); err == nil {
		t.Fatal("malformed snapshot accepted")
	}
	svc, err := NewRolloutService(constructorTx{}, nil, nil, k, d)
	if err != nil {
		t.Fatal(err)
	}
	k.Signers[0].PublicKey[0] = 9
	k.Thresholds[0].Threshold = 20
	k.Capabilities[0] = "changed"
	k.IssuerCeilings[0].Capabilities[0] = "changed"
	if err := svc.checkKernel(); err != nil {
		t.Fatalf("caller mutation changed pin: %v", err)
	}
	svc.kernel.Signers[0].PublicKey[0]++
	if err := svc.checkKernel(); err == nil {
		t.Fatal("mutated internal pin was not detected")
	}
}

func TestRolloutRequestsDoNotAcceptKernelSubstitutionAndContextsBindDigest(t *testing.T) {
	for _, v := range []any{StartCanaryRequest{}, PromoteRequest{}} {
		typ := reflect.TypeOf(v)
		if _, ok := typ.FieldByName("Kernel"); ok {
			t.Fatalf("%s permits request-supplied Kernel", typ.Name())
		}
	}
	q := PromoteRequest{CommandID: "c", Nonce: "n", Scope: "s", Rollout: "r", Candidate: domain.DomainCandidate{IssuerID: "i", ProposalID: "p", Nonce: "n"}}
	a, err := promoteCommandDigest(q, domain.ProposalContext{ProposerID: "candidate"}, domain.ProposalContext{ProposerID: "transition"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := promoteCommandDigest(q, domain.ProposalContext{ProposerID: "other"}, domain.ProposalContext{ProposerID: "transition"})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("candidate proposer identity was not bound to command digest")
	}
	c, err := promoteCommandDigest(q, domain.ProposalContext{ProposerID: "candidate"}, domain.ProposalContext{ProposerID: "other-transition"})
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("transition proposer identity was not bound to command digest")
	}
}

func TestRolloutRequestDigestsBindOperationAndExpectedState(t *testing.T) {
	base := RollbackRequest{CommandID: "cmd-1", Nonce: "nonce-1", Scope: domain.ScopeID("scope-a"), Rollout: domain.RolloutID("rollout-a"), ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 40, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: map[domain.RootID]domain.Epoch{"root-a": 3}}
	first, err := commandDigest(base.CommandID, base.Nonce, base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.ExpectedScopeEpoch++
	second, err := commandDigest(changed.CommandID, changed.Nonce, changed)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different expected state must have a different command digest")
	}
}

// Build the expected digest independently from the public request JSON. Only
// the otherwise-empty Bundle is replaced; every request/proposer field stays.
func expectedBundleCommandDigest(t *testing.T, id, nonce string, payload any, bundle domain.CanonicalBundle, candidate bool) domain.Digest {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	replace := func(object map[string]json.RawMessage) {
		t.Helper()
		if string(object["Bundle"]) != "{}" {
			t.Fatalf("public Bundle serialization changed: %s", object["Bundle"])
		}
		object["Bundle"], err = json.Marshal(map[string]any{
			"SchemaVersion": bundle.SchemaVersion(), "BundleID": bundle.BundleID(), "Nonce": bundle.Nonce(),
			"CanonicalBytes": bundle.CanonicalBytes(), "SigningBytes": bundle.SigningBytes(), "Digest": bundle.Digest(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	request := fields
	if candidate {
		request = nil
		if err := json.Unmarshal(fields["Request"], &request); err != nil {
			t.Fatal(err)
		}
	}
	if candidate {
		var c map[string]json.RawMessage
		if err := json.Unmarshal(request["Candidate"], &c); err != nil {
			t.Fatal(err)
		}
		replace(c)
		request["Candidate"], err = json.Marshal(c)
	} else {
		replace(request)
	}
	if err != nil {
		t.Fatal(err)
	}
	if candidate {
		fields["Request"], err = json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	r, err := domain.NewCanonicalRequest(id, nonce, b)
	if err != nil {
		t.Fatal(err)
	}
	return r.Digest()
}

func TestRolloutProductionDigestsBindBundleAndReplayBeforeWrites(t *testing.T) {
	for _, operation := range []string{"propose", "start", "promote"} {
		for _, change := range []string{"payload", "schema"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := newRolloutFixture(t)
				var invoke func() (any, error)
				var payload func() any
				var bundle *domain.CanonicalBundle
				var id, nonce string
				switch operation {
				case "propose":
					calls := []string{}
					now, _ := f.tx.DatabaseTime(context.Background())
					resolver := bundleResolverFake{calls: &calls, key: BundleSigningKey{KeyID: "bundle-key", PublicKey: f.key.Public().(ed25519.PublicKey), ValidFrom: now, ValidUntil: now.Add(time.Hour)}}
					f.service.bundles = NewBundleRegistrationService(bundleTransactorFake{calls: &calls}, resolver)
					q := ProposeRequest{CommandID: "propose", Nonce: "propose-nonce", Scope: "scope", ProposalID: "proposal", ProposerID: "author", BundleKeyID: "bundle-key", Bundle: f.request.Candidate.Bundle, Signature: ed25519.Sign(f.key, f.request.Candidate.Bundle.SigningBytes())}
					id, nonce, bundle = q.CommandID, q.Nonce, &q.Bundle
					payload = func() any { return q }
					invoke = func() (any, error) { return f.service.Propose(context.Background(), q) }
				case "start":
					f.tx.scope.LiveRolloutID = nil
					f.tx.scope.ActivationEpoch = 40
					r := f.tx.scope.Roots["root-b"]
					r.AuthorizationEpoch = 5
					r.Policy = f.tx.scope.Roots["root-a"].Policy
					f.tx.scope.Roots["root-b"] = r
					q := StartCanaryRequest{CommandID: "start", Nonce: "start-nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: 7, Approvals: f.request.CandidateApprovals}
					id, nonce, bundle = q.CommandID, q.Nonce, &q.Candidate.Bundle
					payload = func() any {
						return struct {
							Request  StartCanaryRequest
							Proposer domain.ProposalContext
						}{q, f.candidateProposer}
					}
					invoke = func() (any, error) { return f.service.StartCanary(context.Background(), q, f.candidateProposer) }
				case "promote":
					id, nonce, bundle = f.request.CommandID, f.request.Nonce, &f.request.Candidate.Bundle
					payload = func() any {
						return struct {
							Request                               PromoteRequest
							CandidateProposer, TransitionProposer domain.ProposalContext
						}{f.request, f.candidateProposer, f.transitionProposer}
					}
					invoke = func() (any, error) { return f.promote() }
				}
				marshalPublic := func() []byte {
					t.Helper()
					b, err := json.Marshal(payload())
					if err != nil {
						t.Fatal(err)
					}
					return b
				}
				publicJSON := marshalPublic()
				wantDigest := expectedBundleCommandDigest(t, id, nonce, payload(), *bundle, operation != "propose")
				out, err := invoke()
				if err != nil {
					t.Fatal(err)
				}
				receipt := f.tx.receipts[id]
				if receipt.RequestDigest != wantDigest {
					t.Fatalf("production digest=%s want=%s", receipt.RequestDigest, wantDigest)
				}
				// Equivalent JSON yields the same canonical Bundle and replays the
				// stored result, even though the first call changed locked state.
				*bundle = testBundle(t, " { \"rule\" : \"candidate\" } ")
				writes := len(f.tx.writes)
				if replay, err := invoke(); err != nil || !reflect.DeepEqual(replay, out) || len(f.tx.writes) != writes {
					t.Fatalf("replay=%+v err=%v writes=%v", replay, err, f.tx.writes)
				}
				if change == "payload" {
					*bundle = testBundle(t, `{"rule":"changed"}`)
				} else {
					*bundle, err = domain.NewCanonicalBundle("paddock.bundle/2", bundle.CanonicalBytes())
					if err != nil {
						t.Fatal(err)
					}
				}
				// Leave signatures, approval digests, contexts and every public
				// field untouched: only the invisible Bundle has changed.
				if !bytes.Equal(publicJSON, marshalPublic()) {
					t.Fatal("test changed more than the private Bundle")
				}
				changedDigest := expectedBundleCommandDigest(t, id, nonce, payload(), *bundle, operation != "propose")
				if changedDigest == receipt.RequestDigest {
					t.Fatal("changed Bundle did not change expected digest")
				}
				commits := f.tx.commits
				_, err = invoke()
				requireFailureKind(t, err, FailureInvalid)
				if CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
					t.Fatalf("expected receipt conflict before approval/state validation, got %v", err)
				}
				if len(f.tx.writes) != writes || f.tx.commits != commits+1 || !reflect.DeepEqual(receipt, f.tx.receipts[id]) {
					t.Fatalf("conflict changed persistence: writes=%v commits=%d receipt=%+v", f.tx.writes, f.tx.commits, f.tx.receipts[id])
				}
			})
		}
	}
}

// rolloutTxFake counts attempts, not just committed changes: rejection must not
// mutate business state, even if the transaction would roll back.
type rolloutTxFake struct {
	port.RolloutTx
	scope                  port.ScopeSnapshot
	rollout                port.RolloutSnapshot
	begins, commits, reads int
	writes                 []string
	receipts               map[string]port.CommandReceipt
	events                 []domain.Event
}

func (f *rolloutTxFake) WithinRolloutTransaction(ctx context.Context, fn func(port.RolloutTx) error) error {
	f.begins++
	err := fn(f)
	if err == nil {
		f.commits++
	}
	return err
}
func (f *rolloutTxFake) LockScope(context.Context, domain.ScopeID) (port.ScopeSnapshot, error) {
	f.reads++
	return f.scope, nil
}
func (f *rolloutTxFake) LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (port.RolloutSnapshot, error) {
	f.reads++
	return f.rollout, nil
}
func (f *rolloutTxFake) ValidateTargets(context.Context, domain.ScopeID, []domain.RootID) error {
	f.reads++
	return nil
}
func (f *rolloutTxFake) LookupCommandReceipt(_ context.Context, id string) (port.CommandReceipt, bool, error) {
	f.reads++
	r, ok := f.receipts[id]
	return r, ok, nil
}
func (f *rolloutTxFake) DatabaseTime(context.Context) (time.Time, error) {
	f.reads++
	return time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nil
}
func (f *rolloutTxFake) InsertPolicyBundle(context.Context, domain.CanonicalBundle, string, []byte) error {
	f.writes = append(f.writes, "bundle")
	return nil
}
func (f *rolloutTxFake) CreateRollout(_ context.Context, r port.RolloutSnapshot) error {
	f.writes = append(f.writes, "create")
	f.rollout = r
	return nil
}
func (f *rolloutTxFake) CompareAndSwapScope(_ context.Context, expected, next port.ScopeSnapshot) error {
	f.writes = append(f.writes, "scope CAS")
	if !reflect.DeepEqual(expected, f.scope) {
		return port.ErrStaleWrite
	}
	f.scope = next
	return nil
}
func (f *rolloutTxFake) CompareAndSwapRollout(_ context.Context, expected, next port.RolloutSnapshot) error {
	f.writes = append(f.writes, "rollout CAS")
	if !reflect.DeepEqual(expected, f.rollout) {
		return port.ErrStaleWrite
	}
	f.rollout = next
	return nil
}
func (f *rolloutTxFake) CompareAndSwapSecurityEpoch(context.Context, domain.Epoch, domain.Epoch) error {
	f.writes = append(f.writes, "security CAS")
	return nil
}
func (f *rolloutTxFake) InsertCommandReceipt(_ context.Context, r port.CommandReceipt) error {
	f.writes = append(f.writes, "receipt")
	if f.receipts == nil {
		f.receipts = map[string]port.CommandReceipt{}
	}
	f.receipts[r.CommandID] = r
	return nil
}
func (f *rolloutTxFake) AppendEvent(_ context.Context, e domain.Event) error {
	f.writes = append(f.writes, "event/outbox")
	for _, old := range f.events {
		if old.AggregateKind() == e.AggregateKind() && old.AggregateID() == e.AggregateID() && old.AggregateVersion() == e.AggregateVersion() {
			return errors.New("duplicate aggregate version")
		}
	}
	f.events = append(f.events, e)
	return nil
}

// Test-only keys are derived locally from fixed seeds; no external key source.
type rolloutFixture struct {
	tx                                    *rolloutTxFake
	service                               *RolloutService
	kernel                                domain.KernelSnapshot
	pin                                   domain.Digest
	key                                   ed25519.PrivateKey
	request                               PromoteRequest
	candidateProposer, transitionProposer domain.ProposalContext
}

func testBundle(t *testing.T, payload string) domain.CanonicalBundle {
	t.Helper()
	b, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func newRolloutFixture(t *testing.T) *rolloutFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	k := kernelFixture()
	k.Signers[0].PublicKey = append([]byte(nil), key.Public().(ed25519.PublicKey)...)
	pin, err := k.Digest()
	if err != nil {
		t.Fatal(err)
	}
	base := testBundle(t, `{"rule":"baseline"}`).Digest()
	candidate := domain.DomainCandidate{Bundle: testBundle(t, `{"rule":"candidate"}`), Tier: domain.TierG0, IssuerID: "issuer", ProposalID: "proposal", Nonce: "candidate-nonce", CapabilityIDs: []string{"governance"}}
	rid, target := domain.RolloutID("rollout"), domain.RootID("root-b")
	tx := &rolloutTxFake{scope: port.ScopeSnapshot{ScopeID: "scope", ActivationEpoch: 41, SecurityEpoch: 7, Mode: domain.ScopeActive, BaselineBundle: &base, LiveRolloutID: &rid, Roots: map[domain.RootID]domain.RootAuthority{
		"root-a": {Policy: domain.PolicyBinding{Digest: base}, AuthorizationEpoch: 3},
		"root-b": {Policy: domain.PolicyBinding{Digest: candidate.Bundle.Digest()}, AuthorizationEpoch: 6},
	}}, rollout: port.RolloutSnapshot{ID: rid, Scope: "scope", State: domain.RolloutCanary, TargetRoot: &target, BaseActivationEpoch: 40, LastActivationEpoch: 41, BaseSecurityEpoch: 7, Targets: map[domain.RootID]port.RolloutTargetSnapshot{
		"root-a": {Baseline: domain.PolicyBinding{Digest: base}, Candidate: domain.PolicyBinding{Digest: candidate.Bundle.Digest()}, BaseRootEpoch: 3},
		"root-b": {Baseline: domain.PolicyBinding{Digest: base}, Candidate: domain.PolicyBinding{Digest: candidate.Bundle.Digest()}, BaseRootEpoch: 5},
	}}}
	service, err := NewRolloutService(tx, nil, nil, k, pin)
	if err != nil {
		t.Fatal(err)
	}
	f := &rolloutFixture{tx: tx, service: service, kernel: k, pin: pin, key: key, candidateProposer: domain.ProposalContext{ProposerID: "candidate-author"}, transitionProposer: domain.ProposalContext{ProposerID: "release-author"}}
	f.request = PromoteRequest{CommandID: "promote", Nonce: "transition-nonce", Scope: "scope", Rollout: rid, ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: map[domain.RootID]domain.Epoch{"root-a": 3, "root-b": 6}, Candidate: candidate,
		Approval: domain.RolloutTransitionApproval{Scope: "scope", Roots: []domain.RootID{"root-b", "root-a"}, ScopeEpoch: 41, SecurityEpoch: 7, RootEpochs: map[domain.RootID]domain.Epoch{"root-a": 3, "root-b": 6}, RolloutID: rid, RolloutState: domain.RolloutCanary, CandidateDigest: candidate.Bundle.Digest(), KernelDigest: pin, Tier: domain.TierG0, ProposerID: f.transitionProposer.ProposerID, ProposalID: candidate.ProposalID, Nonce: "transition-nonce"}}
	f.signCandidate(t)
	f.signTransition(t)
	return f
}
func (f *rolloutFixture) signCandidate(t *testing.T) {
	t.Helper()
	b, err := domain.DomainApprovalSigningBytes(f.request.Candidate, f.pin, f.candidateProposer.ProposerID)
	if err != nil {
		t.Fatal(err)
	}
	f.request.CandidateApprovals = []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, b)}}
}
func (f *rolloutFixture) signTransition(t *testing.T) {
	t.Helper()
	b, err := f.request.Approval.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	f.request.Approval.Approvals = []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, b)}}
}
func (f *rolloutFixture) promote() (PromoteResult, error) {
	return f.service.Promote(context.Background(), f.request, f.candidateProposer, f.transitionProposer)
}
func assertNoRolloutStateWrites(t *testing.T, tx *rolloutTxFake, err error) {
	t.Helper()
	if err == nil {
		t.Error("expected rejection")
	}
	// S05 permits exactly a durable negative receipt, never a state/Event
	// mutation, for deterministic pre-write denials.
	if reflect.DeepEqual(tx.writes, []string{"receipt"}) && tx.commits == 1 && len(tx.receipts) == 1 {
		for _, r := range tx.receipts {
			var response CommandResponse
			if r.Status != "REJECTED" || r.Expired || json.Unmarshal(r.Response, &response) != nil || !reflect.DeepEqual(response, CommandErrorResponse(err)) {
				t.Fatalf("invalid negative receipt: %+v", r)
			}
		}
		return
	}
	if len(tx.writes) != 0 || tx.commits != 0 {
		t.Fatalf("rejection attempted state writes=%v commits=%d", tx.writes, tx.commits)
	}
}

func TestRolloutConstructorRejectsMalformedPinsBeforeDatabaseCalls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*domain.KernelSnapshot)
	}{
		{"header", func(k *domain.KernelSnapshot) { k.Version = 0 }},
		{"missing signers", func(k *domain.KernelSnapshot) { k.Signers = nil }},
		{"signer id", func(k *domain.KernelSnapshot) { k.Signers[0].ID = " bad " }},
		{"signer key", func(k *domain.KernelSnapshot) { k.Signers[0].PublicKey = []byte{1} }},
		{"duplicate signer", func(k *domain.KernelSnapshot) { k.Signers = append(k.Signers, k.Signers[0]) }},
		{"duplicate key", func(k *domain.KernelSnapshot) { s := k.Signers[0]; s.ID = "other"; k.Signers = append(k.Signers, s) }},
		{"zero threshold", func(k *domain.KernelSnapshot) { k.Thresholds[0].Threshold = 0 }},
		{"negative threshold", func(k *domain.KernelSnapshot) { k.Thresholds[0].Threshold = -1 }},
		{"unreachable threshold", func(k *domain.KernelSnapshot) { k.Thresholds[0].Threshold = 2 }},
		{"missing tier", func(k *domain.KernelSnapshot) { k.Thresholds = k.Thresholds[:1] }},
		{"unsupported tier", func(k *domain.KernelSnapshot) { k.Thresholds[0].Tier = domain.TierG2 }},
		{"duplicate tier", func(k *domain.KernelSnapshot) { k.Thresholds = append(k.Thresholds, k.Thresholds[0]) }},
		{"missing capabilities", func(k *domain.KernelSnapshot) { k.Capabilities = nil }},
		{"malformed capability", func(k *domain.KernelSnapshot) { k.Capabilities[0] = "BAD capability" }},
		{"duplicate capability", func(k *domain.KernelSnapshot) { k.Capabilities = append(k.Capabilities, k.Capabilities[0]) }},
		{"issuer id", func(k *domain.KernelSnapshot) { k.IssuerCeilings[0].IssuerID = " bad " }},
		{"duplicate issuer", func(k *domain.KernelSnapshot) { k.IssuerCeilings = append(k.IssuerCeilings, k.IssuerCeilings[0]) }},
		{"unknown ceiling capability", func(k *domain.KernelSnapshot) { k.IssuerCeilings[0].Capabilities[0] = "unknown" }},
		{"duplicate ceiling capability", func(k *domain.KernelSnapshot) {
			k.IssuerCeilings[0].Capabilities = append(k.IssuerCeilings[0].Capabilities, "governance")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := kernelFixture()
			tc.mutate(&k)
			d, _ := k.Digest() // Header errors deliberately have no computable digest.
			tx := &rolloutTxFake{}
			svc, err := NewRolloutService(tx, nil, nil, k, d)
			if err == nil || svc != nil {
				t.Fatalf("malformed Kernel constructed: %v", err)
			}
			if tx.begins != 0 || tx.reads != 0 || len(tx.writes) != 0 {
				t.Fatal("constructor accessed database")
			}
		})
	}
	for _, pin := range []domain.Digest{"bad", domain.Digest(strings.Repeat("a", 64))} {
		tx := &rolloutTxFake{}
		if svc, err := NewRolloutService(tx, nil, nil, kernelFixture(), pin); err == nil || svc != nil {
			t.Fatal("invalid/mismatched independent pin accepted")
		}
		if tx.begins != 0 || tx.reads != 0 {
			t.Fatal("pin rejection accessed database")
		}
	}
}

func TestPromoteMonitoringClockFailureIsAtomic(t *testing.T) {
	for _, mode := range []string{"clock error", "zero clock", "commit error"} {
		t.Run(mode, func(t *testing.T) {
			base := newRolloutFixture(t)
			f := &monitoringTxFake{rolloutTxFake: base.tx, cause: errors.New("clock/commit failure")}
			base.service.tx = f
			oldScope, oldRollout := f.scope, f.rollout
			switch mode {
			case "clock error":
				f.fail = "DB clock"
			case "commit error":
				f.now = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
				f.commitErr = f.cause
			}
			if _, err := base.promote(); err == nil {
				t.Fatal("failed promotion claimed success")
			}
			if !reflect.DeepEqual(f.scope, oldScope) || !reflect.DeepEqual(f.rollout, oldRollout) || len(f.receipts) != 0 || len(f.events) != 0 {
				t.Fatal("partially initialized monitoring was persisted")
			}
		})
	}
}

func TestPromoteUsesSignedContextsAndAdvancesOnlyChangedRoots(t *testing.T) {
	f := newRolloutFixture(t)
	out, err := f.promote()
	if err != nil {
		t.Fatal(err)
	}
	if out.State != domain.RolloutMonitoring || out.ScopeEpoch != 42 || f.tx.scope.Roots["root-a"].AuthorizationEpoch != 4 || f.tx.scope.Roots["root-b"].AuthorizationEpoch != 6 {
		t.Fatalf("result=%+v roots=%+v", out, f.tx.scope.Roots)
	}
	dbNow, _ := f.tx.DatabaseTime(context.Background())
	m := f.tx.rollout.Monitoring
	if m.Validate() != nil || m.StartedAt != dbNow || m.ObservationDeadline != dbNow.Add(domain.MonitoringActivePeriod) || m.DecisionRevision != 0 {
		t.Fatalf("promotion did not initialize DB-clock monitoring: %+v", m)
	}
	if f.tx.commits != 1 || !reflect.DeepEqual(f.tx.writes, []string{"scope CAS", "rollout CAS", "receipt", "event/outbox"}) {
		t.Fatalf("writes=%v commits=%d", f.tx.writes, f.tx.commits)
	}
	wantDigest, err := promoteCommandDigest(f.request, f.candidateProposer, f.transitionProposer)
	if err != nil {
		t.Fatal(err)
	}
	if f.tx.receipts[f.request.CommandID].RequestDigest != wantDigest {
		t.Fatal("actual receipt does not bind both trusted contexts")
	}
	writes := len(f.tx.writes)
	if replay, err := f.promote(); err != nil || replay != out || len(f.tx.writes) != writes {
		t.Fatalf("replay=%+v err=%v writes=%v", replay, err, f.tx.writes)
	}
	for _, which := range []string{"candidate", "transition"} {
		t.Run(which+" digest", func(t *testing.T) {
			c, a := f.candidateProposer, f.transitionProposer
			if which == "candidate" {
				c.ProposerID = "other-candidate"
			} else {
				a.ProposerID = "other-transition"
			}
			_, err := f.service.Promote(context.Background(), f.request, c, a)
			if err == nil || !strings.Contains(err.Error(), "different request") || len(f.tx.writes) != writes {
				t.Fatalf("trusted context not bound: err=%v", err)
			}
		})
	}
	f.request.CommandID = "new-command-same-approval"
	_, err = f.promote()
	if !errors.Is(err, port.ErrStaleWrite) || len(f.tx.writes) != writes {
		t.Fatalf("stale signed transition reused: %v", err)
	}
}

func TestPromoteRejectsEverySignedContextMismatchBeforeWrites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rolloutFixture)
		resign bool
	}{
		{"signed scope", func(f *rolloutFixture) { f.request.Approval.Scope = "other-scope" }, true},
		{"signed rollout", func(f *rolloutFixture) { f.request.Approval.RolloutID = "other-rollout" }, true},
		{"signed state", func(f *rolloutFixture) { f.request.Approval.RolloutState = domain.RolloutMonitoring }, true},
		{"signed scope epoch", func(f *rolloutFixture) { f.request.Approval.ScopeEpoch++ }, true},
		{"signed security epoch", func(f *rolloutFixture) { f.request.Approval.SecurityEpoch++ }, true},
		{"signed root epoch", func(f *rolloutFixture) { f.request.Approval.RootEpochs["root-a"]++ }, true},
		{"signed missing root", func(f *rolloutFixture) {
			f.request.Approval.Roots = []domain.RootID{"root-b"}
			delete(f.request.Approval.RootEpochs, "root-a")
		}, true},
		{"signed extra root", func(f *rolloutFixture) {
			f.request.Approval.Roots = append(f.request.Approval.Roots, "root-c")
			f.request.Approval.RootEpochs["root-c"] = 1
		}, true},
		{"signed wrong root", func(f *rolloutFixture) {
			f.request.Approval.Roots[1] = "root-c"
			delete(f.request.Approval.RootEpochs, "root-a")
			f.request.Approval.RootEpochs["root-c"] = 3
		}, true},
		{"signed candidate", func(f *rolloutFixture) { f.request.Approval.CandidateDigest = testBundle(t, `{"other":true}`).Digest() }, true},
		{"signed kernel", func(f *rolloutFixture) { f.request.Approval.KernelDigest = testBundle(t, `{"kernel":true}`).Digest() }, true},
		{"signed tier", func(f *rolloutFixture) { f.request.Approval.Tier = domain.TierG1 }, true},
		{"resubmitted candidate tier", func(f *rolloutFixture) {
			f.request.Candidate.Tier = domain.TierG1
			f.signCandidate(t)
		}, false},
		{"signed proposer", func(f *rolloutFixture) { f.request.Approval.ProposerID = "request-author" }, true},
		{"signed proposal", func(f *rolloutFixture) { f.request.Approval.ProposalID = "other-proposal" }, true},
		{"signed nonce", func(f *rolloutFixture) { f.request.Approval.Nonce = "other-nonce" }, true},
		{"trusted candidate proposer", func(f *rolloutFixture) { f.candidateProposer.ProposerID = "wrong-candidate" }, false},
		{"trusted transition proposer", func(f *rolloutFixture) { f.transitionProposer.ProposerID = "wrong-transition" }, false},
		{"swapped trusted proposers", func(f *rolloutFixture) {
			f.candidateProposer, f.transitionProposer = f.transitionProposer, f.candidateProposer
		}, false},
		{"missing candidate approvals", func(f *rolloutFixture) { f.request.CandidateApprovals = nil }, false},
		{"invalid candidate signature", func(f *rolloutFixture) { f.request.CandidateApprovals[0].Signature[0] ^= 1 }, false},
		{"candidate issuer", func(f *rolloutFixture) { f.request.Candidate.IssuerID = "other-issuer" }, false},
		{"candidate proposal", func(f *rolloutFixture) { f.request.Candidate.ProposalID = "other-proposal" }, false},
		{"candidate nonce", func(f *rolloutFixture) { f.request.Candidate.Nonce = "other-nonce" }, false},
		{"candidate capability", func(f *rolloutFixture) { f.request.Candidate.CapabilityIDs = []string{"other"} }, false},
		{"missing transition approvals", func(f *rolloutFixture) { f.request.Approval.Approvals = nil }, false},
		{"invalid transition signature", func(f *rolloutFixture) { f.request.Approval.Approvals[0].Signature[0] ^= 1 }, false},
		{"missing signed root epoch", func(f *rolloutFixture) { delete(f.request.Approval.RootEpochs, "root-a") }, false},
		{"extra signed root epoch", func(f *rolloutFixture) { f.request.Approval.RootEpochs["root-c"] = 1 }, false},
		{"duplicate signed root", func(f *rolloutFixture) { f.request.Approval.Roots[1] = f.request.Approval.Roots[0] }, false},
		{"locked candidate on target", func(f *rolloutFixture) {
			r := f.tx.rollout.Targets["root-b"]
			r.Candidate.Digest = testBundle(t, `{"other":true}`).Digest()
			f.tx.rollout.Targets["root-b"] = r
		}, false},
		{"locked candidate on other root", func(f *rolloutFixture) {
			r := f.tx.rollout.Targets["root-a"]
			r.Candidate.Digest = testBundle(t, `{"other":true}`).Digest()
			f.tx.rollout.Targets["root-a"] = r
		}, false},
		{"resubmitted candidate differs from locked", func(f *rolloutFixture) {
			f.request.Candidate.Bundle = testBundle(t, `{"other":true}`)
			f.request.Approval.CandidateDigest = f.request.Candidate.Bundle.Digest()
			f.signCandidate(t)
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRolloutFixture(t)
			tc.mutate(f)
			// Re-sign valid-but-wrong contexts so rejection cannot be attributed to a
			// stale signature: these must be compared with the locked state/request.
			if tc.resign {
				f.signTransition(t)
			}
			_, err := f.promote()
			assertNoRolloutStateWrites(t, f.tx, err)
		})
	}
}

func TestPromoteSignedOperationMustBeCanonicalPROMOTE(t *testing.T) {
	for _, op := range []string{"ROLLBACK", "promote", "START_CANARY"} {
		t.Run(op, func(t *testing.T) {
			f := newRolloutFixture(t)
			b, err := f.request.Approval.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte(`"operation":"PROMOTE"`)) {
				t.Fatal("transition signing bytes lack canonical operation")
			}
			b = bytes.ReplaceAll(b, []byte(`"operation":"PROMOTE"`), []byte(`"operation":"`+op+`"`))
			f.request.Approval.Approvals[0].Signature = ed25519.Sign(f.key, b)
			_, err = f.promote()
			assertNoRolloutStateWrites(t, f.tx, err)
		})
	}
}

func TestPromoteAndRollbackRejectNonexactRootEpochMapsBeforeWrites(t *testing.T) {
	for _, operation := range []string{"promote", "rollback"} {
		for _, variant := range []string{"nil", "missing", "extra", "stale", "wrong ID"} {
			t.Run(operation+"/"+variant, func(t *testing.T) {
				f := newRolloutFixture(t)
				epochs := f.request.ExpectedRootEpochs
				switch variant {
				case "nil":
					epochs = nil
				case "missing":
					delete(epochs, "root-a")
				case "extra":
					epochs["root-c"] = 1
				case "stale":
					epochs["root-a"]--
				case "wrong ID":
					delete(epochs, "root-a")
					epochs["root-c"] = 3
				}
				var err error
				if operation == "promote" {
					f.request.ExpectedRootEpochs = epochs
					_, err = f.promote()
				} else {
					_, err = f.service.Rollback(context.Background(), RollbackRequest{CommandID: "rollback", Nonce: "rollback-nonce", Scope: "scope", Rollout: "rollout", ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: epochs})
				}
				assertNoRolloutStateWrites(t, f.tx, err)
			})
		}
	}
}

func TestPromoteAndRollbackRejectLockedStateMismatchBeforeWrites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rolloutFixture)
	}{
		{"scope epoch", func(f *rolloutFixture) { f.tx.scope.ActivationEpoch++ }},
		{"security epoch", func(f *rolloutFixture) { f.tx.scope.SecurityEpoch++ }},
		{"rollout state", func(f *rolloutFixture) { f.tx.rollout.State = domain.RolloutMonitoring }},
		{"no live rollout", func(f *rolloutFixture) { f.tx.scope.LiveRolloutID = nil }},
		{"other live rollout", func(f *rolloutFixture) { r := domain.RolloutID("other"); f.tx.scope.LiveRolloutID = &r }},
		{"scope identity", func(f *rolloutFixture) { f.tx.scope.ScopeID = "other" }},
		{"rollout identity", func(f *rolloutFixture) { f.tx.rollout.ID = "other" }},
		{"rollout scope", func(f *rolloutFixture) { f.tx.rollout.Scope = "other" }},
		{"missing locked root", func(f *rolloutFixture) { delete(f.tx.scope.Roots, "root-a") }},
		{"extra locked root", func(f *rolloutFixture) { f.tx.scope.Roots["root-c"] = f.tx.scope.Roots["root-a"] }},
		{"missing target root", func(f *rolloutFixture) { delete(f.tx.rollout.Targets, "root-a") }},
	}
	for _, operation := range []string{"promote", "rollback"} {
		for _, tc := range cases {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				f := newRolloutFixture(t)
				tc.mutate(f)
				var err error
				if operation == "promote" {
					_, err = f.promote()
				} else {
					_, err = f.service.Rollback(context.Background(), RollbackRequest{CommandID: "rollback", Nonce: "rollback-nonce", Scope: "scope", Rollout: "rollout", ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: f.request.ExpectedRootEpochs})
				}
				assertNoRolloutStateWrites(t, f.tx, err)
			})
		}
	}
}

func TestRolloutTrustUsesOnlyImmutableConstructorPin(t *testing.T) {
	for _, operation := range []string{"start", "promote"} {
		for _, variant := range []string{"caller mutation", "internal corruption", "request signed by substituted key"} {
			t.Run(operation+"/"+variant, func(t *testing.T) {
				f := newRolloutFixture(t)
				switch variant {
				case "caller mutation":
					f.kernel.Signers[0].ID = "changed"
					f.kernel.Signers[0].PublicKey[0] ^= 1
					f.kernel.Thresholds[0].Threshold = 99
					f.kernel.Capabilities[0] = "changed"
					f.kernel.IssuerCeilings[0].IssuerID = "changed"
					f.kernel.IssuerCeilings[0].Capabilities[0] = "changed"
				case "internal corruption":
					f.service.kernel.Signers[0].PublicKey[0] ^= 1
				case "request signed by substituted key":
					f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
					f.kernel.Signers[0].PublicKey = f.key.Public().(ed25519.PublicKey)
					var err error
					f.pin, err = f.kernel.Digest()
					if err != nil {
						t.Fatal(err)
					}
					f.request.Approval.KernelDigest = f.pin
					f.signCandidate(t)
					f.signTransition(t)
				}
				var err error
				if operation == "promote" {
					_, err = f.promote()
				} else {
					f.tx.scope.LiveRolloutID = nil
					f.tx.scope.ActivationEpoch = 40
					r := f.tx.scope.Roots["root-b"]
					r.AuthorizationEpoch = 5
					r.Policy = f.tx.scope.Roots["root-a"].Policy
					f.tx.scope.Roots["root-b"] = r
					_, err = f.service.StartCanary(context.Background(), StartCanaryRequest{CommandID: "start", Nonce: "start-nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: 7, Approvals: f.request.CandidateApprovals}, f.candidateProposer)
				}
				if variant == "caller mutation" {
					if err != nil || f.tx.commits != 1 {
						t.Fatalf("caller mutated service trust: %v", err)
					}
				} else {
					assertNoRolloutStateWrites(t, f.tx, err)
				}
				if variant == "internal corruption" && (f.tx.begins != 0 || f.tx.reads != 0) {
					t.Fatal("corrupt pin reached database")
				}
			})
		}
	}
}

func TestStartCanaryLinksNewRolloutThroughScopeCAS(t *testing.T) {
	f := newRolloutFixture(t)
	f.tx.scope.LiveRolloutID = nil
	f.tx.scope.ActivationEpoch = 40
	r := f.tx.scope.Roots["root-b"]
	r.AuthorizationEpoch = 5
	r.Policy = f.tx.scope.Roots["root-a"].Policy
	f.tx.scope.Roots["root-b"] = r
	f.tx.rollout = port.RolloutSnapshot{}
	before := f.tx.scope
	q := StartCanaryRequest{CommandID: "start", Nonce: "start-nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: 7, Approvals: f.request.CandidateApprovals}
	out, err := f.service.StartCanary(context.Background(), q, f.candidateProposer)
	if err != nil {
		t.Fatal(err)
	}
	// The fake assigns scope only from CompareAndSwapScope's next argument.
	if f.tx.scope.LiveRolloutID == nil || *f.tx.scope.LiveRolloutID != q.Rollout || f.tx.rollout.ID != q.Rollout {
		t.Fatalf("Scope CAS live ID=%v created rollout=%q want=%q", f.tx.scope.LiveRolloutID, f.tx.rollout.ID, q.Rollout)
	}
	if before.LiveRolloutID != nil || before.ActivationEpoch != 40 || before.Roots["root-b"].AuthorizationEpoch != 5 {
		t.Fatal("StartCanary mutated the expected Scope snapshot")
	}
	if out.ScopeEpoch != 41 || out.RootEpoch != 6 || f.tx.scope.SecurityEpoch != 7 || f.tx.scope.Roots["root-a"] != before.Roots["root-a"] {
		t.Fatalf("Canary result=%+v scope=%+v", out, f.tx.scope)
	}
	if f.tx.commits != 1 || !reflect.DeepEqual(f.tx.writes, []string{"create", "scope CAS", "receipt", "event/outbox"}) {
		t.Fatalf("writes=%v commits=%d", f.tx.writes, f.tx.commits)
	}
	writes := len(f.tx.writes)
	if replay, err := f.service.StartCanary(context.Background(), q, f.candidateProposer); err != nil || replay != out || len(f.tx.writes) != writes {
		t.Fatalf("Canary replay=%+v err=%v writes=%v", replay, err, f.tx.writes)
	}
	q.CommandID = "stale-start"
	_, err = f.service.StartCanary(context.Background(), q, f.candidateProposer)
	requireFailureKind(t, err, FailureBusy)
	if len(f.tx.writes) != writes {
		t.Fatalf("occupied Canary slot attempted writes: err=%v writes=%v", err, f.tx.writes)
	}
	// The newly linked slot is usable by the existing Promote/Rollback flow.
	if _, err := f.promote(); err != nil {
		t.Fatal(err)
	}
	if f.tx.scope.LiveRolloutID == nil || *f.tx.scope.LiveRolloutID != q.Rollout {
		t.Fatal("Promote did not retain the live Rollout ID")
	}
	f.service.lkg = localLKGFunc(func(_ context.Context, digest domain.Digest) (domain.LKGAssessment, error) {
		return domain.LKGAssessment{Status: domain.LKGUsable, Digest: digest}, nil
	})
	rolled, err := f.service.Rollback(context.Background(), RollbackRequest{CommandID: "rollback", Nonce: "rollback-nonce", Scope: q.Scope, Rollout: q.Rollout, ExpectedState: domain.RolloutMonitoring, ExpectedScopeEpoch: 42, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: map[domain.RootID]domain.Epoch{"root-a": 4, "root-b": 6}})
	if err != nil || rolled.State != domain.RolloutRolledBack || rolled.ScopeEpoch != 43 {
		t.Fatalf("Rollback=%+v err=%v", rolled, err)
	}
	if f.tx.scope.LiveRolloutID != nil {
		t.Fatal("terminal Rollback did not release the live Scope slot")
	}
}

func TestStartCanaryRejectsStaleEpochsBeforeWrites(t *testing.T) {
	for _, field := range []string{"scope", "security", "root"} {
		t.Run(field, func(t *testing.T) {
			f := newRolloutFixture(t)
			f.tx.scope.LiveRolloutID = nil
			f.tx.scope.ActivationEpoch = 40
			r := f.tx.scope.Roots["root-b"]
			r.AuthorizationEpoch = 5
			r.Policy = f.tx.scope.Roots["root-a"].Policy
			f.tx.scope.Roots["root-b"] = r
			q := StartCanaryRequest{CommandID: "start", Nonce: "start-nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: 7, Approvals: f.request.CandidateApprovals}
			switch field {
			case "scope":
				q.ExpectedScopeEpoch--
			case "security":
				q.ExpectedSecurityEpoch--
			case "root":
				q.ExpectedRootEpoch--
			}
			_, err := f.service.StartCanary(context.Background(), q, f.candidateProposer)
			if !errors.Is(err, port.ErrStaleWrite) {
				t.Fatalf("stale %s epoch error=%v", field, err)
			}
			assertNoRolloutStateWrites(t, f.tx, err)
		})
	}
}

func TestStartCanaryRejectsWrongTrustedProposerBeforeWrites(t *testing.T) {
	f := newRolloutFixture(t)
	f.tx.scope.LiveRolloutID = nil
	f.tx.scope.ActivationEpoch = 40
	r := f.tx.scope.Roots["root-b"]
	r.AuthorizationEpoch = 5
	r.Policy = f.tx.scope.Roots["root-a"].Policy
	f.tx.scope.Roots["root-b"] = r
	_, err := f.service.StartCanary(context.Background(), StartCanaryRequest{CommandID: "start", Nonce: "start-nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: 7, Approvals: f.request.CandidateApprovals}, domain.ProposalContext{ProposerID: "request-author"})
	assertNoRolloutStateWrites(t, f.tx, err)
}

func TestProposeTwoIDsInOneScopeUseDistinctAggregatesAndCallerTransaction(t *testing.T) {
	f := newRolloutFixture(t)
	calls := []string{}
	now, _ := f.tx.DatabaseTime(context.Background())
	resolver := bundleResolverFake{calls: &calls, key: BundleSigningKey{KeyID: "bundle-key", PublicKey: f.key.Public().(ed25519.PublicKey), ValidFrom: now, ValidUntil: now.Add(time.Hour)}}
	// If Propose accidentally calls Register instead of RegisterWithin, this
	// transactor records a nested begin and fails on its nil transaction.
	f.service.bundles = NewBundleRegistrationService(bundleTransactorFake{calls: &calls}, resolver)
	before := f.tx.scope
	for _, id := range []string{"proposal-a", "proposal-b"} {
		q := ProposeRequest{CommandID: "command-" + id, Nonce: "nonce-" + id, Scope: "scope", ProposalID: id, ProposerID: "author", BundleKeyID: "bundle-key", Bundle: f.request.Candidate.Bundle, Signature: ed25519.Sign(f.key, f.request.Candidate.Bundle.SigningBytes())}
		out, err := f.service.Propose(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if out.ProposalID != id || out.BundleDigest != q.Bundle.Digest() {
			t.Fatalf("result=%+v", out)
		}
	}
	if f.tx.begins != 2 || f.tx.commits != 2 || !reflect.DeepEqual(calls, []string{"resolve:bundle-key", "resolve:bundle-key"}) {
		t.Fatalf("transactions=%d commits=%d calls=%v", f.tx.begins, f.tx.commits, calls)
	}
	if !reflect.DeepEqual(before, f.tx.scope) {
		t.Fatal("Propose changed authority")
	}
	if len(f.tx.events) != 2 {
		t.Fatalf("events=%d", len(f.tx.events))
	}
	for i, id := range []string{"proposal-a", "proposal-b"} {
		e := f.tx.events[i]
		if e.AggregateKind() != "proposal" || e.AggregateID() != id || e.AggregateVersion() != 1 {
			t.Fatalf("event %d not proposal/ID/1", i)
		}
	}
	if !reflect.DeepEqual(f.tx.writes, []string{"bundle", "receipt", "event/outbox", "bundle", "receipt", "event/outbox"}) {
		t.Fatalf("writes=%v", f.tx.writes)
	}
}

func TestRolloutRequestTypesExcludeAllKernelTrustFields(t *testing.T) {
	for _, request := range []any{StartCanaryRequest{}, PromoteRequest{}} {
		typ := reflect.TypeOf(request)
		for i := 0; i < typ.NumField(); i++ {
			if strings.Contains(strings.ToLower(typ.Field(i).Name), "kernel") {
				t.Fatalf("%s contains request trust field %s", typ.Name(), typ.Field(i).Name)
			}
		}
		// The serialized request exposes no independent Kernel pin either.
		b, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["KernelDigest"]; ok {
			t.Fatal("request serializes a Kernel trust pin")
		}
	}
}

type localLKGFunc func(context.Context, domain.Digest) (domain.LKGAssessment, error)

func (fn localLKGFunc) VerifyLKG(ctx context.Context, digest domain.Digest) (domain.LKGAssessment, error) {
	return fn(ctx, digest)
}

func TestRollbackAcceptsExactRootMapAndChecksLKGWithoutIntermediateWrites(t *testing.T) {
	for _, outcome := range []string{"usable", "mismatch", "revoked_signature", "unavailable", "error", "missing", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			f := newRolloutFixture(t)
			// Safe-only rollback must not wait for ordinary candidate/transition approval.
			f.request.CandidateApprovals = nil
			f.request.Approval.Approvals = nil
			if ev := domain.VerifyDomainApproval(f.kernel, f.pin, f.request.Candidate, f.candidateProposer, f.request.CandidateApprovals); ev.Accepted {
				t.Fatal("candidate unexpectedly approved without signatures")
			}
			before := f.tx.scope
			beforeRollout := f.tx.rollout
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			if outcome != "missing" {
				f.service.lkg = localLKGFunc(func(ctx context.Context, digest domain.Digest) (domain.LKGAssessment, error) {
					calls++
					if len(f.tx.writes) != 0 {
						t.Fatalf("Freeze was persisted before finalization: %v", f.tx.writes)
					}
					if !reflect.DeepEqual(f.tx.scope, before) || !reflect.DeepEqual(f.tx.rollout, beforeRollout) {
						t.Fatal("Rollback changed the locked snapshots before finalization")
					}
					if digest != *f.tx.scope.BaselineBundle {
						t.Fatalf("LKG requested %q", digest)
					}
					switch outcome {
					case "mismatch":
						return domain.LKGAssessment{Status: domain.LKGUsable, Digest: f.request.Candidate.Bundle.Digest()}, nil
					case "revoked_signature":
						// Revocation is assessed by the injected verifier, not by Rollback.
						return domain.LKGAssessment{Status: domain.LKGInvalid, Digest: digest}, nil
					case "unavailable":
						return domain.LKGAssessment{Status: domain.LKGUnavailable, Digest: digest}, nil
					case "error":
						return domain.LKGAssessment{}, errors.New("local verification unavailable")
					case "cancelled":
						cancel()
						return domain.LKGAssessment{}, ctx.Err()
					default:
						return domain.LKGAssessment{Status: domain.LKGUsable, Digest: digest}, nil
					}
				})
			}
			q := RollbackRequest{CommandID: "rollback", Nonce: "rollback-nonce", Scope: "scope", Rollout: "rollout", ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: f.request.ExpectedRootEpochs}
			out, err := f.service.Rollback(ctx, q)
			if outcome == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error=%v", err)
				}
				assertNoRolloutStateWrites(t, f.tx, err)
				if !reflect.DeepEqual(f.tx.scope, before) || !reflect.DeepEqual(f.tx.rollout, beforeRollout) {
					t.Fatal("cancelled Rollback changed the live slot or epochs")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := 1
			if outcome == "missing" {
				wantCalls = 0
			}
			if calls != wantCalls || out.ScopeEpoch != 42 || f.tx.scope.SecurityEpoch != 7 || f.tx.commits != 1 || !reflect.DeepEqual(f.tx.writes, []string{"scope CAS", "rollout CAS", "receipt", "event/outbox"}) {
				t.Fatalf("result=%+v calls=%d writes=%v commits=%d", out, calls, f.tx.writes, f.tx.commits)
			}
			if f.tx.scope.LiveRolloutID != nil {
				t.Fatal("terminal Rollback retained the live Scope slot")
			}
			if before.LiveRolloutID == nil || *before.LiveRolloutID != q.Rollout || before.ActivationEpoch != 41 || before.Roots["root-a"].AuthorizationEpoch != 3 || before.Roots["root-b"].AuthorizationEpoch != 6 {
				t.Fatal("Rollback mutated the expected Scope snapshot")
			}
			if f.tx.scope.ActivationEpoch != 42 || f.tx.rollout.LastActivationEpoch != 42 || f.tx.rollout.State != out.State || f.tx.scope.Mode != out.Mode || f.tx.scope.Roots["root-b"].AuthorizationEpoch != 7 {
				t.Fatalf("final snapshot epochs/state: scope=%+v rollout=%+v", f.tx.scope, f.tx.rollout)
			}
			if outcome == "usable" {
				if out.State != domain.RolloutRolledBack || out.Mode != domain.ScopeActive || f.tx.scope.Roots["root-a"].AuthorizationEpoch != 3 || f.tx.scope.Roots["root-b"].AuthorizationEpoch != 7 {
					t.Fatalf("rollback=%+v roots=%+v", out, f.tx.scope.Roots)
				}
				for _, root := range f.tx.scope.Roots {
					if root.Policy.SafeBaseline || root.Policy.Digest != *f.tx.scope.BaselineBundle {
						t.Fatal("usable LKG not restored")
					}
				}
			} else {
				if out.State != domain.RolloutSafeStopped || out.Mode != domain.ScopeSafeStop || f.tx.scope.Roots["root-a"].AuthorizationEpoch != 4 {
					t.Fatalf("unsafe LKG did not select Safe Baseline: %+v", out)
				}
				for id, root := range f.tx.scope.Roots {
					if !root.Policy.SafeBaseline || root.Policy.Digest != "" {
						t.Fatal("unsafe LKG restored instead of deny-all")
					}
					if _, err := domain.EffectivePolicy(snapshotAuthority(f.tx.scope), id); !errors.Is(err, domain.ErrSafeStopped) {
						t.Fatalf("Safe Baseline did not deny root %q: %v", id, err)
					}
				}
			}
			writes := len(f.tx.writes)
			if replay, err := f.service.Rollback(ctx, q); err != nil || replay != out || len(f.tx.writes) != writes || calls != wantCalls {
				t.Fatalf("rollback replay=%+v err=%v writes=%v LKG calls=%d", replay, err, f.tx.writes, calls)
			}
		})
	}
}

// The boundary normalizes errors from any transaction phase, not just those
// raised by the callback (notably Begin and Commit errors).
type rolloutTransactorFunc func(context.Context, func(port.RolloutTx) error) error

func (f rolloutTransactorFunc) WithinRolloutTransaction(ctx context.Context, fn func(port.RolloutTx) error) error {
	return f(ctx, fn)
}

func TestRolloutPublicBoundariesNormalizeOnlyKnownFailures(t *testing.T) {
	unmatched := errors.New("unclassified infrastructure failure")
	for _, operation := range []string{"propose", "start", "promote", "rollback"} {
		for _, tc := range []struct {
			name string
			err  error
			kind FailureKind
		}{
			{"stale", port.ErrStaleWrite, FailureStale},
			{"busy", errors.Join(port.ErrTransactionRolledBack, stateErr{"55P03"}), FailureBusy},
			{"approval", domain.ErrInvalidApproval, FailureForbidden},
			{"ACL", errors.Join(port.ErrTransactionRolledBack, stateErr{"42501"}), FailureForbidden},
			{"invalid", domain.ErrInvalidCanonicalInput, FailureInvalid},
			{"serialization abort", errors.Join(port.ErrTransactionRolledBack, stateErr{"40001"}), FailureRetryable},
			{"deadlock abort", errors.Join(port.ErrTransactionRolledBack, stateErr{"40P01"}), FailureRetryable},
			{"unmarked lock unavailable", stateErr{"55P03"}, ""},
			{"unmarked ACL", stateErr{"42501"}, ""},
			{"unmarked serialization", stateErr{"40001"}, ""},
			{"unmarked deadlock", stateErr{"40P01"}, ""},
			{"unknown", errors.Join(port.ErrCommitOutcomeUnknown, stateErr{"40001"}), FailureUnknownCommit},
			{"unknown overrides rollback", errors.Join(port.ErrTransactionRolledBack, port.ErrCommitOutcomeUnknown, stateErr{"40P01"}), FailureUnknownCommit},
			{"unmatched", unmatched, ""},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				f := newRolloutFixture(t)
				cause := fmt.Errorf("transaction phase: %w", tc.err)
				calls := 0
				f.service.tx = rolloutTransactorFunc(func(context.Context, func(port.RolloutTx) error) error {
					calls++
					return cause
				})
				f.service.bundles = NewBundleRegistrationService(nil, nil)
				var err error
				switch operation {
				case "propose":
					_, err = f.service.Propose(context.Background(), ProposeRequest{CommandID: "propose", Nonce: "nonce"})
				case "start":
					_, err = f.service.StartCanary(context.Background(), StartCanaryRequest{CommandID: "start", Nonce: "nonce"}, f.candidateProposer)
				case "promote":
					_, err = f.promote()
				case "rollback":
					_, err = f.service.Rollback(context.Background(), RollbackRequest{CommandID: "rollback", Nonce: "nonce"})
				}
				if calls != 1 || !errors.Is(err, tc.err) {
					t.Fatalf("error=%v calls=%d", err, calls)
				}
				if tc.kind == "" {
					if err != cause {
						t.Fatal("unmatched error not passed through unchanged")
					}
				} else if requireFailureKind(t, err, tc.kind).Cause != cause {
					t.Fatal("boundary lost original cause")
				}
			})
		}
	}
}

func TestStartCanaryBusyFromLockedSlotBeforeAnyWrites(t *testing.T) {
	for _, active := range []domain.RolloutID{"rollout", "other-rollout", ""} {
		t.Run("active="+string(active), func(t *testing.T) {
			f := newRolloutFixture(t)
			f.tx.scope.LiveRolloutID = &active
			before := f.tx.scope
			q := StartCanaryRequest{CommandID: "new-start", Nonce: "nonce", Scope: "scope", Rollout: "rollout", Root: "root-b", ExpectedScopeEpoch: 41, ExpectedRootEpoch: 6, ExpectedSecurityEpoch: 7}
			_, err := f.service.StartCanary(context.Background(), q, f.candidateProposer)
			requireFailureKind(t, err, FailureBusy)
			assertNoRolloutStateWrites(t, f.tx, err)
			if f.tx.begins != 1 || f.tx.reads != 2 || !reflect.DeepEqual(before, f.tx.scope) {
				t.Fatalf("BUSY must follow locked Scope + receipt read only: begins=%d reads=%d", f.tx.begins, f.tx.reads)
			}
		})
	}
}

func TestRolloutKnownInputAndApprovalFailuresAreTyped(t *testing.T) {
	for _, operation := range []string{"propose", "start", "promote", "rollback"} {
		for _, input := range []string{"nil context", "malformed command"} {
			t.Run(operation+"/"+input, func(t *testing.T) {
				f := newRolloutFixture(t)
				f.service.bundles = NewBundleRegistrationService(nil, nil)
				ctx := context.Background()
				id := "valid-command"
				if input == "nil context" {
					ctx = nil
				} else {
					id = " bad command "
				}
				var err error
				switch operation {
				case "propose":
					_, err = f.service.Propose(ctx, ProposeRequest{CommandID: id, Nonce: "nonce"})
				case "start":
					_, err = f.service.StartCanary(ctx, StartCanaryRequest{CommandID: id, Nonce: "nonce"}, f.candidateProposer)
				case "promote":
					f.request.CommandID = id
					_, err = f.service.Promote(ctx, f.request, f.candidateProposer, f.transitionProposer)
				case "rollback":
					_, err = f.service.Rollback(ctx, RollbackRequest{CommandID: id, Nonce: "nonce"})
				}
				requireFailureKind(t, err, FailureInvalid)
				assertNoRolloutStateWrites(t, f.tx, err)
				if f.tx.begins != 0 {
					t.Fatal("invalid command reached transaction")
				}
			})
		}
	}
	f := newRolloutFixture(t)
	f.request.CandidateApprovals = nil
	_, err := f.promote()
	requireFailureKind(t, err, FailureForbidden)
	if !errors.Is(err, domain.ErrInvalidApproval) {
		t.Fatal("approval cause lost")
	}
	assertNoRolloutStateWrites(t, f.tx, err)
}

func TestProposeKnownMalformedAndUnsupportedInputs(t *testing.T) {
	for _, input := range []string{"scope", "key ID", "bundle", "schema"} {
		t.Run(input, func(t *testing.T) {
			f := newRolloutFixture(t)
			f.service.bundles = NewBundleRegistrationService(nil, nil)
			q := ProposeRequest{CommandID: "propose", Nonce: "nonce", Scope: "scope", BundleKeyID: "key", Bundle: f.request.Candidate.Bundle}
			switch input {
			case "scope":
				q.Scope = " bad scope "
			case "key ID":
				q.BundleKeyID = " key "
			case "bundle":
				q.Bundle = domain.CanonicalBundle{}
			case "schema":
				var err error
				q.Bundle, err = domain.NewCanonicalBundle("paddock.bundle/999", []byte(`{"rule":true}`))
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.service.Propose(context.Background(), q)
			requireFailureKind(t, err, FailureInvalid)
			assertNoRolloutStateWrites(t, f.tx, err)
		})
	}
}

type staleScopeCASTx struct{ *rolloutTxFake }

func (f staleScopeCASTx) CompareAndSwapScope(context.Context, port.ScopeSnapshot, port.ScopeSnapshot) error {
	return fmt.Errorf("scope CAS: %w", port.ErrStaleWrite)
}

func TestRolloutCASMismatchAndExpectedValueMismatchAreStale(t *testing.T) {
	for _, mismatch := range []string{"expected value", "CAS", "active rollout"} {
		t.Run(mismatch, func(t *testing.T) {
			f := newRolloutFixture(t)
			switch mismatch {
			case "expected value":
				f.request.ExpectedScopeEpoch--
			case "CAS":
				f.service.tx = rolloutTransactorFunc(func(ctx context.Context, fn func(port.RolloutTx) error) error {
					return fn(staleScopeCASTx{f.tx})
				})
			case "active rollout":
				f.tx.scope.LiveRolloutID = nil
			}
			_, err := f.promote()
			requireFailureKind(t, err, FailureStale)
			if !errors.Is(err, port.ErrStaleWrite) {
				t.Fatal("stale write cause lost")
			}
			assertNoRolloutStateWrites(t, f.tx, err)
		})
	}
}

func TestRolloutNegativeReceiptReplayConflictAndExpiry(t *testing.T) {
	for _, operation := range []string{"propose", "start", "promote", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			f := newRolloutFixture(t)
			var invoke func() error
			var id string
			nonce := "receipt-nonce"
			switch operation {
			case "propose":
				id = "negative-propose"
				f.service.bundles = NewBundleRegistrationService(nil, nil)
				invoke = func() error {
					_, err := f.service.Propose(context.Background(), ProposeRequest{CommandID: id, Nonce: nonce, Scope: "scope", BundleKeyID: " invalid "})
					return err
				}
			case "start":
				id = "negative-start"
				f.tx.scope.LiveRolloutID = nil
				root := f.tx.scope.Roots["root-b"]
				invoke = func() error {
					_, err := f.service.StartCanary(context.Background(), StartCanaryRequest{CommandID: id, Nonce: nonce, Scope: "scope", Rollout: "rollout", Root: "root-b", Candidate: f.request.Candidate, ExpectedScopeEpoch: f.tx.scope.ActivationEpoch, ExpectedRootEpoch: root.AuthorizationEpoch, ExpectedSecurityEpoch: 7}, f.candidateProposer)
					return err
				}
			case "promote":
				id = f.request.CommandID
				f.request.CandidateApprovals = nil
				invoke = func() error { f.request.Nonce = nonce; _, err := f.promote(); return err }
			case "rollback":
				id = "negative-rollback"
				// The persisted rollout is valid, but the submitted scope is malformed.
				invoke = func() error {
					_, err := f.service.Rollback(context.Background(), RollbackRequest{CommandID: id, Nonce: nonce, Scope: " bad scope ", Rollout: "rollout", ExpectedState: f.tx.rollout.State, ExpectedScopeEpoch: f.tx.scope.ActivationEpoch, ExpectedSecurityEpoch: 7, ExpectedRootEpochs: lockedTargetEpochs(f.tx.scope, f.tx.rollout.Targets)})
					return err
				}
			}
			before := f.tx.scope
			first := invoke()
			assertNoRolloutStateWrites(t, f.tx, first)
			original, ok := f.tx.receipts[id]
			if !ok || original.Status != "REJECTED" || !reflect.DeepEqual(before, f.tx.scope) {
				t.Fatalf("no deterministic denial: %v %+v", first, original)
			}
			reads := f.tx.reads
			second := invoke()
			if !reflect.DeepEqual(CommandErrorResponse(first), CommandErrorResponse(second)) || f.tx.reads != reads+1 || len(f.tx.writes) != 1 {
				t.Fatalf("negative replay re-executed: %v", second)
			}
			nonce = "modified-payload"
			if err := invoke(); CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
				t.Fatalf("modified request accepted: %v", err)
			}
			nonce = "receipt-nonce"
			expired := original
			expired.Expired, expired.Response = true, []byte(port.ReceiptTombstoneResponse)
			f.tx.receipts[id] = expired
			if err := invoke(); !errors.Is(err, port.ErrReceiptExpired) || CommandErrorResponse(err).Code != "RECEIPT_EXPIRED" {
				t.Fatalf("expiry not enforced: %v", err)
			}
			nonce = "modified-after-expiry"
			if err := invoke(); errors.Is(err, port.ErrReceiptExpired) || CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
				t.Fatalf("expiry masked digest conflict: %v", err)
			}
			if !reflect.DeepEqual(f.tx.receipts[id], expired) || len(f.tx.writes) != 1 {
				t.Fatal("terminal status/digest overwritten or command ID reused")
			}
		})
	}
}
