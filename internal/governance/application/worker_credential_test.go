package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type credentialIssuerStub struct {
	issuer domain.CredentialIssuerContext
	err    error
	calls  int
}

func (s *credentialIssuerStub) CurrentCredentialIssuer(_ context.Context, id string) (domain.CredentialIssuerContext, error) {
	s.calls++
	if s.err != nil {
		return domain.CredentialIssuerContext{}, s.err
	}
	return s.issuer, nil
}
func unitCredentialIssuer() *credentialIssuerStub {
	return &credentialIssuerStub{issuer: domain.CredentialIssuerContext{IssuerID: "issuer", Revision: 1, CeilingDigest: domain.Digest(strings.Repeat("a", 64))}}
}
func unitCredentialKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
}
func unitCredential(lease domain.AttemptLeaseBinding) domain.WorkerCredential {
	fp, _ := domain.FingerprintWorkerKey(unitCredentialKey().Public().(ed25519.PublicKey))
	return domain.WorkerCredential{ID: strings.Repeat("1", 64), Fingerprint: fp, Lease: lease, Audience: "coordinator", Issuer: unitCredentialIssuer().issuer}
}
func gateRequest() domain.CredentialRequest {
	r, _ := domain.NewCanonicalRequest("command", "nonce", []byte(`{"action":"fixture"}`))
	return domain.CredentialRequest{CommandID: "command", Nonce: "nonce", RequestDigest: r.Digest()}
}

type credentialStoreStub struct {
	issued  []domain.WorkerCredential
	revoked []string
	err     error
}

func (s *credentialStoreStub) IssueWorkerCredential(_ context.Context, c domain.WorkerCredential) error {
	if s.err != nil {
		return s.err
	}
	s.issued = append(s.issued, c)
	return nil
}
func (s *credentialStoreStub) RevokeWorkerCredential(_ context.Context, id string) error {
	if s.err != nil {
		return s.err
	}
	s.revoked = append(s.revoked, id)
	return nil
}

func TestWorkerCredentialServiceTrustedContextIssueRevoke(t *testing.T) {
	store, issuer := &credentialStoreStub{}, unitCredentialIssuer()
	service := NewWorkerCredentialService(store, issuer, "coordinator", "issuer")
	service.random = bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	lease := gateAuthorization(domain.Grant{}).Lease
	fp := unitCredential(lease).Fingerprint
	c, err := service.Issue(context.Background(), fp, lease)
	if err != nil || len(store.issued) != 1 || c.Issuer != issuer.issuer || c.Audience != "coordinator" || c.Revoked || c.ID != strings.Repeat("07", 32) {
		t.Fatalf("issuance error: %v", err)
	}
	issuer.issuer.Revision++
	next, err := service.Issue(context.Background(), fp, lease)
	if err != nil || next.Issuer.Revision != 2 || issuer.calls != 2 {
		t.Fatal("issuer context cached")
	}
	if err := service.Revoke(context.Background(), c.ID); err != nil || len(store.revoked) != 1 {
		t.Fatal(err)
	}
}

func TestWorkerCredentialServiceFailsClosed(t *testing.T) {
	cause := errors.New("offline issuer")
	for _, tc := range []string{"issuer error", "wrong issuer", "empty issuer", "bad audience", "entropy failure", "db error", "invalid fingerprint", "invalid lease"} {
		t.Run(tc, func(t *testing.T) {
			store, issuer := &credentialStoreStub{}, unitCredentialIssuer()
			service := NewWorkerCredentialService(store, issuer, "coordinator", "issuer")
			service.random = bytes.NewReader(bytes.Repeat([]byte{7}, 32))
			lease := gateAuthorization(domain.Grant{}).Lease
			fp := unitCredential(lease).Fingerprint
			switch tc {
			case "issuer error":
				issuer.err = cause
			case "wrong issuer":
				issuer.issuer.IssuerID = "other"
			case "empty issuer":
				issuer.issuer = domain.CredentialIssuerContext{}
			case "bad audience":
				service.audience = ""
			case "entropy failure":
				service.random = bytes.NewReader(nil)
			case "db error":
				store.err = cause
			case "invalid fingerprint":
				fp = ""
			case "invalid lease":
				lease.LeaseEpoch = 0
			}
			if _, err := service.Issue(context.Background(), fp, lease); err == nil || len(store.issued) != 0 {
				t.Fatal("invalid issuance persisted")
			}
		})
	}
	var service *WorkerCredentialService
	if _, err := service.Issue(context.Background(), "", domain.AttemptLeaseBinding{}); err == nil {
		t.Fatal("nil service")
	}
	store := &credentialStoreStub{}
	service = NewWorkerCredentialService(store, unitCredentialIssuer(), "coordinator", "issuer")
	if err := service.Revoke(context.Background(), "bad"); err == nil || len(store.revoked) != 0 {
		t.Fatal("invalid revoke reached store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Issue(ctx, "", domain.AttemptLeaseBinding{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSafetyGateCredentialFailureMatrix(t *testing.T) {
	for _, name := range []string{"missing binding", "missing row", "DB error", "revoked", "bad key", "bad signature", "stale credential lease", "wrong credential worker", "wrong credential session", "wrong credential attempt", "wrong fingerprint", "audience mismatch", "issuer unavailable", "issuer id mismatch", "issuer revision mismatch", "issuer digest mismatch", "changed command", "changed request digest", "changed nonce", "missing issuer row"} {
		t.Run(name, func(t *testing.T) {
			f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
			auth := gateAuthorization(gateGrant(f.snapshot))
			c := unitCredential(auth.Lease)
			f.credential = &c
			issuer := unitCredentialIssuer()
			f.issuer = &issuer.issuer
			gate := NewSafetyGate(f, "coordinator")
			r := gateRequest()
			switch name {
			case "missing binding":
				auth.Credential = domain.WorkerCredentialBinding{}
			case "missing row":
				f.credentialErr = domain.ErrWorkerCredential
			case "DB error":
				f.credentialErr = domain.ErrDatabaseUnavailable
			case "revoked":
				c.Revoked = true
			case "bad key":
				f.credentialKey = make([]byte, 32)
			case "bad signature":
				auth.Credential.Signature[0] ^= 1
			case "stale credential lease":
				c.Lease.LeaseEpoch++
			case "wrong credential worker":
				c.Lease.WorkerID = domain.WorkerID("worker_" + strings.Repeat("f", 64))
			case "wrong credential session":
				c.Lease.SessionID = "other"
			case "wrong credential attempt":
				c.Lease.AttemptID = "other"
			case "wrong fingerprint":
				c.Fingerprint = domain.WorkerKeyFingerprint(strings.Repeat("f", 64))
			case "audience mismatch":
				gate.audience = "other"
			case "issuer unavailable":
				f.issuerErr = domain.ErrWorkerCredential
			case "issuer id mismatch":
				issuer.issuer.IssuerID = "other"
			case "issuer revision mismatch":
				issuer.issuer.Revision++
			case "issuer digest mismatch":
				issuer.issuer.CeilingDigest = domain.Digest(strings.Repeat("f", 64))
			case "changed command":
				r.CommandID = "other"
			case "changed request digest":
				r.RequestDigest = domain.Digest(strings.Repeat("f", 64))
			case "changed nonce":
				r.Nonce = "other"
			case "missing issuer row":
				issuer.issuer = domain.CredentialIssuerContext{}
			}
			if err := gate.CheckHighRiskAction(context.Background(), "scope", auth, r); err == nil {
				t.Fatal("invalid authentication accepted")
			}
		})
	}
}

func TestSafetyGateReloadsCredentialAndIssuerPerUse(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	auth := gateAuthorization(gateGrant(f.snapshot))
	c := unitCredential(auth.Lease)
	f.credential = &c
	issuer := unitCredentialIssuer()
	f.issuer = &issuer.issuer
	gate := NewSafetyGate(f, "coordinator")
	ctx := context.Background()
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); err != nil {
		t.Fatal(err)
	}
	// Receipt idempotency permits an identical authenticated retry, not a second
	// effect. Revocation/issuer changes still deny that same proof immediately.
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); err != nil {
		t.Fatal(err)
	}
	c.Revoked = true
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal(err)
	}
	c.Revoked = false
	issuer.issuer.Revision++
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal(err)
	}
	issuer.issuer = c.Issuer
	issuer.issuer.CeilingDigest = domain.Digest(strings.Repeat("f", 64))
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("updated ceiling cached")
	}
	f.issuerErr = domain.ErrWorkerCredential // registry row deleted after prior use
	if err := gate.CheckHighRiskAction(ctx, "scope", auth, gateRequest()); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("deleted registry cached")
	}
	if f.issuerCalls != 6 || f.calls != 6 || f.leaseCalls != 8 {
		t.Fatal("cached Gate state")
	}
}

func TestAuthenticatedCommandUsesExistingReceiptReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	auth := gateAuthorization(gateGrant(f.snapshot))
	c := unitCredential(auth.Lease)
	f.credential = &c
	gate := NewSafetyGate(f, "coordinator")
	ledger := &safetyFake{receipts: map[string]port.CommandReceipt{}}
	effects, replays := 0, 0
	invoke := func(a domain.HighRiskAuthorization, r domain.CredentialRequest) error {
		if err := gate.CheckHighRiskAction(ctx, "scope", a, r); err != nil {
			return err
		}
		return withinReceiptCommand(ctx, r.CommandID, r.RequestDigest, ledger.WithinTransaction,
			func(tx port.GovernanceTx, response []byte) error {
				replays++
				if string(response) != `{"done":true}` {
					return errors.New("unexpected replay")
				}
				return nil
			},
			func(tx port.GovernanceTx) error {
				effects++
				return tx.InsertCommandReceipt(ctx, port.CommandReceipt{CommandID: r.CommandID, RequestDigest: r.RequestDigest, Status: "SUCCEEDED", Response: []byte(`{"done":true}`)})
			})
	}
	request := gateRequest()
	if err := invoke(auth, request); err != nil {
		t.Fatal(err)
	}
	if err := invoke(auth, request); err != nil {
		t.Fatal(err)
	}
	if effects != 1 || replays != 1 || len(ledger.receipts) != 1 {
		t.Fatal("authenticated retry duplicated effect")
	}
	changed := request
	changed.RequestDigest = domain.Digest(strings.Repeat("f", 64))
	// Even a fresh valid signature cannot reuse a committed command ID for a
	// different canonical request. This is M04-S02, not a Credential nonce ledger.
	message, err := c.SigningBytes("scope", auth.Grant, changed)
	if err != nil {
		t.Fatal(err)
	}
	other := auth
	other.Credential.Signature = ed25519.Sign(unitCredentialKey(), message)
	if err := invoke(other, changed); CommandErrorResponse(err).Code != "COMMAND_ID_CONFLICT" {
		t.Fatalf("changed command: %v", err)
	}
	c.Revoked = true
	if err := invoke(auth, request); !errors.Is(err, domain.ErrWorkerCredential) {
		t.Fatal("revoked retry reached Receipt")
	}
	if effects != 1 || replays != 1 || len(ledger.receipts) != 1 {
		t.Fatal("denial mutated command effects")
	}
}
