package application

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type gateTransactor struct {
	snapshot            port.ScopeSnapshot
	lockErr             error
	calls               int
	leaseErr            error
	leaseCalls          int
	inTransaction       bool
	order               []string
	binding             domain.AttemptLeaseBinding
	credential          *domain.WorkerCredential
	credentialErr       error
	credentialKey       []byte
	issuer              *domain.CredentialIssuerContext
	issuerErr           error
	issuerCalls         int
	leaseErrAfterIssuer error
}

func TestSafetyGateRequiresFreshLeaseInAuthorityTransaction(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f, "coordinator")
	authorization := gateAuthorization(gateGrant(f.snapshot))
	if err := gate.CheckHighRiskAction(context.Background(), "scope", authorization, gateRequest()); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || f.leaseCalls != 2 || f.binding != authorization.Lease || !reflect.DeepEqual(f.order, []string{"authority", "lease", "credential", "issuer", "lease"}) {
		t.Fatalf("not composed in order: %+v", f)
	}
	// The same Gate must consult the lease again, not cache the previous success.
	for _, denial := range []error{domain.ErrInvalidLease, domain.ErrDatabaseUnavailable} {
		f.leaseErr = denial
		if err := gate.CheckHighRiskAction(context.Background(), "scope", authorization, gateRequest()); !errors.Is(err, denial) {
			t.Fatalf("fresh lease denial: %v", err)
		}
	}
	if f.calls != 3 || f.leaseCalls != 4 {
		t.Fatal("lease validation was cached")
	}
}

func TestSafetyGateRejectsMissingBindingAndStaleGrantBeforeLeaseCheck(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f, "coordinator")
	auth := gateAuthorization(gateGrant(f.snapshot))
	missing := auth
	missing.Lease = domain.AttemptLeaseBinding{}
	if err := gate.CheckHighRiskAction(context.Background(), "scope", missing, gateRequest()); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatal(err)
	}
	f.snapshot.Roots["root-a"] = domain.RootAuthority{Policy: auth.Grant.Policy, AuthorizationEpoch: 4}
	if err := gate.CheckHighRiskAction(context.Background(), "scope", auth, gateRequest()); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatal(err)
	}
	if f.leaseCalls != 0 {
		t.Fatal("invalid authorization reached lease check")
	}
}

func TestSafetyGateRollbackEpochBoundaryWithActiveLease(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	f.snapshot.ActivationEpoch = 42
	before := gateAuthorization(gateGrant(f.snapshot))
	// Same v1 digest, but a newer Root epoch after one-transaction Rollback.
	f.snapshot.ActivationEpoch = 43
	root := f.snapshot.Roots["root-a"]
	root.AuthorizationEpoch++
	f.snapshot.Roots["root-a"] = root
	gate := NewSafetyGate(f, "coordinator")
	if err := gate.CheckHighRiskAction(context.Background(), "scope", before, gateRequest()); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatal(err)
	}
	current := gateAuthorization(gateGrant(f.snapshot))
	if err := gate.CheckHighRiskAction(context.Background(), "scope", current, gateRequest()); err != nil {
		t.Fatal(err)
	}
	f.leaseErr = domain.ErrInvalidLease
	if err := gate.CheckHighRiskAction(context.Background(), "scope", current, gateRequest()); !errors.Is(err, domain.ErrInvalidLease) {
		t.Fatal(err)
	}
	if f.snapshot.SecurityEpoch != 7 {
		t.Fatal("Rollback advanced Security Epoch")
	}
}

func (f *gateTransactor) WithinSafetyGateTransaction(ctx context.Context, fn func(port.SafetyGateTx) error) error {
	f.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	f.inTransaction = true
	defer func() { f.inTransaction = false }()
	return fn(f)
}
func (f *gateTransactor) LockScope(context.Context, domain.ScopeID) (port.ScopeSnapshot, error) {
	f.order = append(f.order, "authority")
	if f.lockErr != nil {
		return port.ScopeSnapshot{}, f.lockErr
	}
	return f.snapshot, nil
}
func (f *gateTransactor) LockRollout(context.Context, domain.ScopeID, domain.RolloutID) (port.RolloutSnapshot, error) {
	return port.RolloutSnapshot{}, errors.New("unexpected rollout lock")
}
func (f *gateTransactor) ValidateTargets(_ context.Context, _ domain.ScopeID, roots []domain.RootID) error {
	if !reflect.DeepEqual(roots, []domain.RootID{"root-a"}) {
		return errors.New("unexpected roots")
	}
	return nil
}
func (f *gateTransactor) ValidateCurrentLease(_ context.Context, scope domain.ScopeID, root domain.RootID, binding domain.AttemptLeaseBinding) error {
	if !f.inTransaction || scope != "scope" || root != "root-a" {
		return errors.New("lease validation outside authority transaction")
	}
	f.leaseCalls++
	f.order = append(f.order, "lease")
	f.binding = binding
	return f.leaseErr
}

func gateAuthorization(grant domain.Grant) domain.HighRiskAuthorization {
	authorization := domain.HighRiskAuthorization{Grant: grant, Lease: domain.AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: domain.WorkerID("worker_" + strings.Repeat("2", 64)), SessionID: "session", LeaseEpoch: 1}}
	credential := unitCredential(authorization.Lease)
	message, err := credential.SigningBytes("scope", grant, gateRequest())
	if err == nil {
		authorization.Credential = domain.WorkerCredentialBinding{ID: credential.ID, Signature: ed25519.Sign(unitCredentialKey(), message)}
	}
	return authorization
}

func gateState(mode domain.ScopeMode, epoch domain.Epoch) port.ScopeSnapshot {
	return port.ScopeSnapshot{ScopeID: "scope", ActivationEpoch: 1, SecurityEpoch: epoch, Mode: mode, Roots: map[domain.RootID]domain.RootAuthority{"root-a": {Policy: domain.PolicyBinding{Digest: testDigest()}, AuthorizationEpoch: 3}}}
}
func gateGrant(state port.ScopeSnapshot) domain.Grant {
	root := state.Roots["root-a"]
	return domain.Grant{Root: "root-a", Policy: root.Policy, AuthorizationEpoch: root.AuthorizationEpoch, SecurityEpoch: state.SecurityEpoch}
}

func TestSafetyGateReadsAuthorityFreshForEveryCheck(t *testing.T) {
	f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7)}
	gate := NewSafetyGate(f, "coordinator")
	ctx := context.Background()
	grant := gateGrant(f.snapshot)
	if err := gate.CheckNewDispatch(ctx, "scope", "root-a"); err != nil {
		t.Fatal(err)
	}
	if err := gate.CheckNewGrant(ctx, "scope", "root-a"); err != nil {
		t.Fatal(err)
	}
	if err := gate.CheckHighRiskAction(ctx, "scope", gateAuthorization(grant), gateRequest()); err != nil {
		t.Fatal(err)
	}

	// Simulate a committed emergency stop after construction: same gate must
	// observe SAFE_STOPPED and the advanced security epoch on every call.
	f.snapshot = gateState(domain.ScopeSafeStop, 8)
	for name, check := range map[string]func() error{
		"dispatch":              func() error { return gate.CheckNewDispatch(ctx, "scope", "root-a") },
		"grant":                 func() error { return gate.CheckNewGrant(ctx, "scope", "root-a") },
		"stale high-risk grant": func() error { return gate.CheckHighRiskAction(ctx, "scope", gateAuthorization(grant), gateRequest()) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, domain.ErrSafeStopped) {
				t.Fatalf("got %v, want safe-stopped denial", err)
			}
		})
	}
	if f.calls != 6 {
		t.Fatalf("transaction calls = %d, want 6", f.calls)
	}
}

func TestSafetyGateFailsClosedOnDatabaseAndFrozen(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		state   port.ScopeSnapshot
		lockErr error
		want    error
	}{
		{"database unavailable", gateState(domain.ScopeActive, 7), domain.ErrDatabaseUnavailable, domain.ErrDatabaseUnavailable},
		{"frozen", gateState(domain.ScopeFrozen, 7), nil, domain.ErrScopeFrozen},
		{"safe stopped", gateState(domain.ScopeSafeStop, 8), nil, domain.ErrSafeStopped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &gateTransactor{snapshot: tc.state, lockErr: tc.lockErr}
			if err := NewSafetyGate(f, "coordinator").CheckNewDispatch(ctx, "scope", "root-a"); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSafetyGateTransactorErrorFailsClosed(t *testing.T) {
	want := errors.New("database transaction failed")
	gate := NewSafetyGate(&gateTransactor{lockErr: want}, "coordinator")
	if err := gate.CheckNewGrant(context.Background(), "scope", "root-a"); !errors.Is(err, want) {
		t.Fatalf("got %v, want transaction error", err)
	}
}

func (f *gateTransactor) LockWorkerCredential(_ context.Context, id string) (domain.WorkerCredential, []byte, error) {
	if !f.inTransaction {
		return domain.WorkerCredential{}, nil, errors.New("credential outside transaction")
	}
	f.order = append(f.order, "credential")
	if f.credentialErr != nil {
		return domain.WorkerCredential{}, nil, f.credentialErr
	}
	c := unitCredential(f.binding)
	if f.credential != nil {
		c = *f.credential
	}
	if id != c.ID {
		return domain.WorkerCredential{}, nil, domain.ErrWorkerCredential
	}
	key := []byte(unitCredentialKey().Public().(ed25519.PublicKey))
	if f.credentialKey != nil {
		key = f.credentialKey
	}
	return c, key, nil
}

func (f *gateTransactor) LockCurrentCredentialIssuer(_ context.Context, id string) (domain.CredentialIssuerContext, error) {
	if !f.inTransaction {
		return domain.CredentialIssuerContext{}, errors.New("issuer outside transaction")
	}
	if len(f.order) == 0 || f.order[len(f.order)-1] != "credential" {
		return domain.CredentialIssuerContext{}, errors.New("issuer before credential lock")
	}
	f.order = append(f.order, "issuer")
	f.issuerCalls++
	if f.leaseErrAfterIssuer != nil {
		f.leaseErr = f.leaseErrAfterIssuer
	}
	if f.issuerErr != nil {
		return domain.CredentialIssuerContext{}, f.issuerErr
	}
	issuer := unitCredentialIssuer().issuer
	if f.issuer != nil {
		issuer = *f.issuer
	}
	if issuer.IssuerID != id {
		return domain.CredentialIssuerContext{}, domain.ErrWorkerCredential
	}
	return issuer, nil
}

func TestSafetyGateRechecksLeaseAfterCredentialAndIssuerLockWait(t *testing.T) {
	for _, cause := range []error{domain.ErrInvalidLease, domain.ErrDatabaseUnavailable} {
		f := &gateTransactor{snapshot: gateState(domain.ScopeActive, 7), leaseErrAfterIssuer: cause}
		auth := gateAuthorization(gateGrant(f.snapshot))
		if err := NewSafetyGate(f, "coordinator").CheckHighRiskAction(context.Background(), "scope", auth, gateRequest()); !errors.Is(err, cause) {
			t.Fatalf("stale lease after lock wait accepted: %v", err)
		}
		if f.leaseCalls != 2 || f.issuerCalls != 1 || !reflect.DeepEqual(f.order, []string{"authority", "lease", "credential", "issuer", "lease"}) {
			t.Fatal("lease not rechecked after locks in same transaction")
		}
	}
}
