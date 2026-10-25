package port_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type credentialPortStub struct{}

func (credentialPortStub) IssueWorkerCredential(context.Context, domain.WorkerCredential) error {
	return nil
}
func (credentialPortStub) RevokeWorkerCredential(context.Context, string) error { return nil }
func (credentialPortStub) CurrentCredentialIssuer(context.Context, string) (domain.CredentialIssuerContext, error) {
	return domain.CredentialIssuerContext{}, domain.ErrWorkerCredential
}

var _ port.WorkerCredentialStore = credentialPortStub{}
var _ port.CredentialIssuerProvider = credentialPortStub{}

func TestSafetyGateCredentialCapabilityIsMandatoryAndReadOnly(t *testing.T) {
	gate := reflect.TypeOf((*port.SafetyGateTx)(nil)).Elem()
	for _, name := range []string{"LockScope", "ValidateCurrentLease", "LockWorkerCredential", "LockCurrentCredentialIssuer"} {
		if _, ok := gate.MethodByName(name); !ok {
			t.Fatalf("missing mandatory Gate capability %s", name)
		}
	}
	for _, name := range []string{"IssueWorkerCredential", "RevokeWorkerCredential", "Exec", "InsertCommandReceipt", "UpdateCredentialIssuer", "UpdateWorkerIssuerContext"} {
		if _, ok := gate.MethodByName(name); ok {
			t.Fatalf("Gate exposed mutation %s", name)
		}
	}
	if field, ok := reflect.TypeOf(domain.HighRiskAuthorization{}).FieldByName("Credential"); !ok || field.Type != reflect.TypeOf(domain.WorkerCredentialBinding{}) {
		t.Fatal("missing typed credential binding")
	}
	// Authentication data cannot carry capability/Scope/Trust/Authority fields.
	c := reflect.TypeOf(domain.WorkerCredential{})
	for _, name := range []string{"Scope", "Capabilities", "Trust", "Authority", "Grant", "AuthorizationEpoch", "SecurityEpoch", "PolicyDigest"} {
		if _, ok := c.FieldByName(name); ok {
			t.Fatalf("credential carries authority field %s", name)
		}
	}
}

func TestWorkerCredentialStoreHasNoIssuerMutationCapability(t *testing.T) {
	store := reflect.TypeOf((*port.WorkerCredentialStore)(nil)).Elem()
	if store.NumMethod() != 2 {
		t.Fatal("unexpected Coordinator store capability")
	}
	for _, name := range []string{"IssueWorkerCredential", "RevokeWorkerCredential"} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("unexpected store API: missing %s", name)
		}
	}
	gate := reflect.TypeOf((*port.SafetyGateTx)(nil)).Elem()
	if gate.NumMethod() != 6 {
		t.Fatal("unexpected Gate capability")
	}
}
