package domain

import (
	"errors"
	"testing"
)

func TestAttemptLeaseBindingValidation(t *testing.T) {
	valid := AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: "worker", SessionID: "session", LeaseEpoch: 1}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*AttemptLeaseBinding){
		"missing work":    func(b *AttemptLeaseBinding) { b.WorkOrderID = "" },
		"missing attempt": func(b *AttemptLeaseBinding) { b.AttemptID = "" },
		"missing worker":  func(b *AttemptLeaseBinding) { b.WorkerID = "" },
		"missing session": func(b *AttemptLeaseBinding) { b.SessionID = "" },
		"whitespace":      func(b *AttemptLeaseBinding) { b.SessionID = " session" },
		"zero epoch":      func(b *AttemptLeaseBinding) { b.LeaseEpoch = 0 },
		"negative epoch":  func(b *AttemptLeaseBinding) { b.LeaseEpoch = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			b := valid
			change(&b)
			if !errors.Is(b.Validate(), ErrInvalidLease) {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestHighRiskAuthorizationKeepsRootGrantReusable(t *testing.T) {
	grant := Grant{Root: "root", AuthorizationEpoch: 3, SecurityEpoch: 7}
	first := HighRiskAuthorization{Grant: grant, Lease: AttemptLeaseBinding{WorkOrderID: "work", AttemptID: "attempt", WorkerID: "worker", SessionID: "session", LeaseEpoch: 1}}
	second := first
	second.Lease.AttemptID = "next-attempt"
	second.Lease.LeaseEpoch++
	first.Credential = WorkerCredentialBinding{ID: "first"}
	second.Credential = WorkerCredentialBinding{ID: "second"}
	if first.Grant != grant || second.Grant != grant || first.Lease == second.Lease {
		t.Fatal("attempt binding contaminated reusable Root Grant")
	}
	if first.Credential.ID == second.Credential.ID {
		t.Fatal("credential cannot bind separate uses")
	}
}
