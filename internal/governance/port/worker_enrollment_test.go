package port_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// Compile-time contract: persistence accepts only a domain-verified value, never
// a caller's boolean assertion or raw proof, and consumes+inserts in one call.
type enrollmentContract interface {
	CreateEnrollmentChallenge(context.Context, domain.EnrollmentChallenge) error
	ReadEnrollmentChallenge(context.Context, string) (domain.EnrollmentChallenge, error)
	ConsumeEnrollment(context.Context, domain.VerifiedWorkerEnrollment, domain.WorkerID) (domain.QuarantinedWorker, error)
}

var _ enrollmentContract = (port.WorkerEnrollmentStore)(nil)

func TestWorkerEnrollmentPortCannotManufactureVerifiedProof(t *testing.T) {
	if (domain.VerifiedWorkerEnrollment{}).Validate() == nil {
		t.Fatal("zero value proof grants enrollment")
	}
	typ := reflect.TypeOf(domain.VerifiedWorkerEnrollment{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Fatalf("caller-writable proof field %s", typ.Field(i).Name)
		}
	}
	// Enrollment is not a Scope, Trust, or Authority promotion API.
	worker := reflect.TypeOf(domain.QuarantinedWorker{})
	for _, name := range []string{"ScopeID", "Scope", "Trust", "Authority"} {
		if _, found := worker.FieldByName(name); found {
			t.Fatalf("enrollment exposes %s", name)
		}
	}
}
