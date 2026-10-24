package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func capabilityFixture() (CapabilityProbeRequest, CoordinatorProbeEvidence, time.Time) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	r := CapabilityProbeRequest{WorkerID: "worker", SessionID: "session", Requirements: []CapabilityRequirement{{"cpu", "x"}}}
	e := CoordinatorProbeEvidence{Name: "cpu", Value: "x", ObservedAt: now, ValidUntil: now.Add(time.Hour),
		Provenance: ProbeProvenance{Source: CoordinatorObservedProbe, CoordinatorID: "coordinator", ProbeID: "probe", WorkerID: r.WorkerID, SessionID: r.SessionID}}
	return r, e, now
}

func TestCapabilityEvidenceTypesRemainDistinct(t *testing.T) {
	types := []reflect.Type{reflect.TypeOf(WorkerCapabilityClaim{}), reflect.TypeOf(CoordinatorProbeEvidence{}), reflect.TypeOf(HardwareAttestation{})}
	for i, a := range types {
		for j, b := range types {
			if i != j && (a == b || a.ConvertibleTo(b)) {
				t.Fatalf("evidence types are interchangeable: %v %v", a, b)
			}
		}
	}
	// Even decoding claim/attestation-shaped data as a probe record cannot
	// manufacture the required Coordinator provenance and observation times.
	for _, input := range []any{WorkerCapabilityClaim{"cpu", "x"}, HardwareAttestation{Name: "cpu", Value: "x", Statement: "unverified"}} {
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var e CoordinatorProbeEvidence
		if err := json.Unmarshal(encoded, &e); err != nil {
			t.Fatal(err)
		}
		r, _, now := capabilityFixture()
		if err := ValidateCapabilityObservations(r, []CoordinatorProbeEvidence{e}, now); !errors.Is(err, ErrCapabilityEvidence) {
			t.Fatalf("accepted non-observation %T: %v", input, err)
		}
	}
}

func TestCapabilityObservationsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		change func(*CapabilityProbeRequest, *[]CoordinatorProbeEvidence, *time.Time)
		valid  bool
	}{
		{"fresh including observed boundary", func(*CapabilityProbeRequest, *[]CoordinatorProbeEvidence, *time.Time) {}, true},
		{"just before expiry", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, at *time.Time) {
			*at = (*e)[0].ValidUntil.Add(-time.Nanosecond)
		}, true},
		{"exact expiry", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, at *time.Time) {
			*at = (*e)[0].ValidUntil
		}, false},
		{"past expiry", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, at *time.Time) {
			*at = (*e)[0].ValidUntil.Add(time.Nanosecond)
		}, false},
		{"future observation", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, at *time.Time) {
			(*e)[0].ObservedAt = at.Add(time.Nanosecond)
		}, false},
		{"zero evaluation", func(_ *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, at *time.Time) { *at = time.Time{} }, false},
		{"malformed evaluation", func(_ *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, at *time.Time) {
			*at = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}, false},
		{"zero observation", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].ObservedAt = time.Time{}
		}, false},
		{"zero expiry", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].ValidUntil = time.Time{}
		}, false},
		{"malformed expiry", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}, false},
		{"empty interval", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].ValidUntil = (*e)[0].ObservedAt
		}, false},
		{"reversed interval", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].ValidUntil = (*e)[0].ObservedAt.Add(-time.Second)
		}, false},
		{"missing provenance", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance = ProbeProvenance{}
		}, false},
		{"claim provenance", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.Source = "worker_claim"
		}, false},
		{"attestation provenance", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.Source = "hardware_attestation"
		}, false},
		{"unknown provenance", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.Source = "unknown"
		}, false},
		{"missing coordinator", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.CoordinatorID = ""
		}, false},
		{"missing probe", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.ProbeID = ""
		}, false},
		{"malformed probe", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.ProbeID = " \n"
		}, false},
		{"wrong worker", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.WorkerID = "other"
		}, false},
		{"wrong session", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.SessionID = "other"
		}, false},
		{"malformed name", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Name = " " }, false},
		{"missing value", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Value = "" }, false},
		{"mismatch", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Value = "other" }, false},
		{"missing", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) { *e = nil }, false},
		{"extra", func(_ *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			extra := (*e)[0]
			extra.Name = "other"
			*e = append(*e, extra)
		}, false},
		{"duplicate evidence", func(r *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			r.Requirements = append(r.Requirements, CapabilityRequirement{"other", "x"})
			*e = append(*e, (*e)[0])
		}, false},
		{"duplicate requirement", func(r *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			r.Requirements = append(r.Requirements, r.Requirements[0])
			extra := (*e)[0]
			extra.Name = "other"
			*e = append(*e, extra)
		}, false},
		{"invalid requirement", func(r *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, _ *time.Time) {
			r.Requirements[0].Value = ""
		}, false},
		{"missing worker", func(r *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, _ *time.Time) { r.WorkerID = "" }, false},
		{"missing session", func(r *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, _ *time.Time) { r.SessionID = "" }, false},
		{"empty policy", func(r *CapabilityProbeRequest, e *[]CoordinatorProbeEvidence, _ *time.Time) {
			r.Requirements = nil
			*e = nil
		}, true},
		{"empty policy extra evidence", func(r *CapabilityProbeRequest, _ *[]CoordinatorProbeEvidence, _ *time.Time) { r.Requirements = nil }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, e, now := capabilityFixture()
			observations := []CoordinatorProbeEvidence{e}
			tc.change(&r, &observations, &now)
			err := ValidateCapabilityObservations(r, observations, now)
			if (err == nil) != tc.valid || (err != nil && !errors.Is(err, ErrCapabilityEvidence)) {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
