package application

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

type capabilityProbeFunc func(context.Context, domain.CapabilityProbeRequest, time.Time) ([]domain.CoordinatorProbeEvidence, error)

func (f capabilityProbeFunc) Observe(ctx context.Context, r domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
	return f(ctx, r, at)
}

func applicationCapabilityFixture() (domain.CapabilityProbeRequest, []domain.CoordinatorProbeEvidence, time.Time) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	r := domain.CapabilityProbeRequest{WorkerID: "worker", SessionID: "session", Requirements: []domain.CapabilityRequirement{{Name: "cpu", Value: "x"}}}
	e := domain.CoordinatorProbeEvidence{Name: "cpu", Value: "x", ObservedAt: now, ValidUntil: now.Add(time.Hour), Provenance: domain.ProbeProvenance{
		Source: domain.CoordinatorObservedProbe, CoordinatorID: "coordinator", ProbeID: "probe", WorkerID: r.WorkerID, SessionID: r.SessionID}}
	return r, []domain.CoordinatorProbeEvidence{e}, now
}

func TestCapabilityEvidenceServiceValidatesObservations(t *testing.T) {
	probeErr := errors.New("probe unavailable")
	cases := []struct {
		name   string
		change func(*[]domain.CoordinatorProbeEvidence, *time.Time)
		err    error
		cancel bool
		valid  bool
	}{
		{"valid", nil, nil, false, true},
		{"error", nil, probeErr, false, false},
		{"cancel during probe", nil, nil, true, false},
		{"missing", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { *e = nil }, nil, false, false},
		{"duplicate", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { *e = append(*e, (*e)[0]) }, nil, false, false},
		{"extra", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) {
			extra := (*e)[0]
			extra.Name = "other"
			*e = append(*e, extra)
		}, nil, false, false},
		{"malformed", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Provenance.ProbeID = "" }, nil, false, false},
		{"claim", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Provenance.Source = "worker_claim" }, nil, false, false},
		{"attestation", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) {
			(*e)[0].Provenance.Source = "hardware_attestation"
		}, nil, false, false},
		{"expiry boundary", func(e *[]domain.CoordinatorProbeEvidence, at *time.Time) { (*e)[0].ValidUntil = *at }, nil, false, false},
		{"future", func(e *[]domain.CoordinatorProbeEvidence, at *time.Time) {
			(*e)[0].ObservedAt = at.Add(time.Nanosecond)
		}, nil, false, false},
		{"wrong worker", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Provenance.WorkerID = "other" }, nil, false, false},
		{"wrong session", func(e *[]domain.CoordinatorProbeEvidence, _ *time.Time) { (*e)[0].Provenance.SessionID = "other" }, nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, observations, now := applicationCapabilityFixture()
			if tc.change != nil {
				tc.change(&observations, &now)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := 0
			service := NewCapabilityEvidenceService(capabilityProbeFunc(func(_ context.Context, request domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
				called++
				if !reflect.DeepEqual(request, r) || at != now {
					t.Fatal("wrong probe request")
				}
				if tc.cancel {
					cancel()
				}
				return observations, tc.err
			}))
			got, err := service.Observe(ctx, r, now)
			if called != 1 || (err == nil) != tc.valid {
				t.Fatalf("called=%d err=%v", called, err)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("lost error: %v", err)
			}
			if tc.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if err != nil && got != nil {
				t.Fatal("partial evidence escaped failure")
			}
			if tc.valid {
				if !reflect.DeepEqual(got, observations) {
					t.Fatal("observation changed")
				}
				observations[0].Value = "mutated"
				if got[0].Value != "x" {
					t.Fatal("result aliases probe-owned data")
				}
			}
		})
	}
}

func TestCapabilityEvidenceServiceRejectsBeforeProbe(t *testing.T) {
	for _, name := range []string{"nil context", "canceled", "nil service", "nil probe", "invalid request", "zero evaluation", "malformed evaluation"} {
		t.Run(name, func(t *testing.T) {
			r, _, now := applicationCapabilityFixture()
			called := false
			s := NewCapabilityEvidenceService(capabilityProbeFunc(func(context.Context, domain.CapabilityProbeRequest, time.Time) ([]domain.CoordinatorProbeEvidence, error) {
				called = true
				return nil, nil
			}))
			ctx := context.Background()
			switch name {
			case "nil context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil service":
				s = nil
			case "nil probe":
				s = NewCapabilityEvidenceService(nil)
			case "invalid request":
				r.Requirements[0].Name = ""
			case "zero evaluation":
				now = time.Time{}
			case "malformed evaluation":
				now = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			got, err := s.Observe(ctx, r, now)
			if err == nil || got != nil || called {
				t.Fatalf("err=%v called=%v got=%v", err, called, got)
			}
		})
	}
}

func TestCapabilityEvidenceServiceSnapshotsRequest(t *testing.T) {
	r, observations, now := applicationCapabilityFixture()
	s := NewCapabilityEvidenceService(capabilityProbeFunc(func(_ context.Context, request domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
		request.Requirements[0].Value = "mutated"
		return observations, nil
	}))
	if _, err := s.Observe(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
	if r.Requirements[0].Value != "x" {
		t.Fatal("probe mutated caller request")
	}
}
