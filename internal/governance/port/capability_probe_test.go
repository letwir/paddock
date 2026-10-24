package port_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type capabilityProbeFunc func(context.Context, domain.CapabilityProbeRequest, time.Time) ([]domain.CoordinatorProbeEvidence, error)

func (f capabilityProbeFunc) Observe(ctx context.Context, r domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
	return f(ctx, r, at)
}

var _ port.CapabilityProbe = capabilityProbeFunc(nil)

func TestCapabilityProbeTypedContract(t *testing.T) {
	probeErr := errors.New("probe unavailable")
	for _, tc := range []struct {
		name     string
		cancel   bool
		probeErr error
	}{
		{"observation", false, nil}, {"probe error", false, probeErr}, {"cancellation", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			r := domain.CapabilityProbeRequest{WorkerID: "worker", SessionID: "session"}
			var probe port.CapabilityProbe = capabilityProbeFunc(func(got context.Context, request domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
				if at.IsZero() || got != ctx || request.WorkerID != r.WorkerID || request.SessionID != r.SessionID {
					t.Fatal("probe request/context changed")
				}
				if err := got.Err(); err != nil {
					return nil, err
				}
				return []domain.CoordinatorProbeEvidence{{Name: "cpu", Value: "x"}}, tc.probeErr
			})
			_, err := probe.Observe(ctx, r, time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
			want := tc.probeErr
			if tc.cancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("err=%v want=%v", err, want)
			}
		})
	}
}
