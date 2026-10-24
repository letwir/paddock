package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
)

var capabilityEvaluationTime = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func observedWorker(id, session string, evidence []Evidence) Worker {
	var observations []domain.CoordinatorProbeEvidence
	for _, e := range evidence {
		observations = append(observations, domain.CoordinatorProbeEvidence{
			Name: e.Name, Value: e.Value,
			Provenance: domain.ProbeProvenance{Source: domain.CoordinatorObservedProbe,
				CoordinatorID: "coordinator", ProbeID: "probe", WorkerID: id, SessionID: session},
			ObservedAt: capabilityEvaluationTime, ValidUntil: capabilityEvaluationTime.Add(time.Hour),
		})
	}
	return Worker{ID: id, SessionID: session, Evidence: append([]Evidence(nil), evidence...), observations: observations, evaluatedAt: capabilityEvaluationTime}
}

func TestPullReprobesPreviouslyAcceptedSnapshot(t *testing.T) {
	c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
	var accepted Worker
	var issued Permit
	gateCalls := 0
	gate := gateFunc(func(context.Context, Candidate, Worker) (bool, error) {
		gateCalls++
		return true, nil
	})
	p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gate, Trust: gate, Budget: gate,
		Store: storeFunc(func(_ context.Context, _ Candidate, w Worker, permit Permit, _ time.Duration) (Reservation, error) {
			accepted, issued = w, permit
			return Reservation{}, nil
		})}
	if _, err := p.Pull(context.Background(), c, Worker{ID: "worker", SessionID: "session"}, capabilityEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if !issued.Authorizes(c, accepted) || gateCalls != 3 {
		t.Fatal("did not obtain an internally accepted snapshot")
	}
	probeCalls := 0
	p.Probe = schedulerCapabilityProbe(func(context.Context, domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
		probeCalls++
		return nil, nil
	})
	if _, err := p.Pull(context.Background(), c, accepted, capabilityEvaluationTime); !errors.Is(err, ErrRejected) || probeCalls != 1 || gateCalls != 3 {
		t.Fatalf("cached snapshot bypassed probe: err=%v probes=%d gates=%d", err, probeCalls, gateCalls)
	}
}

type evaluatedCapabilityProbe func(context.Context, domain.CapabilityProbeRequest, time.Time) ([]domain.CoordinatorProbeEvidence, error)

func (f evaluatedCapabilityProbe) Observe(ctx context.Context, r domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
	return f(ctx, r, at)
}

func TestPullRequiresProbeAndTimeBeforeAnyEffect(t *testing.T) {
	for _, mode := range []string{"missing probe", "zero time", "malformed time", "canceled", "nil context"} {
		t.Run(mode, func(t *testing.T) {
			called := false
			probe := matchingCapabilityProbe()
			p := Puller{LeaseTTL: time.Second, Probe: schedulerCapabilityProbe(func(ctx context.Context, r domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
				called = true
				return probe.Observe(ctx, r, capabilityEvaluationTime)
			})}
			gate := gateFunc(func(context.Context, Candidate, Worker) (bool, error) { called = true; return true, nil })
			p.Authority, p.Trust, p.Budget = gate, gate, gate
			p.Store = storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
				called = true
				return Reservation{}, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var pullCtx context.Context = ctx
			at := capabilityEvaluationTime
			switch mode {
			case "missing probe":
				p.Probe = nil
			case "zero time":
				at = time.Time{}
			case "malformed time":
				at = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "canceled":
				cancel()
			case "nil context":
				pullCtx = nil
			}
			// Even same-package forged private state must not bypass the Probe.
			w := observedWorker("worker", "session", []Evidence{{"cpu", "x"}})
			got, err := p.Pull(pullCtx, Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, w, at)
			if !errors.Is(err, ErrRejected) || called || !reflect.DeepEqual(got, PullResult{}) {
				t.Fatalf("err=%v called=%v result=%v", err, called, got)
			}
		})
	}
}

func TestPullDiscardsCallerEvidenceAndInvokesTrustedProbe(t *testing.T) {
	for _, mode := range []string{"valid probe", "empty probe", "probe error", "probe cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
			var w Worker
			// Public-looking provenance/observations cannot populate the private
			// accepted snapshot, even when their shape and names appear credible.
			if err := json.Unmarshal([]byte(`{"ID":"worker","SessionID":"session","Evidence":[{"name":"cpu","value":"forged"}],"Observations":[{"name":"cpu","value":"x","provenance":{"source":"coordinator_observed_probe"}}],"Attestations":[{"name":"cpu","value":"x","statement":"unverified"}]}`), &w); err != nil {
				t.Fatal(err)
			}
			if len(w.ProbeEvidence()) != 0 {
				t.Fatal("caller populated accepted observations")
			}
			probeErr := errors.New("unavailable probe")
			var order []string
			p := Puller{LeaseTTL: time.Second, Probe: evaluatedCapabilityProbe(func(gotCtx context.Context, r domain.CapabilityProbeRequest, at time.Time) ([]domain.CoordinatorProbeEvidence, error) {
				order = append(order, "probe")
				if gotCtx != ctx || at != capabilityEvaluationTime || r.WorkerID != w.ID || r.SessionID != w.SessionID || !reflect.DeepEqual(r.Requirements, []domain.CapabilityRequirement{{Name: "cpu", Value: "x"}}) {
					t.Fatalf("wrong trusted request: %#v at=%v", r, at)
				}
				if mode == "probe error" {
					return nil, probeErr
				}
				if mode == "empty probe" {
					return nil, nil
				}
				if mode == "probe cancellation" {
					cancel()
				}
				result, err := matchingCapabilityProbe().Observe(gotCtx, r, at)
				r.Requirements[0].Value = "mutated by probe"
				return result, err
			})}
			gate := func(name string) Gate {
				return gateFunc(func(_ context.Context, gotC Candidate, gotW Worker) (bool, error) {
					order = append(order, name)
					if !reflect.DeepEqual(gotC, c) || !reflect.DeepEqual(gotW.Evidence, []Evidence{{"cpu", "x"}}) || len(gotW.Attestations) != 0 {
						t.Fatalf("gate received claims instead of probe snapshot: %#v %#v", gotC, gotW)
					}
					return true, nil
				})
			}
			p.Authority, p.Trust, p.Budget = gate("authority"), gate("trust"), gate("budget")
			p.Store = storeFunc(func(_ context.Context, gotC Candidate, gotW Worker, permit Permit, _ time.Duration) (Reservation, error) {
				order = append(order, "reserve")
				if !permit.Authorizes(gotC, gotW) || permit.Authorizes(c, w) {
					t.Fatal("permit did not distinguish internally observed snapshot from caller")
				}
				return Reservation{}, nil
			})
			_, err := p.Pull(ctx, c, w, capabilityEvaluationTime)
			want := []string{"probe"}
			if mode == "valid probe" {
				want = append(want, "authority", "trust", "budget", "reserve")
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrRejected) {
				t.Fatalf("did not fail closed: %v", err)
			}
			if mode == "probe error" && !errors.Is(err, probeErr) || mode == "probe cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost probe failure: %v", err)
			}
			if !reflect.DeepEqual(order, want) {
				t.Fatalf("order=%v want=%v", order, want)
			}
		})
	}
}

func TestPullRejectsInvalidObservationBeforeAllGates(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Candidate, *Worker, *time.Time)
	}{
		{"claim alone", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations = nil }},
		{"attestation alone", func(_ *Candidate, w *Worker, _ *time.Time) {
			w.observations = nil
			w.Attestations = []domain.HardwareAttestation{{Name: "cpu", Value: "x", Attester: "hardware", Statement: "unverified"}}
		}},
		{"missing evidence", func(_ *Candidate, w *Worker, _ *time.Time) { w.Evidence = nil; w.observations = nil }},
		{"zero evaluation", func(_ *Candidate, _ *Worker, at *time.Time) { *at = time.Time{} }},
		{"malformed evaluation", func(_ *Candidate, _ *Worker, at *time.Time) {
			*at = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"exact expiry", func(_ *Candidate, w *Worker, at *time.Time) { *at = w.observations[0].ValidUntil }},
		{"after expiry", func(_ *Candidate, w *Worker, at *time.Time) {
			*at = w.observations[0].ValidUntil.Add(time.Nanosecond)
		}},
		{"future observation", func(_ *Candidate, w *Worker, at *time.Time) {
			w.observations[0].ObservedAt = at.Add(time.Nanosecond)
		}},
		{"zero observation", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].ObservedAt = time.Time{} }},
		{"zero expiry", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].ValidUntil = time.Time{} }},
		{"malformed expiry", func(_ *Candidate, w *Worker, _ *time.Time) {
			w.observations[0].ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"missing provenance", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance = domain.ProbeProvenance{} }},
		{"unknown provenance", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.Source = "unknown" }},
		{"claim provenance", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.Source = "worker_claim" }},
		{"attestation provenance", func(_ *Candidate, w *Worker, _ *time.Time) {
			w.observations[0].Provenance.Source = "hardware_attestation"
		}},
		{"missing probe", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.ProbeID = "" }},
		{"malformed coordinator", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.CoordinatorID = " \n" }},
		{"wrong worker", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.WorkerID = "other" }},
		{"wrong session", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Provenance.SessionID = "other" }},
		{"malformed observation", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Name = "" }},
		{"observation mismatch", func(_ *Candidate, w *Worker, _ *time.Time) { w.observations[0].Value = "other" }},
		{"extra observation", func(_ *Candidate, w *Worker, _ *time.Time) {
			extra := w.observations[0]
			extra.Name = "other"
			w.observations = append(w.observations, extra)
		}},
		{"duplicate observation", func(c *Candidate, w *Worker, _ *time.Time) {
			c.Requirements = append(c.Requirements, CapabilityRequirement{"other", "x"})
			w.Evidence = append(w.Evidence, Evidence{"other", "x"})
			w.observations = append(w.observations, w.observations[0])
		}},
		{"duplicate requirement", func(c *Candidate, _ *Worker, _ *time.Time) {
			c.Requirements = append(c.Requirements, c.Requirements[0])
		}},
		{"unconstrained policy extra observation", func(c *Candidate, w *Worker, _ *time.Time) { c.Requirements = nil; w.Evidence = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
			w := observedWorker("worker", "session", []Evidence{{"cpu", "x"}})
			at := capabilityEvaluationTime
			tc.change(&c, &w, &at)
			var calls []string
			gate := func(name string) Gate {
				return gateFunc(func(context.Context, Candidate, Worker) (bool, error) { calls = append(calls, name); return true, nil })
			}
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gate("authority"), Trust: gate("trust"), Budget: gate("budget"),
				Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
					calls = append(calls, "reserve")
					return Reservation{}, nil
				})}
			p.Probe = schedulerCapabilityProbe(func(context.Context, domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
				return w.observations, nil
			})
			result, err := p.Pull(context.Background(), c, w, at)
			if !errors.Is(err, ErrRejected) || len(calls) != 0 || !reflect.DeepEqual(result, PullResult{}) {
				t.Fatalf("err=%v calls=%v result=%v", err, calls, result)
			}
		})
	}
}

func TestPullFreshObservationBoundariesAndPermit(t *testing.T) {
	for _, name := range []string{"observed boundary", "just before expiry", "unverified attestation is only metadata"} {
		t.Run(name, func(t *testing.T) {
			c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
			w := observedWorker("worker", "session", []Evidence{{"cpu", "x"}})
			at := capabilityEvaluationTime
			if name == "just before expiry" {
				at = w.observations[0].ValidUntil.Add(-time.Nanosecond)
			}
			if name == "unverified attestation is only metadata" {
				w.Attestations = []domain.HardwareAttestation{{Name: "cpu", Value: "anything", Statement: "unverified"}}
			}
			gate := gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil })
			var issued Permit
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gate, Trust: gate, Budget: gate, Store: storeFunc(func(_ context.Context, gotC Candidate, gotW Worker, permit Permit, _ time.Duration) (Reservation, error) {
				issued = permit
				w = snapshotWorker(gotW)
				if !permit.Authorizes(gotC, gotW) {
					t.Fatal("store received unbound snapshot")
				}
				return Reservation{}, nil
			})}
			if _, err := p.Pull(context.Background(), c, w, at); err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*Worker){
				func(w *Worker) { w.observations[0].Provenance.ProbeID = "other" },
				func(w *Worker) { w.observations[0].Provenance.CoordinatorID = "other" },
				func(w *Worker) { w.observations[0].ObservedAt = w.observations[0].ObservedAt.Add(-time.Second) },
				func(w *Worker) { w.observations[0].ValidUntil = w.observations[0].ValidUntil.Add(time.Second) },
				func(w *Worker) { w.observations = nil },
				func(w *Worker) { w.evaluatedAt = w.evaluatedAt.Add(time.Nanosecond) },
			} {
				changed := snapshotWorker(w)
				mutate(&changed)
				if issued.Authorizes(c, changed) {
					t.Fatal("permit authorized changed observation snapshot")
				}
			}
		})
	}
}

func TestPullCancellationStopsBeforeNextEffect(t *testing.T) {
	for _, stage := range []string{"before pull", "authority", "trust", "budget"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []string
			gate := func(name string) Gate {
				return gateFunc(func(context.Context, Candidate, Worker) (bool, error) {
					calls = append(calls, name)
					if name == stage {
						cancel()
					}
					return true, nil
				})
			}
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gate("authority"), Trust: gate("trust"), Budget: gate("budget"), Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
				t.Fatal("reserved after cancellation")
				return Reservation{}, nil
			})}
			if stage == "before pull" {
				cancel()
			}
			_, err := p.Pull(ctx, Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, observedWorker("worker", "session", []Evidence{{"cpu", "x"}}), capabilityEvaluationTime)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrRejected) {
				t.Fatalf("lost cancellation: %v", err)
			}
			want := map[string]int{"before pull": 0, "authority": 1, "trust": 2, "budget": 3}[stage]
			if len(calls) != want {
				t.Fatalf("calls=%v", calls)
			}
		})
	}
}

type schedulerCapabilityProbe func(context.Context, domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error)

func (f schedulerCapabilityProbe) Observe(ctx context.Context, r domain.CapabilityProbeRequest, _ time.Time) ([]domain.CoordinatorProbeEvidence, error) {
	return f(ctx, r)
}

func matchingCapabilityProbe() schedulerCapabilityProbe {
	return schedulerCapabilityProbe(func(_ context.Context, r domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
		var evidence []Evidence
		for _, requirement := range r.Requirements {
			evidence = append(evidence, Evidence(requirement))
		}
		return observedWorker(r.WorkerID, r.SessionID, evidence).observations, nil
	})
}

func TestCoordinatorProbeApplicationFeedsPull(t *testing.T) {
	for _, mode := range []string{"observation", "probe error", "probe cancellation", "claim-shaped result", "attestation-shaped result"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probeErr := errors.New("probe unavailable")
			service := application.NewCapabilityEvidenceService(schedulerCapabilityProbe(func(_ context.Context, r domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
				if mode == "probe error" {
					return nil, probeErr
				}
				if mode == "probe cancellation" {
					cancel()
				}
				e := observedWorker(r.WorkerID, r.SessionID, []Evidence{{"cpu", "x"}}).observations
				if mode == "claim-shaped result" {
					e[0].Provenance.Source = "worker_claim"
				}
				if mode == "attestation-shaped result" {
					e[0].Provenance.Source = "hardware_attestation"
				}
				return e, nil
			}))
			c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}

			calls := 0
			gate := gateFunc(func(context.Context, Candidate, Worker) (bool, error) { calls++; return true, nil })
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gate, Trust: gate, Budget: gate, Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
				calls++
				return Reservation{}, nil
			})}
			p.Probe = service
			_, err := p.Pull(ctx, c, Worker{ID: "worker", SessionID: "session", Evidence: []Evidence{{"cpu", "x"}}}, capabilityEvaluationTime)
			if mode == "observation" {
				if err != nil || calls != 4 {
					t.Fatalf("pull=%v calls=%d", err, calls)
				}
			} else {
				if !errors.Is(err, ErrRejected) || calls != 0 {
					t.Fatalf("pull=%v calls=%d", err, calls)
				}
				if mode == "probe error" && !errors.Is(err, probeErr) {
					t.Fatal("lost probe error")
				}
				if mode == "probe cancellation" && !errors.Is(err, context.Canceled) {
					t.Fatal("lost probe cancellation")
				}
			}
		})
	}
}

func TestCapabilityRequirementAndEvidenceJSONUseCanonicalKeys(t *testing.T) {
	requirements, err := json.Marshal([]CapabilityRequirement{{Name: "cpu", Value: "x"}})
	if err != nil || string(requirements) != `[{"name":"cpu","value":"x"}]` {
		t.Fatalf("requirements JSON is not canonical: %s", requirements)
	}
	evidence, err := json.Marshal([]Evidence{{Name: "cpu", Value: "x"}})
	if err != nil || string(evidence) != `[{"name":"cpu","value":"x"}]` {
		t.Fatalf("evidence JSON is not canonical: %s", evidence)
	}
}

type gateFunc func(context.Context, Candidate, Worker) (bool, error)

func (f gateFunc) Allow(c context.Context, w Candidate, x Worker) (bool, error) { return f(c, w, x) }

func TestPermitBindsExactRequest(t *testing.T) {
	c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
	w := observedWorker("w", "session", []Evidence{{"cpu", "x"}})
	var issued Permit
	p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Trust: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Budget: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Store: storeFunc(func(_ context.Context, _ Candidate, gotW Worker, permit Permit, _ time.Duration) (Reservation, error) {
		issued = permit
		w = snapshotWorker(gotW)
		return Reservation{}, nil
	})}
	if _, err := p.Pull(context.Background(), c, w, capabilityEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if !issued.Authorizes(c, w) {
		t.Fatal("Puller-issued permit did not authorize its request")
	}
	if issued.Authorizes(Candidate{"other", c.Requirements}, w) || issued.Authorizes(c, observedWorker("other", "session", w.Evidence)) {
		t.Fatal("permit authorized changed request")
	}
	var zero Permit
	if zero.Authorizes(c, w) {
		t.Fatal("zero permit authorized request")
	}
}

type storeFunc func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error)

func (f storeFunc) Reserve(c context.Context, w Candidate, x Worker, p Permit, ttl time.Duration) (Reservation, error) {
	return f(c, w, x, p, ttl)
}

type lifecycleFunc struct {
	heartbeat func(context.Context, LeaseIdentity, time.Duration) (bool, error)
	reap      func(context.Context, int) (int, error)
	complete  func(context.Context, LeaseIdentity) (bool, error)
}

func (f lifecycleFunc) Heartbeat(c context.Context, id LeaseIdentity, ttl time.Duration) (bool, error) {
	return f.heartbeat(c, id, ttl)
}
func (f lifecycleFunc) Reap(c context.Context, n int) (int, error) { return f.reap(c, n) }
func (f lifecycleFunc) Complete(c context.Context, id LeaseIdentity) (bool, error) {
	return f.complete(c, id)
}

func TestPullRequiresCoordinatorTTLAndSessionBeforeGates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ttl     time.Duration
		session string
	}{
		{"missing ttl", 0, "session"}, {"negative ttl", -time.Second, "session"}, {"missing session", time.Second, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			gate := gateFunc(func(context.Context, Candidate, Worker) (bool, error) { called = true; return true, nil })
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: tc.ttl, Authority: gate, Trust: gate, Budget: gate,
				Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
					called = true
					return Reservation{}, nil
				})}
			_, err := p.Pull(context.Background(), Candidate{WorkOrderID: "wo"}, Worker{ID: "w", SessionID: tc.session}, capabilityEvaluationTime)
			if !errors.Is(err, ErrRejected) || called {
				t.Fatalf("err=%v called=%v", err, called)
			}
		})
	}
}

func TestPullPassesOnlyCoordinatorTTLAfterGates(t *testing.T) {
	var gotTTL time.Duration
	var order []string
	gate := func(name string) Gate {
		return gateFunc(func(context.Context, Candidate, Worker) (bool, error) { order = append(order, name); return true, nil })
	}
	p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: 17 * time.Second, Authority: gate("authority"), Trust: gate("trust"), Budget: gate("budget"),
		Store: storeFunc(func(_ context.Context, _ Candidate, w Worker, _ Permit, ttl time.Duration) (Reservation, error) {
			order = append(order, "reserve")
			gotTTL = ttl
			if w.SessionID != "opaque" {
				t.Errorf("session=%q", w.SessionID)
			}
			return Reservation{}, nil
		})}
	if _, err := p.Pull(context.Background(), Candidate{WorkOrderID: "wo"}, Worker{ID: "w", SessionID: "opaque"}, capabilityEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if gotTTL != p.LeaseTTL || !reflect.DeepEqual(order, []string{"authority", "trust", "budget", "reserve"}) {
		t.Fatalf("ttl=%v order=%v", gotTTL, order)
	}
}

func TestLeaseLifecycleRejectsIncompleteInputsAndDelegates(t *testing.T) {
	id := LeaseIdentity{"wo", "attempt", "worker", "session", 2}
	called := 0
	p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Lifecycle: lifecycleFunc{
		heartbeat: func(_ context.Context, got LeaseIdentity, ttl time.Duration) (bool, error) {
			called++
			if got != id || ttl != time.Second {
				t.Fatalf("heartbeat got=%+v ttl=%v", got, ttl)
			}
			return true, nil
		},
		reap: func(_ context.Context, n int) (int, error) {
			called++
			if n != 3 {
				t.Fatalf("batch=%d", n)
			}
			return 2, nil
		},
		complete: func(_ context.Context, got LeaseIdentity) (bool, error) {
			called++
			if got != id {
				t.Fatalf("complete got=%+v", got)
			}
			return true, nil
		},
	}}
	for _, bad := range []LeaseIdentity{{}, {"wo", "attempt", "worker", "", 1}, {"wo", "attempt", "worker", "session", 0}} {
		if _, err := p.Heartbeat(context.Background(), bad); !errors.Is(err, ErrRejected) {
			t.Fatalf("heartbeat accepted %+v: %v", bad, err)
		}
		if _, err := p.Complete(context.Background(), bad); !errors.Is(err, ErrRejected) {
			t.Fatalf("complete accepted %+v: %v", bad, err)
		}
	}
	if _, err := p.Reap(context.Background(), 0); !errors.Is(err, ErrRejected) {
		t.Fatalf("reap accepted zero batch: %v", err)
	}
	if called != 0 {
		t.Fatalf("invalid calls delegated: %d", called)
	}
	if ok, err := p.Heartbeat(context.Background(), id); err != nil || !ok {
		t.Fatalf("heartbeat=%v err=%v", ok, err)
	}
	if n, err := p.Reap(context.Background(), 3); err != nil || n != 2 {
		t.Fatalf("reap=%d err=%v", n, err)
	}
	if ok, err := p.Complete(context.Background(), id); err != nil || !ok {
		t.Fatalf("complete=%v err=%v", ok, err)
	}
	if called != 3 {
		t.Fatalf("delegated calls=%d", called)
	}
	p.LeaseTTL = 0
	if _, err := p.Heartbeat(context.Background(), id); !errors.Is(err, ErrRejected) {
		t.Fatalf("heartbeat accepted missing ttl: %v", err)
	}
	if _, err := p.Complete(context.Background(), id); !errors.Is(err, ErrRejected) {
		t.Fatalf("complete accepted missing ttl: %v", err)
	}
}

func TestCapabilityMatchFailClosed(t *testing.T) {
	cases := []struct {
		name string
		r    []CapabilityRequirement
		e    []Evidence
		want bool
	}{
		{"match", []CapabilityRequirement{{"gpu", "yes"}}, []Evidence{{"gpu", "yes"}}, true},
		{"explicit empty policy", nil, nil, true},
		{"empty policy rejects evidence", nil, []Evidence{{"gpu", "yes"}}, false},
		{"extra evidence", []CapabilityRequirement{{"gpu", "yes"}}, []Evidence{{"gpu", "yes"}, {"cpu", "x"}}, false},
		{"missing", []CapabilityRequirement{{"gpu", "yes"}}, nil, false},
		{"wrong", []CapabilityRequirement{{"gpu", "yes"}}, []Evidence{{"gpu", "no"}}, false},
		{"duplicate evidence", []CapabilityRequirement{{"gpu", "yes"}}, []Evidence{{"gpu", "yes"}, {"gpu", "yes"}}, false},
		{"malformed extra", []CapabilityRequirement{{"gpu", "yes"}}, []Evidence{{"gpu", "yes"}, {"", "x"}}, false},
		{"duplicate requirement", []CapabilityRequirement{{"gpu", "yes"}, {"gpu", "yes"}}, []Evidence{{"gpu", "yes"}}, false},
		{"invalid requirement", []CapabilityRequirement{{"gpu", ""}}, []Evidence{{"gpu", "yes"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapabilityMatch(tc.r, tc.e); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}
func TestPullOrderingAndFailClosed(t *testing.T) {
	want := []string{"authority", "trust", "budget", "reserve"}
	var got []string
	yes := func(name string) Gate {
		return gateFunc(func(context.Context, Candidate, Worker) (bool, error) { got = append(got, name); return true, nil })
	}
	p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: yes("authority"), Trust: yes("trust"), Budget: yes("budget"), Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
		got = append(got, "reserve")
		return Reservation{AttemptID: "a", SlotID: "s"}, nil
	})}
	c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
	w := observedWorker("worker", "session", []Evidence{{"cpu", "x"}})
	if _, err := p.Pull(context.Background(), c, w, capabilityEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v", got)
	}
}

func TestPullGatesReceiveIndependentRequestSnapshots(t *testing.T) {
	originalC := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}, {"memory", "large"}}}
	originalW := observedWorker("worker", "session", []Evidence{{"cpu", "x"}, {"memory", "large"}})
	inputC, inputW := snapshotCandidate(originalC), snapshotWorker(originalW)
	probeObservations := originalW.ProbeEvidence()
	var laterC Candidate
	var laterW Worker
	var storeC Candidate
	var storeW Worker
	var issued Permit
	p := Puller{
		Probe: schedulerCapabilityProbe(func(_ context.Context, r domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
			r.Requirements[0].Value = "mutated by probe"
			return probeObservations, nil
		}),
		Authority: gateFunc(func(_ context.Context, c Candidate, w Worker) (bool, error) {
			probeObservations[0].Value = "mutated probe-owned result"
			view := w.ProbeEvidence()
			view[0].Value = "mutated detached view"
			if w.observations[0].Value != "x" {
				t.Fatal("view aliases accepted snapshot")
			}
			c.Requirements[0] = CapabilityRequirement{"cpu", "tampered"}
			w.Evidence[0] = Evidence{"cpu", "tampered"}
			w.observations[0].Provenance.ProbeID = "tampered"
			return true, nil
		}),
		Trust: gateFunc(func(_ context.Context, c Candidate, w Worker) (bool, error) {
			laterC, laterW = c, w
			return true, nil
		}),
		Budget: gateFunc(func(_ context.Context, c Candidate, w Worker) (bool, error) {
			if !reflect.DeepEqual(c, originalC) || !reflect.DeepEqual(w, originalW) {
				t.Errorf("budget saw mutated request: %#v %#v", c, w)
			}
			return true, nil
		}),
		LeaseTTL: time.Second,
		Store: storeFunc(func(_ context.Context, c Candidate, w Worker, permit Permit, _ time.Duration) (Reservation, error) {
			storeC, storeW, issued = c, w, permit
			return Reservation{}, nil
		}),
	}
	if _, err := p.Pull(context.Background(), inputC, inputW, capabilityEvaluationTime); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(laterC, originalC) || !reflect.DeepEqual(laterW, originalW) {
		t.Fatalf("later gate saw mutated request: %#v %#v", laterC, laterW)
	}
	if !reflect.DeepEqual(storeC, originalC) || !reflect.DeepEqual(storeW, originalW) {
		t.Fatalf("store saw mutated request: %#v %#v", storeC, storeW)
	}
	tamperedC := snapshotCandidate(originalC)
	tamperedW := snapshotWorker(originalW)
	tamperedC.Requirements[0].Value = "tampered"
	tamperedW.Evidence[0].Value = "tampered"
	if !issued.Authorizes(originalC, originalW) || issued.Authorizes(tamperedC, tamperedW) {
		t.Fatal("permit was not bound to original snapshotted request")
	}
	if !reflect.DeepEqual(inputC, originalC) || !reflect.DeepEqual(inputW, originalW) {
		t.Fatal("Pull mutated caller-owned request slices")
	}
}

func TestPullHardMismatchSkipsGatesAndReservation(t *testing.T) {
	called := false
	deny := gateFunc(func(context.Context, Candidate, Worker) (bool, error) { called = true; return true, nil })
	p := Puller{Probe: schedulerCapabilityProbe(func(context.Context, domain.CapabilityProbeRequest) ([]domain.CoordinatorProbeEvidence, error) {
		return nil, nil
	}), LeaseTTL: time.Second, Authority: deny, Trust: deny, Budget: deny, Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
		called = true
		return Reservation{}, nil
	})}
	_, err := p.Pull(context.Background(), Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, Worker{ID: "w", SessionID: "session"}, capabilityEvaluationTime)
	if !errors.Is(err, ErrRejected) || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}
func TestPullMissingDenyAndErrorGatesRejectBeforeReserve(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*Puller)
	}{
		{"missing authority", func(p *Puller) { p.Authority = nil }},
		{"missing trust", func(p *Puller) { p.Trust = nil }},
		{"missing budget", func(p *Puller) { p.Budget = nil }},
		{"authority deny", func(p *Puller) {
			p.Authority = gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return false, nil })
		}},
		{"trust error", func(p *Puller) {
			p.Trust = gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return false, errors.New("unavailable") })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reserved := false
			p := Puller{Probe: matchingCapabilityProbe(), LeaseTTL: time.Second, Authority: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Trust: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Budget: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
				reserved = true
				return Reservation{}, nil
			})}
			tc.configure(&p)
			_, err := p.Pull(context.Background(), Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, observedWorker("w", "session", []Evidence{{"cpu", "x"}}), capabilityEvaluationTime)
			if err == nil || reserved {
				t.Fatalf("err=%v reserved=%v", err, reserved)
			}
		})
	}
}
