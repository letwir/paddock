package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

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
	w := Worker{"w", "session", []Evidence{{"cpu", "x"}}}
	var issued Permit
	p := Puller{LeaseTTL: time.Second, Authority: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Trust: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Budget: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Store: storeFunc(func(_ context.Context, _ Candidate, _ Worker, permit Permit, _ time.Duration) (Reservation, error) {
		issued = permit
		return Reservation{}, nil
	})}
	if _, err := p.Pull(context.Background(), c, w); err != nil {
		t.Fatal(err)
	}
	if !issued.Authorizes(c, w) {
		t.Fatal("Puller-issued permit did not authorize its request")
	}
	if issued.Authorizes(Candidate{"other", c.Requirements}, w) || issued.Authorizes(c, Worker{"other", "session", w.Evidence}) {
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
			p := Puller{LeaseTTL: tc.ttl, Authority: gate, Trust: gate, Budget: gate,
				Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
					called = true
					return Reservation{}, nil
				})}
			_, err := p.Pull(context.Background(), Candidate{WorkOrderID: "wo"}, Worker{ID: "w", SessionID: tc.session})
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
	p := Puller{LeaseTTL: 17 * time.Second, Authority: gate("authority"), Trust: gate("trust"), Budget: gate("budget"),
		Store: storeFunc(func(_ context.Context, _ Candidate, w Worker, _ Permit, ttl time.Duration) (Reservation, error) {
			order = append(order, "reserve")
			gotTTL = ttl
			if w.SessionID != "opaque" {
				t.Errorf("session=%q", w.SessionID)
			}
			return Reservation{}, nil
		})}
	if _, err := p.Pull(context.Background(), Candidate{WorkOrderID: "wo"}, Worker{ID: "w", SessionID: "opaque"}); err != nil {
		t.Fatal(err)
	}
	if gotTTL != p.LeaseTTL || !reflect.DeepEqual(order, []string{"authority", "trust", "budget", "reserve"}) {
		t.Fatalf("ttl=%v order=%v", gotTTL, order)
	}
}

func TestLeaseLifecycleRejectsIncompleteInputsAndDelegates(t *testing.T) {
	id := LeaseIdentity{"wo", "attempt", "worker", "session", 2}
	called := 0
	p := Puller{LeaseTTL: time.Second, Lifecycle: lifecycleFunc{
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
	p := Puller{LeaseTTL: time.Second, Authority: yes("authority"), Trust: yes("trust"), Budget: yes("budget"), Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
		got = append(got, "reserve")
		return Reservation{AttemptID: "a", SlotID: "s"}, nil
	})}
	c := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}
	w := Worker{"worker", "session", []Evidence{{"cpu", "x"}}}
	if _, err := p.Pull(context.Background(), c, w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v", got)
	}
}

func TestPullGatesReceiveIndependentRequestSnapshots(t *testing.T) {
	originalC := Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}, {"memory", "large"}}}
	originalW := Worker{"worker", "session", []Evidence{{"cpu", "x"}, {"memory", "large"}}}
	inputC, inputW := snapshotCandidate(originalC), snapshotWorker(originalW)
	var laterC Candidate
	var laterW Worker
	var storeC Candidate
	var storeW Worker
	var issued Permit
	p := Puller{
		Authority: gateFunc(func(_ context.Context, c Candidate, w Worker) (bool, error) {
			c.Requirements[0] = CapabilityRequirement{"cpu", "tampered"}
			w.Evidence[0] = Evidence{"cpu", "tampered"}
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
	if _, err := p.Pull(context.Background(), inputC, inputW); err != nil {
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
	p := Puller{LeaseTTL: time.Second, Authority: deny, Trust: deny, Budget: deny, Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
		called = true
		return Reservation{}, nil
	})}
	_, err := p.Pull(context.Background(), Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, Worker{"w", "session", nil})
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
			p := Puller{LeaseTTL: time.Second, Authority: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Trust: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Budget: gateFunc(func(context.Context, Candidate, Worker) (bool, error) { return true, nil }), Store: storeFunc(func(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error) {
				reserved = true
				return Reservation{}, nil
			})}
			tc.configure(&p)
			_, err := p.Pull(context.Background(), Candidate{"wo", []CapabilityRequirement{{"cpu", "x"}}}, Worker{"w", "session", []Evidence{{"cpu", "x"}}})
			if err == nil || reserved {
				t.Fatalf("err=%v reserved=%v", err, reserved)
			}
		})
	}
}
