// Package scheduler defines the fail-closed Worker Pull decision seam.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrRejected = errors.New("worker pull rejected")

type CapabilityRequirement struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func snapshotCandidate(c Candidate) Candidate {
	c.Requirements = append([]CapabilityRequirement(nil), c.Requirements...)
	return c
}

func snapshotWorker(w Worker) Worker {
	w.Evidence = append([]Evidence(nil), w.Evidence...)
	return w
}

type Evidence struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Candidate struct {
	WorkOrderID  string
	Requirements []CapabilityRequirement
}
type Worker struct {
	ID string
	// SessionID is an opaque session bound by the trusted Coordinator; it is not
	// authentication and must not be interpreted as proof of identity.
	SessionID string
	Evidence  []Evidence
}

// Gates are injectable decision seams, not worker authentication, trust formation,
// or budget enforcement implementations. A nil or denying gate rejects the pull.
type Gate interface {
	Allow(context.Context, Candidate, Worker) (bool, error)
}
type Reservation struct {
	AttemptID  string
	SlotID     string
	SessionID  string
	LeaseEpoch int64
	ExpiresAt  time.Time
}

// LeaseIdentity is the complete fencing tuple used by heartbeat and completion.
// SessionID is opaque and is not authenticated by the SQL storage boundary.
type LeaseIdentity struct {
	WorkOrderID string
	AttemptID   string
	WorkerID    string
	SessionID   string
	Epoch       int64
}

// LeaseLifecycle is the persistence seam for fenced lease lifecycle operations.
// SessionID is opaque; the Coordinator is the trust boundary, not this interface.
type LeaseLifecycle interface {
	Heartbeat(context.Context, LeaseIdentity, time.Duration) (bool, error)
	Reap(context.Context, int) (int, error)
	Complete(context.Context, LeaseIdentity) (bool, error)
}

// Permit is opaque to callers: its zero value is invalid and only Puller can issue it.
// Its binding prevents use with a changed candidate or worker request.
type Permit struct{ binding [32]byte }

func (p Permit) Authorizes(c Candidate, w Worker) bool {
	return p.binding != ([32]byte{}) && p.binding == requestBinding(c, w)
}
func requestBinding(c Candidate, w Worker) [32]byte {
	b, _ := json.Marshal(struct {
		C Candidate
		W Worker
	}{c, w})
	return sha256.Sum256(b)
}

type Reserver interface {
	Reserve(context.Context, Candidate, Worker, Permit, time.Duration) (Reservation, error)
}
type PullResult struct {
	Candidate   Candidate
	Reservation Reservation
}
type Puller struct {
	Authority, Trust, Budget Gate
	Store                    Reserver
	// LeaseTTL is supplied only by trusted Coordinator configuration.
	LeaseTTL  time.Duration
	Lifecycle LeaseLifecycle
}

func validLeaseIdentity(id LeaseIdentity) bool {
	return id.WorkOrderID != "" && id.AttemptID != "" && id.WorkerID != "" && id.SessionID != "" && id.Epoch > 0
}

// Heartbeat extends a lease only through the configured lifecycle adapter.
func (p *Puller) Heartbeat(ctx context.Context, id LeaseIdentity) (bool, error) {
	if ctx == nil || p == nil || !validLeaseIdentity(id) || p.LeaseTTL <= 0 || p.Lifecycle == nil {
		return false, ErrRejected
	}
	return p.Lifecycle.Heartbeat(ctx, id, p.LeaseTTL)
}

// Complete completes a lease only through the configured lifecycle adapter.
func (p *Puller) Complete(ctx context.Context, id LeaseIdentity) (bool, error) {
	if ctx == nil || p == nil || !validLeaseIdentity(id) || p.LeaseTTL <= 0 || p.Lifecycle == nil {
		return false, ErrRejected
	}
	return p.Lifecycle.Complete(ctx, id)
}

// Reap delegates bounded cleanup only when given a positive batch size.
func (p *Puller) Reap(ctx context.Context, batch int) (int, error) {
	if ctx == nil || p == nil || batch <= 0 || p.Lifecycle == nil {
		return 0, ErrRejected
	}
	return p.Lifecycle.Reap(ctx, batch)
}

// CapabilityMatch validates evidence deterministically; malformed, duplicate, empty,
// or missing values fail closed.
func CapabilityMatch(required []CapabilityRequirement, evidence []Evidence) bool {
	// Explicitly configured empty requirements are an allowed, unconstrained policy;
	// evidence must also be empty so the three representations remain identical.
	if len(required) == 0 || len(evidence) == 0 {
		return len(required) == 0 && len(evidence) == 0
	}
	if len(required) != len(evidence) {
		return false
	}
	have := make(map[string]string, len(evidence))
	for _, e := range evidence {
		if e.Name == "" || e.Value == "" {
			return false
		}
		if _, ok := have[e.Name]; ok {
			return false
		}
		have[e.Name] = e.Value
	}
	seen := map[string]bool{}
	for _, r := range required {
		if r.Name == "" || r.Value == "" || seen[r.Name] || have[r.Name] != r.Value {
			return false
		}
		seen[r.Name] = true
	}
	return true
}

// Pull performs capability matching and the Authority/Trust/Budget decision seams
// before issuing a request-bound permit to the reservation adapter.
func (p *Puller) Pull(ctx context.Context, c Candidate, w Worker) (PullResult, error) {
	var zero PullResult
	// Detach from caller-owned backing arrays before any callback can observe them.
	c = snapshotCandidate(c)
	w = snapshotWorker(w)
	if ctx == nil || p == nil || c.WorkOrderID == "" || w.ID == "" || w.SessionID == "" || p.LeaseTTL <= 0 {
		return zero, ErrRejected
	}
	if !CapabilityMatch(c.Requirements, w.Evidence) {
		return zero, ErrRejected
	}
	for _, gate := range []struct {
		name string
		g    Gate
	}{{"authority", p.Authority}, {"trust", p.Trust}, {"budget", p.Budget}} {
		if gate.g == nil {
			return zero, fmt.Errorf("%w: missing %s gate", ErrRejected, gate.name)
		}
		// Each callback is untrusted with respect to the request value: give it
		// independent slices so mutation cannot affect later decisions/binding.
		allow, err := gate.g.Allow(ctx, snapshotCandidate(c), snapshotWorker(w))
		if err != nil {
			return zero, fmt.Errorf("%w: %s gate: %v", ErrRejected, gate.name, err)
		}
		if !allow {
			return zero, fmt.Errorf("%w: %s gate denied", ErrRejected, gate.name)
		}
	}
	if p.Store == nil {
		return zero, fmt.Errorf("%w: missing reservation store", ErrRejected)
	}
	permit := Permit{binding: requestBinding(c, w)}
	r, err := p.Store.Reserve(ctx, snapshotCandidate(c), snapshotWorker(w), permit, p.LeaseTTL)
	if err != nil {
		return zero, err
	}
	return PullResult{Candidate: snapshotCandidate(c), Reservation: r}, nil
}
