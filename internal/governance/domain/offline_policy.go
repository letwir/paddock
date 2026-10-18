package domain

import (
	"errors"
	"sync"
	"time"
)

// OfflinePolicy and Checkpointability are independent WorkOrder policy axes.
type OfflinePolicy string

const (
	OnlineRequired OfflinePolicy = "ONLINE_REQUIRED"
	OfflineCompute OfflinePolicy = "OFFLINE_COMPUTE"
)

type Checkpointability string

const (
	Checkpointable    Checkpointability = "CHECKPOINTABLE"
	NotCheckpointable Checkpointability = "NOT_CHECKPOINTABLE"
)

type OperationClass string

const (
	LocalCompute    OperationClass = "LOCAL_COMPUTE"
	LocalCheckpoint OperationClass = "LOCAL_CHECKPOINT"
	ExternalEffect  OperationClass = "EXTERNAL_EFFECT"
)

var (
	ErrOfflineDenied   = errors.New("offline operation denied")
	ErrInvalidGrant    = errors.New("invalid offline grant")
	ErrOfflineExpired  = errors.New("offline session expired")
	ErrOfflineClock    = errors.New("invalid offline monotonic clock")
	ErrStaleCheckpoint = errors.New("stale offline checkpoint candidate")
)

// OfflineGrantBinding identifies the exact run and WorkOrder policy for which
// a Coordinator issued the opaque grant. Policy and Checkpointability are
// canonical binding axes, not separate worker-controlled claim values.
type OfflineGrantBinding struct {
	GrantID           string
	RootID            RootID
	WorkOrderID       WorkOrderID
	AttemptID         string
	LeaseEpoch        Epoch
	WorkerID          string
	SessionID         string
	PolicyDigest      Digest
	Policy            OfflinePolicy
	Checkpointability Checkpointability
}

// OfflineGrantClaims are returned only by the injected verifier. TTL is the
// Coordinator-selected validity duration; AllowedOperations is never trusted
// without validating every member below.
type OfflineGrantClaims struct {
	Binding           OfflineGrantBinding
	TTL               time.Duration
	AllowedOperations []OperationClass
}

// OfflineGrantVerifier is an injected trust boundary. This PoC provides no
// production signing implementation, signature algorithm, issuer, key custody,
// or token encoding. Implementations must validate signature and key status,
// prove the policy digest matches the complete binding (Root, WorkOrder, Attempt,
// worker, session, epoch, Policy, and Checkpointability), and consume or reject
// duplicate/replayed grant IDs. Binding the complete claim prevents policy-axis
// substitution and grant replay. The verifier must be
// single-use/replay safe. VerifyOfflineGrant must run on the trusted Coordinator
// path at online issuance/receipt, before disconnect. The expected binding is
// loaded by the trusted Coordinator from the current WorkOrder policy, including
// Policy and Checkpointability; it is never Worker-controlled. Current
// lease/policy inputs must likewise come from Coordinator/DB state.
// Worker SessionID must be fresh for every process; restart invalidates a session.
type OfflineGrantVerifier interface {
	VerifyOfflineGrant(token []byte) (OfflineGrantClaims, error)
}

// MonotonicClock reports elapsed time within this process, not wall-clock time.
type MonotonicClock interface {
	Elapsed() time.Duration
}

// OfflineSession deliberately has no exported state. Its authorization is
// process-local and cannot be reconstructed by JSON decoding. Callers MUST
// supply a fresh SessionID on every process start; restart requires re-verification.
type OfflineSession struct {
	mu          sync.Mutex
	claims      OfflineGrantClaims
	allowed     map[OperationClass]struct{}
	started     time.Duration
	ttl         time.Duration
	clock       MonotonicClock
	lastElapsed time.Duration
	invalid     bool
}

// OfflineLease is the exact current lease/policy identity used when considering
// a local checkpoint candidate after reconnect.
type OfflineLease struct {
	RootID            RootID
	WorkOrderID       WorkOrderID
	AttemptID         string
	LeaseEpoch        Epoch
	WorkerID          string
	SessionID         string
	PolicyDigest      Digest
	Policy            OfflinePolicy
	Checkpointability Checkpointability
}

// OfflineCheckpointCandidate is an in-memory L1 candidate, not durable or
// verified checkpoint state. Its fields are intentionally unexported.
type OfflineCheckpointCandidate struct {
	binding           OfflineGrantBinding
	policy            OfflinePolicy
	checkpointability Checkpointability
}

func validateOfflineBinding(b OfflineGrantBinding) error {
	if err := validateID(b.GrantID); err != nil {
		return err
	}
	if err := b.RootID.Validate(); err != nil {
		return err
	}
	if err := b.WorkOrderID.Validate(); err != nil {
		return err
	}
	if err := validateID(b.AttemptID); err != nil {
		return err
	}
	if err := validateID(b.WorkerID); err != nil {
		return err
	}
	if err := validateID(b.SessionID); err != nil {
		return err
	}
	if err := b.PolicyDigest.Validate(); err != nil {
		return err
	}
	if b.LeaseEpoch == 0 {
		return ErrInvalidGrant
	}
	if (b.Policy != OnlineRequired && b.Policy != OfflineCompute) ||
		(b.Checkpointability != Checkpointable && b.Checkpointability != NotCheckpointable) {
		return ErrInvalidGrant
	}
	return nil
}

// VerifyOfflineGrant captures elapsed time before verifier work, so a slow
// verifier consumes (rather than extends) the grant's validity interval.
func VerifyOfflineGrant(expected OfflineGrantBinding, token []byte, verifier OfflineGrantVerifier, clock MonotonicClock) (*OfflineSession, error) {
	if verifier == nil || clock == nil {
		return nil, ErrInvalidGrant
	}
	if err := validateOfflineBinding(expected); err != nil {
		return nil, ErrInvalidGrant
	}
	started := clock.Elapsed()
	if started < 0 {
		return nil, ErrOfflineClock
	}
	claims, err := verifier.VerifyOfflineGrant(append([]byte(nil), token...))
	if err != nil {
		return nil, ErrInvalidGrant
	}
	verifiedAt := clock.Elapsed()
	if verifiedAt < 0 || verifiedAt < started {
		return nil, ErrOfflineClock
	}
	if claims.TTL <= 0 || !sameOfflineBinding(claims.Binding, expected) {
		return nil, ErrInvalidGrant
	}
	if claims.Binding.Policy == OnlineRequired {
		return nil, ErrOfflineDenied
	}
	if verifiedAt-started >= claims.TTL {
		return nil, ErrOfflineExpired
	}
	allowed := make(map[OperationClass]struct{}, len(claims.AllowedOperations))
	for _, op := range claims.AllowedOperations {
		if _, duplicate := allowed[op]; duplicate {
			return nil, ErrInvalidGrant
		}
		switch op {
		case LocalCompute, LocalCheckpoint:
			allowed[op] = struct{}{}
		case ExternalEffect:
			return nil, ErrInvalidGrant
		default:
			return nil, ErrInvalidGrant
		}
	}
	if _, ok := allowed[LocalCompute]; !ok {
		return nil, ErrInvalidGrant
	}
	if claims.Binding.Checkpointability != Checkpointable {
		if _, ok := allowed[LocalCheckpoint]; ok {
			return nil, ErrInvalidGrant
		}
	}
	claims.AllowedOperations = append([]OperationClass(nil), claims.AllowedOperations...)
	return &OfflineSession{claims: claims, allowed: allowed, started: started, ttl: claims.TTL, clock: clock, lastElapsed: verifiedAt}, nil
}

func sameOfflineBinding(a, b OfflineGrantBinding) bool {
	return a.GrantID == b.GrantID && a.RootID == b.RootID && a.WorkOrderID == b.WorkOrderID && a.AttemptID == b.AttemptID && a.LeaseEpoch == b.LeaseEpoch && a.WorkerID == b.WorkerID && a.SessionID == b.SessionID && a.PolicyDigest == b.PolicyDigest && a.Policy == b.Policy && a.Checkpointability == b.Checkpointability
}

// Authorize permits only the offline-local operations granted by policy. An
// allowed checkpoint action returns an L1 candidate; it does not persist/promote it.
func (s *OfflineSession) Authorize(operation OperationClass) (*OfflineCheckpointCandidate, error) {
	if s == nil || s.clock == nil {
		return nil, ErrOfflineDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalid {
		return nil, ErrOfflineClock
	}
	elapsed := s.clock.Elapsed()
	if elapsed < 0 || elapsed < s.lastElapsed {
		s.invalid = true
		return nil, ErrOfflineClock
	}
	s.lastElapsed = elapsed
	if elapsed < s.started || elapsed-s.started >= s.ttl {
		return nil, ErrOfflineExpired
	}
	if operation == ExternalEffect {
		return nil, ErrOfflineDenied
	}
	if operation != LocalCompute && operation != LocalCheckpoint {
		return nil, ErrOfflineDenied
	}
	if operation == LocalCheckpoint {
		if s.claims.Binding.Checkpointability != Checkpointable {
			return nil, ErrOfflineDenied
		}
		if _, ok := s.allowed[LocalCheckpoint]; !ok {
			return nil, ErrOfflineDenied
		}
		return &OfflineCheckpointCandidate{binding: s.claims.Binding, policy: s.claims.Binding.Policy, checkpointability: s.claims.Binding.Checkpointability}, nil
	}
	if s.claims.Binding.Policy != OfflineCompute {
		return nil, ErrOfflineDenied
	}
	if _, ok := s.allowed[LocalCompute]; !ok {
		return nil, ErrOfflineDenied
	}
	return nil, nil
}

// AcceptOfflineCheckpoint is a pure fencing predicate only. Acceptance means
// the candidate matches the current lease; it does not make it durable, L2, or verified.
func AcceptOfflineCheckpoint(candidate OfflineCheckpointCandidate, current OfflineLease) bool {
	b := candidate.binding
	if validateOfflineBinding(b) != nil || current.RootID.Validate() != nil || current.WorkOrderID.Validate() != nil || current.LeaseEpoch == 0 ||
		validateID(current.AttemptID) != nil || validateID(current.WorkerID) != nil ||
		validateID(current.SessionID) != nil || current.PolicyDigest.Validate() != nil {
		return false
	}
	return candidate.policy == OfflineCompute && candidate.checkpointability == Checkpointable &&
		current.Policy == candidate.policy && current.Checkpointability == candidate.checkpointability &&
		b.RootID == current.RootID && b.WorkOrderID == current.WorkOrderID &&
		b.AttemptID == current.AttemptID && b.LeaseEpoch == current.LeaseEpoch &&
		b.WorkerID == current.WorkerID && b.SessionID == current.SessionID &&
		b.PolicyDigest == current.PolicyDigest
}
