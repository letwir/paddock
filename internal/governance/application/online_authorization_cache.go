package application

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/letwir/paddock/internal/governance/domain"
)

// AuthorizationRisk identifies the freshness contract for an authorization.
type AuthorizationRisk string

const (
	AuthorizationRiskHigh AuthorizationRisk = "HIGH"
	AuthorizationRiskLow  AuthorizationRisk = "LOW"
)

// AuthorizationSnapshot is the DB-observed decision and remaining lease.
type AuthorizationSnapshot struct {
	Allowed        bool
	Risk           AuthorizationRisk
	LeaseRemaining time.Duration
}

// AuthorizationSnapshotReader obtains a fresh decision bound to the operation.
type AuthorizationSnapshotReader interface {
	ReadAuthorization(context.Context, GatewayOperation) (AuthorizationSnapshot, error)
}

// ErrAuthorizationUnavailable is the only reader failure permitting LOW fallback.
var ErrAuthorizationUnavailable = errors.New("authorization state unavailable")

// ElapsedClock supplies process-local monotonic elapsed time.
type ElapsedClock interface {
	Elapsed() time.Duration
}

type authorizationCacheKey struct {
	rootID       domain.RootID
	workOrderID  domain.WorkOrderID
	attemptID    string
	workerID     string
	sessionID    string
	leaseEpoch   domain.Epoch
	policyDigest domain.Digest
	action       string
}

type lowAuthorizationEntry struct {
	deadline time.Duration
}

// CachedOnlineAuthorizer implements OnlineAuthorizer with a process-local,
// lease-bounded fallback for LOW-risk authorizations only.
type CachedOnlineAuthorizer struct {
	reader AuthorizationSnapshotReader
	clock  ElapsedClock

	mu       sync.Mutex
	lastTime time.Duration
	hasTime  bool
	lowCache map[authorizationCacheKey]lowAuthorizationEntry
}

// NewCachedOnlineAuthorizer constructs a process-local authorizer.
func NewCachedOnlineAuthorizer(reader AuthorizationSnapshotReader, clock ElapsedClock) *CachedOnlineAuthorizer {
	return &CachedOnlineAuthorizer{reader: reader, clock: clock, lowCache: make(map[authorizationCacheKey]lowAuthorizationEntry)}
}

// AuthorizeOnline checks current DB authority, permitting only a typed outage
// fallback from a previously observed LOW allow until its DB lease deadline.
func (a *CachedOnlineAuthorizer) AuthorizeOnline(ctx context.Context, op GatewayOperation) error {
	if a == nil || !portPresent(a.reader) || !portPresent(a.clock) || ctx == nil || ctx.Err() != nil {
		return ErrGatewayDenied
	}
	key, ok := authorizationKey(op)
	if !ok {
		return ErrGatewayDenied
	}

	// Serialize observations so a clock rewind or DB recovery cannot race a
	// stale cache decision against a newer observation.
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Elapsed()
	if now < 0 || (a.hasTime && now < a.lastTime) {
		a.invalidateAll()
		return ErrGatewayDenied
	}
	a.lastTime, a.hasTime = now, true
	if ctx.Err() != nil {
		a.delete(key)
		return ErrGatewayDenied
	}

	startElapsed := a.clock.Elapsed()
	if startElapsed < 0 || (a.hasTime && startElapsed < a.lastTime) {
		a.invalidateAll()
		return ErrGatewayDenied
	}
	a.lastTime, a.hasTime = startElapsed, true
	snapshot, err := a.reader.ReadAuthorization(ctx, cloneGatewayOperation(op))
	if ctx.Err() != nil {
		a.delete(key)
		return ErrGatewayDenied
	}
	if err != nil {
		if errors.Is(err, ErrAuthorizationUnavailable) {
			// The database read may have blocked past the cached lease deadline.
			// Only the post-read monotonic observation can safely authorize fallback.
			postReadNow := a.clock.Elapsed()
			if postReadNow < 0 || postReadNow < a.lastTime {
				a.invalidateAll()
				return ErrGatewayDenied
			}
			a.lastTime, a.hasTime = postReadNow, true
			entry, exists := a.lowCache[key]
			if exists && postReadNow < entry.deadline {
				return nil
			}
			if exists {
				a.delete(key)
			}
		}
		a.delete(key)
		return ErrGatewayDenied
	}

	// Any fresh response replaces or invalidates the corresponding entry.
	a.delete(key)
	if snapshot.Risk != AuthorizationRiskHigh && snapshot.Risk != AuthorizationRiskLow {
		return ErrGatewayDenied
	}
	if !snapshot.Allowed {
		return ErrGatewayDenied
	}
	if snapshot.LeaseRemaining <= 0 || snapshot.LeaseRemaining > time.Duration(math.MaxInt64)-startElapsed {
		return ErrGatewayDenied
	}
	deadline := startElapsed + snapshot.LeaseRemaining
	postReadElapsed := a.clock.Elapsed()
	if postReadElapsed < 0 || postReadElapsed < a.lastTime {
		a.invalidateAll()
		return ErrGatewayDenied
	}
	a.lastTime, a.hasTime = postReadElapsed, true
	if postReadElapsed >= deadline {
		return ErrGatewayDenied
	}
	if snapshot.Risk == AuthorizationRiskHigh {
		return nil
	}
	a.lowCache[key] = lowAuthorizationEntry{deadline: deadline}
	return nil
}

func authorizationKey(op GatewayOperation) (authorizationCacheKey, bool) {
	if op.RootID.Validate() != nil || op.WorkOrderID.Validate() != nil ||
		validateID(op.AttemptID) != nil || validateID(op.WorkerID) != nil ||
		validateID(op.SessionID) != nil || op.LeaseEpoch == 0 ||
		op.PolicyDigest.Validate() != nil || validateID(op.Action) != nil {
		return authorizationCacheKey{}, false
	}
	return authorizationCacheKey{
		rootID: op.RootID, workOrderID: op.WorkOrderID, attemptID: op.AttemptID,
		workerID: op.WorkerID, sessionID: op.SessionID, leaseEpoch: op.LeaseEpoch,
		policyDigest: op.PolicyDigest, action: op.Action,
	}, true
}

func (a *CachedOnlineAuthorizer) delete(key authorizationCacheKey) {
	delete(a.lowCache, key)
}

func (a *CachedOnlineAuthorizer) invalidateAll() {
	a.lowCache = make(map[authorizationCacheKey]lowAuthorizationEntry)
}
