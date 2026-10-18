package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type testOfflineClock struct{ elapsed time.Duration }

func TestOfflineGrantRejectsPolicyAxesDifferentFromExpectedBinding(t *testing.T) {
	binding, claims := offlineFixture()
	claims.Binding.Policy = OnlineRequired
	if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{claims: claims}, &testOfflineClock{}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("policy mismatch: %v", err)
	}
	claims.Binding = binding
	claims.Binding.Checkpointability = NotCheckpointable
	if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{claims: claims}, &testOfflineClock{}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("checkpointability mismatch: %v", err)
	}
}

func TestOfflinePolicyAndCheckpointabilityComeOnlyFromVerifierClaims(t *testing.T) {
	binding, claims := offlineFixture()
	if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{claims: claims}, &testOfflineClock{}); err != nil {
		t.Fatal(err)
	}
	clock := &testOfflineClock{}
	session := newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	candidate, err := session.Authorize(LocalCheckpoint)
	if err != nil || candidate == nil {
		t.Fatalf("claims-derived checkpoint = %v, %v", candidate, err)
	}
	lease := OfflineLease{RootID: binding.RootID, WorkOrderID: binding.WorkOrderID, AttemptID: binding.AttemptID, LeaseEpoch: binding.LeaseEpoch, WorkerID: binding.WorkerID, SessionID: binding.SessionID, PolicyDigest: binding.PolicyDigest, Policy: claims.Binding.Policy, Checkpointability: claims.Binding.Checkpointability}
	if !AcceptOfflineCheckpoint(*candidate, lease) {
		t.Fatal("claims-derived policy rejected against matching lease")
	}
}

func TestOfflinePolicyClaimsOperationSliceIsCopied(t *testing.T) {
	binding, claims := offlineFixture()
	original := claims.AllowedOperations
	session := newOfflineSession(t, binding, claims, &testOfflineClock{}, &testOfflineVerifier{claims: claims})
	original[1] = ExternalEffect
	claims.AllowedOperations[0] = ExternalEffect
	if _, err := session.Authorize(LocalCheckpoint); err != nil {
		t.Fatalf("caller mutation affected retained claims: %v", err)
	}
}
func (c *testOfflineClock) Elapsed() time.Duration { return c.elapsed }

type testOfflineVerifier struct {
	claims  OfflineGrantClaims
	err     error
	advance func()
}

func (v *testOfflineVerifier) VerifyOfflineGrant(token []byte) (OfflineGrantClaims, error) {
	if v.advance != nil {
		v.advance()
	}
	return v.claims, v.err
}

func offlineFixture() (OfflineGrantBinding, OfflineGrantClaims) {
	digest, _ := ParseDigest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	binding := OfflineGrantBinding{GrantID: "grant-1", RootID: RootID("root-1"), WorkOrderID: WorkOrderID("work-1"), AttemptID: "attempt-1", LeaseEpoch: 7, WorkerID: "worker-1", SessionID: "session-1", PolicyDigest: digest, Policy: OfflineCompute, Checkpointability: Checkpointable}
	return binding, OfflineGrantClaims{Binding: binding, TTL: time.Minute, AllowedOperations: []OperationClass{LocalCompute, LocalCheckpoint}}
}

func newOfflineSession(t *testing.T, binding OfflineGrantBinding, claims OfflineGrantClaims, clock *testOfflineClock, verifier OfflineGrantVerifier) *OfflineSession {
	t.Helper()
	session, err := VerifyOfflineGrant(binding, []byte("opaque"), verifier, clock)
	if err != nil {
		t.Fatalf("VerifyOfflineGrant() error = %v", err)
	}
	return session
}

func TestOfflinePolicyOnlineRequiredDenied(t *testing.T) {
	binding, _ := offlineFixture()
	clock := &testOfflineClock{}
	onlineBinding := binding
	onlineBinding.Policy = OnlineRequired
	if _, err := VerifyOfflineGrant(onlineBinding, nil, &testOfflineVerifier{claims: OfflineGrantClaims{Binding: onlineBinding, TTL: time.Minute, AllowedOperations: []OperationClass{LocalCompute}}}, clock); !errors.Is(err, ErrOfflineDenied) {
		t.Fatalf("expected deny, got %v", err)
	}
}

func TestOfflinePolicyComputeCheckpointabilityAndExternalDeny(t *testing.T) {
	binding, claims := offlineFixture()
	clock := &testOfflineClock{}
	session := newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	if candidate, err := session.Authorize(LocalCompute); err != nil || candidate != nil {
		t.Fatalf("compute = %v, %v", candidate, err)
	}
	candidate, err := session.Authorize(LocalCheckpoint)
	if err != nil || candidate == nil {
		t.Fatalf("checkpoint = %v, %v", candidate, err)
	}
	if _, err := session.Authorize(ExternalEffect); !errors.Is(err, ErrOfflineDenied) {
		t.Fatalf("external effect allowed: %v", err)
	}
	noCPClaims := claims
	noCPClaims.Binding.Checkpointability = NotCheckpointable
	noCPClaims.AllowedOperations = []OperationClass{LocalCompute}
	bindingNoCP := binding
	bindingNoCP.Checkpointability = NotCheckpointable
	noCP := &testOfflineVerifier{claims: noCPClaims}
	session = newOfflineSession(t, bindingNoCP, noCPClaims, clock, noCP)
	if _, err := session.Authorize(LocalCheckpoint); !errors.Is(err, ErrOfflineDenied) {
		t.Fatalf("non-checkpointable action allowed: %v", err)
	}
	claims.AllowedOperations = []OperationClass{LocalCompute}
	session = newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	if _, err := session.Authorize(LocalCheckpoint); !errors.Is(err, ErrOfflineDenied) {
		t.Fatalf("unclaimed checkpoint allowed: %v", err)
	}
}

func TestOfflinePolicyVerifierAndClaimsFailClosed(t *testing.T) {
	binding, claims := offlineFixture()
	clock := &testOfflineClock{}
	if _, err := VerifyOfflineGrant(binding, nil, nil, clock); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("nil verifier: %v", err)
	}
	if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{err: errors.New("secret verifier detail")}, clock); !errors.Is(err, ErrInvalidGrant) || err.Error() != ErrInvalidGrant.Error() {
		t.Fatalf("verifier error was not sanitized: %v", err)
	}
	for _, mutate := range []func(*OfflineGrantClaims){
		func(c *OfflineGrantClaims) { c.TTL = 0 },
		func(c *OfflineGrantClaims) { c.TTL = -time.Second },
		func(c *OfflineGrantClaims) { c.Binding.SessionID = "other" },
		func(c *OfflineGrantClaims) { c.Binding.LeaseEpoch = 0 },
		func(c *OfflineGrantClaims) { c.Binding.Policy = "UNKNOWN_POLICY" },
		func(c *OfflineGrantClaims) { c.Binding.Checkpointability = "UNKNOWN_CHECKPOINTABILITY" },
		func(c *OfflineGrantClaims) { c.Binding.Checkpointability = NotCheckpointable },
		func(c *OfflineGrantClaims) { c.AllowedOperations = []OperationClass{LocalCompute, ExternalEffect} },
		func(c *OfflineGrantClaims) { c.AllowedOperations = []OperationClass{LocalCompute, "UNKNOWN"} },
		func(c *OfflineGrantClaims) { c.AllowedOperations = []OperationClass{LocalCheckpoint} },
	} {
		bad := claims
		bad.AllowedOperations = append([]OperationClass(nil), claims.AllowedOperations...)
		mutate(&bad)
		if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{claims: bad}, clock); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("malformed claims accepted: %v", err)
		}
	}
}

func TestOfflinePolicyTTLIncludesVerifierTimeAndRejectsRollback(t *testing.T) {
	binding, claims := offlineFixture()
	clock := &testOfflineClock{}
	verifier := &testOfflineVerifier{claims: claims, advance: func() { clock.elapsed = 59 * time.Second }}
	session := newOfflineSession(t, binding, claims, clock, verifier)
	clock.elapsed = time.Minute
	if _, err := session.Authorize(LocalCompute); !errors.Is(err, ErrOfflineExpired) {
		t.Fatalf("expected expiry after verifier-consumed TTL, got %v", err)
	}

	clock = &testOfflineClock{}
	session = newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	clock.elapsed = 2 * time.Second
	if _, err := session.Authorize(LocalCompute); err != nil {
		t.Fatal(err)
	}
	clock.elapsed = time.Second
	if _, err := session.Authorize(LocalCompute); !errors.Is(err, ErrOfflineClock) {
		t.Fatalf("clock rollback accepted: %v", err)
	}
	clock.elapsed = 3 * time.Second
	if _, err := session.Authorize(LocalCompute); !errors.Is(err, ErrOfflineClock) {
		t.Fatalf("session recovered after clock rollback: %v", err)
	}
	clock = &testOfflineClock{elapsed: -time.Second}
	if _, err := VerifyOfflineGrant(binding, nil, &testOfflineVerifier{claims: claims}, clock); !errors.Is(err, ErrOfflineClock) {
		t.Fatalf("negative initial elapsed accepted: %v", err)
	}
}

func TestOfflinePolicyReconnectFencesExactIdentity(t *testing.T) {
	binding, claims := offlineFixture()
	clock := &testOfflineClock{}
	session := newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	candidate, err := session.Authorize(LocalCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	current := OfflineLease{RootID: binding.RootID, WorkOrderID: binding.WorkOrderID, AttemptID: binding.AttemptID, LeaseEpoch: binding.LeaseEpoch, WorkerID: binding.WorkerID, SessionID: binding.SessionID, PolicyDigest: binding.PolicyDigest, Policy: claims.Binding.Policy, Checkpointability: claims.Binding.Checkpointability}
	if !AcceptOfflineCheckpoint(*candidate, current) {
		t.Fatal("current candidate rejected")
	}
	stale := []OfflineLease{current, current, current, current, current, current}
	stale[0].RootID = "other-root"
	stale[1].WorkOrderID = "other-work"
	stale[2].AttemptID = "other-attempt"
	stale[3].WorkerID = "other-worker"
	stale[4].SessionID = "new-process-session"
	stale[5].LeaseEpoch++
	for i, lease := range stale {
		if AcceptOfflineCheckpoint(*candidate, lease) {
			t.Errorf("stale lease mutation %d accepted", i)
		}
	}
	otherDigest := current
	otherDigest.PolicyDigest = Digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if AcceptOfflineCheckpoint(*candidate, otherDigest) {
		t.Fatal("digest mismatch accepted")
	}
	if func() bool {
		changed := current
		changed.Policy = OnlineRequired
		if AcceptOfflineCheckpoint(*candidate, changed) {
			return true
		}
		changed = current
		changed.Checkpointability = NotCheckpointable
		return AcceptOfflineCheckpoint(*candidate, changed)
	}() {
		t.Fatal("policy mismatch accepted")
	}
}

func TestOfflineSessionAndCandidateHaveNoExportedJSONState(t *testing.T) {
	binding, claims := offlineFixture()
	clock := &testOfflineClock{}
	session := newOfflineSession(t, binding, claims, clock, &testOfflineVerifier{claims: claims})
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	var restored OfflineSession
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.Authorize(LocalCompute); !errors.Is(err, ErrOfflineDenied) {
		t.Fatalf("JSON-reconstructed session authorized: %v", err)
	}
	candidate, err := session.Authorize(LocalCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	candidateJSON, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if string(candidateJSON) != "{}" {
		t.Fatalf("candidate unexpectedly serializable: %s", candidateJSON)
	}
}
