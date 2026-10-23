package domain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"
)

func signHoldExtend(t *testing.T, r PolicyRollout, ids []string, keys []ed25519.PrivateKey) []SafetySignature {
	t.Helper()
	msg, err := HoldExtendApprovalMessage(r, r.BaseSecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
	if err != nil {
		t.Fatal(err)
	}

	out := make([]SafetySignature, len(ids))
	for i, id := range ids {
		out[i] = SafetySignature{id, ed25519.Sign(keys[i], msg)}
	}
	return out
}

func TestHoldExtendQuorumOneShotAndCumulativeCap(t *testing.T) {
	q, ids, keys, _ := safetyFixture(t)
	s, r, start := monitoringFixture(t)
	// Consume a closed episode first: extension must not reset that usage.
	r = recordMonitoring(t, r, DecisionHold, start.Add(time.Hour))
	r = recordMonitoring(t, r, DecisionPass, start.Add(7*time.Hour))
	r = recordMonitoring(t, r, DecisionHold, start.Add(10*time.Hour))
	before := r
	for _, count := range []int{2, 3} {
		sigs := signHoldExtend(t, r, ids[:count], keys[:count])
		out, err := q.HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, sigs, start.Add(11*time.Hour))
		if err != nil || out.Validate() != nil {
			t.Fatal(err)
		}
		m := out.Monitoring
		if !m.ExtensionUsed || m.HoldBudget != 48*time.Hour || m.HoldUsed != 6*time.Hour || m.ExtensionCommandID != "extend-1" || m.ExtensionNonce != "nonce-1" || !m.HoldDeadline.Equal(start.Add(52*time.Hour)) || m.ObservationDeadline != r.Monitoring.ObservationDeadline {
			t.Fatal(m)
		}
		if got, err := q.HoldExtend(s, out, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, sigs, start.Add(12*time.Hour)); err == nil || !reflect.DeepEqual(got, out) {
			t.Fatal("extension replay accepted")
		}
		if got, err := q.HoldExtend(s, out, s.SecurityEpoch, "extend-2", "nonce-2", MonitoringExtendedCap, sigs, start.Add(12*time.Hour)); err == nil || !reflect.DeepEqual(got, out) {
			t.Fatal("second extension accepted")
		}
		out = recordMonitoring(t, out, DecisionPass, start.Add(51*time.Hour))
		if out.Monitoring.HoldUsed != 47*time.Hour {
			t.Fatal("extension reset cumulative usage")
		}
		out = recordMonitoring(t, out, DecisionHold, start.Add(60*time.Hour))
		if !out.Monitoring.HoldDeadline.Equal(start.Add(61 * time.Hour)) {
			t.Fatal("extended cap reset per episode")
		}
		got, result, err := EvaluateMonitoring(out, start.Add(100*time.Hour))
		if err != nil || result != MonitoringSafeRollback || got.Monitoring.HoldUsed != MonitoringExtendedCap {
			t.Fatal(result, err)
		}
	}
	if !reflect.DeepEqual(before, r) {
		t.Fatal("input mutated")
	}
}

func TestHoldExtendRejectsInvalidSignaturesAndAuthority(t *testing.T) {
	q, ids, keys, _ := safetyFixture(t)
	s, r, start := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, start.Add(time.Hour))
	valid := signHoldExtend(t, r, ids[:2], keys[:2])
	unknown := append([]SafetySignature(nil), valid...)
	unknown[0].SignerID = "outsider"
	malformed := append([]SafetySignature(nil), valid...)
	malformed[0].Signature = []byte{1}
	invalid := append([]SafetySignature(nil), valid...)
	invalid[0].Signature = make([]byte, ed25519.SignatureSize)
	for _, tc := range []struct {
		name string
		sigs []SafetySignature
	}{
		{"none", nil}, {"one", valid[:1]}, {"unknown", unknown}, {"duplicate", []SafetySignature{valid[0], valid[0]}},
		{"malformed", malformed}, {"invalid", invalid}, {"valid pair plus invalid", append(append([]SafetySignature(nil), valid...), SafetySignature{ids[2], []byte{1}})},
		{"four", append(append([]SafetySignature(nil), valid...), valid...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := q.HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, tc.sigs, start.Add(2*time.Hour))
			if err == nil || !reflect.DeepEqual(got, r) {
				t.Fatal("bad signatures accepted or input changed")
			}
		})
	}
	for _, change := range []func(*AuthorityState){
		func(s *AuthorityState) { s.Scope = "other" }, func(s *AuthorityState) { s.SecurityEpoch++ },
		func(s *AuthorityState) { s.ScopeActivationEpoch++ }, func(s *AuthorityState) { s.DatabaseAvailable = false },
		func(s *AuthorityState) { s.Mode = ScopeFrozen }, func(s *AuthorityState) { s.Mode = ScopeSafeStop },
	} {
		bad := cloneAuthority(s)
		change(&bad)
		if got, err := q.HoldExtend(bad, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, valid, start.Add(2*time.Hour)); err == nil || !reflect.DeepEqual(got, r) {
			t.Fatal("bad authority accepted")
		}
	}
	for _, at := range []time.Time{{}, start, r.Monitoring.HoldDeadline, r.Monitoring.HoldDeadline.Add(time.Hour)} {
		if got, err := q.HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, valid, at); err == nil || !reflect.DeepEqual(got, r) {
			t.Fatal("bad clock/expired hold accepted")
		}
	}
	if got, err := (SafetyQuorum{}).HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, valid, start.Add(2*time.Hour)); err == nil || !reflect.DeepEqual(got, r) {
		t.Fatal("zero quorum accepted")
	}
}

func TestHoldExtendSigningBindsSnapshotAndCommand(t *testing.T) {
	q, ids, keys, _ := safetyFixture(t)
	s, r, start := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, start.Add(time.Hour))
	msg, err := HoldExtendApprovalMessage(r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := HoldExtendApprovalMessage(r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
	if err != nil || !bytes.Equal(msg, msg2) {
		t.Fatal("nondeterministic signing bytes")
	}
	valid := signHoldExtend(t, r, ids[:2], keys[:2])
	for _, tc := range []struct {
		name   string
		change func(*PolicyRollout)
	}{
		{"rollout", func(r *PolicyRollout) { r.ID = "other" }},
		{"scope", func(r *PolicyRollout) { r.Scope = "other" }},
		{"epoch", func(r *PolicyRollout) { r.BaseSecurityEpoch++ }},
		{"cumulative used", func(r *PolicyRollout) {
			r.Monitoring.HoldUsed = time.Hour
			r.Monitoring.ObservationDeadline = r.Monitoring.ObservationDeadline.Add(time.Hour)
			r.Monitoring.HoldDeadline = r.Monitoring.HoldDeadline.Add(-time.Hour)
		}},
		{"deadline", func(r *PolicyRollout) {
			r.Monitoring.HoldSince = r.Monitoring.HoldSince.Add(-time.Second)
			r.Monitoring.HoldDeadline = r.Monitoring.HoldDeadline.Add(-time.Second)
		}},
		{"budget", func(r *PolicyRollout) { r.Monitoring.HoldBudget = MonitoringExtendedCap }},
		{"extension flag", func(r *PolicyRollout) { r.Monitoring.ExtensionUsed = true }},
		{"evidence", func(r *PolicyRollout) { r.Monitoring.EvidenceDigest = digestOf('f') }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			tc.change(&bad)
			candidate, err := HoldExtendApprovalMessage(bad, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
			if err == nil && bytes.Equal(candidate, msg) {
				t.Fatal("snapshot field not bound")
			}
			if got, err := q.HoldExtend(s, bad, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, valid, start.Add(2*time.Hour)); err == nil || !reflect.DeepEqual(got, bad) {
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
	for _, tc := range []struct {
		command, nonce string
		cap            time.Duration
	}{
		{"other", "nonce-1", MonitoringExtendedCap}, {"extend-1", "other", MonitoringExtendedCap},
		{"", "nonce-1", MonitoringExtendedCap}, {"extend-1", "", MonitoringExtendedCap},
		{"extend-1", "nonce-1", MonitoringHoldBudget}, {"extend-1", "nonce-1", MonitoringExtendedCap + 1},
	} {
		if got, err := q.HoldExtend(s, r, s.SecurityEpoch, tc.command, tc.nonce, tc.cap, valid, start.Add(2*time.Hour)); err == nil || !reflect.DeepEqual(got, r) {
			t.Fatal("command/cap not bound")
		}
	}
	if _, err := SafetyApprovalMessage(SafetyActionHoldExtend, r.Scope, s.SecurityEpoch, "extend-1", "nonce-1"); err == nil {
		t.Fatal("unbound generic hold message accepted")
	}
	if err := q.VerifySafetyApproval(s, SafetyActionHoldExtend, s.SecurityEpoch, "extend-1", "nonce-1", valid); err == nil {
		t.Fatal("generic verifier accepted unbound hold")
	}
}

func TestSafetyQuorumRejectsDuplicateHumanKeys(t *testing.T) {
	_, ids, keys, _ := safetyFixture(t)
	signers := []SafetySigner{{ids[0], keys[0].Public().(ed25519.PublicKey)}, {ids[1], keys[0].Public().(ed25519.PublicKey)}, {ids[2], keys[2].Public().(ed25519.PublicKey)}}
	if _, err := NewSafetyQuorum(signers); err == nil {
		t.Fatal("one key counted as two humans")
	}
}

func TestSafetyStopReleaseSigningCompatibility(t *testing.T) {
	// Fixed protocol fixtures intentionally independent of HoldExtend's payload.
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	for _, tc := range []struct {
		action SafetyAction
		digest [][32]byte
		want   string
	}{
		{SafetyActionStop, nil, "3fd1ee7d54fd40764793b45d98f4da95805f45b923fa65a0f106327bf411380c"},
		{SafetyActionRelease, [][32]byte{digest}, "6c37d4c5f9c544f366d038ac935aca3212d2b5dad3951dc100f0db2e392b2c65"},
	} {
		msg, err := SafetyApprovalMessage(tc.action, "scope-a", 7, "cmd", "nonce-1", tc.digest...)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(msg)); got != tc.want {
			t.Errorf("%s hash = %s", tc.action, got)
		}
	}
}

func safetyFixture(t *testing.T) (SafetyQuorum, []string, []ed25519.PrivateKey, AuthorityState) {
	t.Helper()
	ids := []string{"human-a", "human-b", "human-c"}
	priv := make([]ed25519.PrivateKey, 3)
	signers := make([]SafetySigner, 3)
	for i := range ids {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		priv[i] = ed25519.NewKeyFromSeed(seed)
		signers[i] = SafetySigner{ID: ids[i], PublicKey: append([]byte(nil), priv[i].Public().(ed25519.PublicKey)...)}
	}
	q, err := NewSafetyQuorum(signers)
	if err != nil {
		t.Fatal(err)
	}
	state := AuthorityState{Scope: "scope-a", ScopeActivationEpoch: 4, SecurityEpoch: 7, Mode: ScopeActive, DatabaseAvailable: true, Roots: map[RootID]RootAuthority{"root-b": {Policy: PolicyBinding{Digest: digestOf('b')}, AuthorizationEpoch: 3}, "root-a": {Policy: PolicyBinding{SafeBaseline: true}, AuthorizationEpoch: 2}}}
	return q, ids, priv, state
}
func signSafety(t *testing.T, action SafetyAction, scope ScopeID, epoch Epoch, command, nonce string, digest *[32]byte, ids []string, priv []ed25519.PrivateKey) []SafetySignature {
	t.Helper()
	var msg []byte
	var err error
	if digest == nil {
		msg, err = SafetyApprovalMessage(action, scope, epoch, command, nonce)
	} else {
		msg, err = SafetyApprovalMessage(action, scope, epoch, command, nonce, *digest)
	}
	if err != nil {
		t.Fatal(err)
	}
	out := make([]SafetySignature, 0, len(ids))
	for _, id := range ids {
		i := 0
		for ids[i] != id {
			i++
		}
		out = append(out, SafetySignature{SignerID: id, Signature: ed25519.Sign(priv[i], msg)})
	}
	return out
}
func TestAuthenticatedStopQuorumAndReplay(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	for _, signers := range [][]string{{ids[0], ids[1]}, {ids[0], ids[1], ids[2]}} {
		result, err := q.Stop(state, "scope-a", 7, "stop-1", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", "nonce-1", nil, signers, priv))
		if err != nil {
			t.Fatal(err)
		}
		if result.State.Mode != ScopeSafeStop || result.State.SecurityEpoch != 8 || result.State.ScopeActivationEpoch != 4 {
			t.Fatalf("bad stop result: %+v", result.State)
		}
		if state.Mode != ScopeActive || state.SecurityEpoch != 7 {
			t.Fatal("input mutated")
		}
	}
	if _, err := q.Stop(state, "scope-a", 7, "stop-1", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", "nonce-1", nil, ids[:2], priv)); err != nil {
		t.Fatalf("pure transition retry from old snapshot should authenticate; persistence owns receipt/replay: %v", err)
	}
	stopped, err := q.Stop(state, "scope-a", 7, "stop-1", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", "nonce-1", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Stop(stopped.State, "scope-a", 7, "stop-1", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", "nonce-1", nil, ids[:2], priv)); err == nil {
		t.Fatal("old-epoch stop approval replay accepted")
	}
}
func TestStopRejectsInvalidApprovalsAndState(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	valid := signSafety(t, SafetyActionStop, "scope-a", 7, "cmd", "nonce-1", nil, ids[:2], priv)
	badSig := append([]SafetySignature(nil), valid...)
	badSig[0].Signature[0] ^= 1
	unknown := append([]SafetySignature(nil), valid...)
	unknown[0].SignerID = "unknown"
	cases := []struct {
		name  string
		s     AuthorityState
		scope ScopeID
		epoch Epoch
		cmd   string
		sig   []SafetySignature
	}{{"one signer", state, "scope-a", 7, "cmd", valid[:1]}, {"duplicate", state, "scope-a", 7, "cmd", []SafetySignature{valid[0], valid[0]}}, {"unknown", state, "scope-a", 7, "cmd", unknown}, {"invalid signature", state, "scope-a", 7, "cmd", badSig}, {"wrong scope", state, "scope-b", 7, "cmd", valid}, {"wrong epoch", state, "scope-a", 8, "cmd", valid}, {"wrong command", state, "scope-a", 7, "other", valid}, {"DB unavailable", func() AuthorityState { s := state; s.DatabaseAvailable = false; return s }(), "scope-a", 7, "cmd", valid}, {"malformed root", func() AuthorityState {
		s := state
		s.Roots = map[RootID]RootAuthority{"": {Policy: PolicyBinding{SafeBaseline: true}}}
		return s
	}(), "scope-a", 7, "cmd", valid}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := q.Stop(tc.s, tc.scope, tc.epoch, tc.cmd, "nonce-1", tc.sig); err == nil {
				t.Fatal("accepted invalid stop")
			}
		})
	}
	if _, err := SafetyApprovalMessage(SafetyActionStop, "scope-a", Epoch(math.MaxUint64), "cmd", "nonce-1"); err == nil {
		t.Fatal("accepted epoch outside the RFC 8785 safe integer range")
	}
}
func TestAuthenticatedReleaseBindsActivationDeterministically(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	stopped, err := q.Stop(state, "scope-a", 7, "stop", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop", "nonce-1", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	activation := AuthorityState{Scope: "scope-a", ScopeActivationEpoch: 5, SecurityEpoch: 9, Mode: ScopeActive, DatabaseAvailable: true, Roots: map[RootID]RootAuthority{"root-a": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 3}, "root-b": {Policy: PolicyBinding{Digest: digestOf('c')}, AuthorizationEpoch: 4}}}
	// expected stop epoch 8, and release advances security exactly once to 9
	digest, err := ActivationDigest(activation)
	if err != nil {
		t.Fatal(err)
	}
	sig := signSafety(t, SafetyActionRelease, "scope-a", 8, "release", "nonce-1", &digest, ids[:2], priv)
	result, err := q.Release(stopped.State, activation, "scope-a", 8, "release", "nonce-1", sig)
	if err != nil {
		t.Fatal(err)
	}
	if result.State.SecurityEpoch != 9 || result.State.Mode != ScopeActive {
		t.Fatalf("bad release: %+v", result.State)
	}
	permuted := activation
	permuted.Roots = map[RootID]RootAuthority{}
	permuted.Roots["root-b"] = activation.Roots["root-b"]
	permuted.Roots["root-a"] = activation.Roots["root-a"]
	d2, err := ActivationDigest(permuted)
	if err != nil || digest != d2 {
		t.Fatalf("map order changed digest: %x %x %v", digest, d2, err)
	}
	altered := activation
	altered.Roots = map[RootID]RootAuthority{"root-a": activation.Roots["root-a"], "root-b": {Policy: PolicyBinding{Digest: digestOf('d')}, AuthorizationEpoch: 4}}
	if _, err = q.Release(stopped.State, altered, "scope-a", 8, "release", "nonce-1", sig); err == nil {
		t.Fatal("approval accepted changed activation")
	}
	if _, err = q.Release(result.State, activation, "scope-a", 9, "release", "nonce-1", sig); err == nil {
		t.Fatal("old approval replay accepted")
	}
}
func TestReleaseRejectsBadApprovalAndActivation(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	stopped, err := q.Stop(state, "scope-a", 7, "stop", "nonce-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop", "nonce-1", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	base := AuthorityState{Scope: "scope-a", ScopeActivationEpoch: 5, SecurityEpoch: 9, Mode: ScopeActive, DatabaseAvailable: true, Roots: map[RootID]RootAuthority{"root-a": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 3}}}
	d, _ := ActivationDigest(base)
	valid := signSafety(t, SafetyActionRelease, "scope-a", 8, "release", "nonce-1", &d, ids[:2], priv)
	bad := []struct {
		name                string
		current, activation AuthorityState
		scope               ScopeID
		epoch               Epoch
		cmd                 string
		sig                 []SafetySignature
	}{{"one signer", stopped.State, base, "scope-a", 8, "release", valid[:1]}, {"wrong command", stopped.State, base, "scope-a", 8, "other", valid}, {"wrong scope", stopped.State, base, "scope-b", 8, "release", valid}, {"wrong epoch", stopped.State, base, "scope-a", 7, "release", valid}, {"not stopped", state, base, "scope-a", 7, "release", valid}, {"database outage", func() AuthorityState { s := stopped.State; s.DatabaseAvailable = false; return s }(), base, "scope-a", 8, "release", valid}, {"stale activation epoch", stopped.State, func() AuthorityState { s := base; s.ScopeActivationEpoch = 4; return s }(), "scope-a", 8, "release", valid}, {"security epoch not +1", stopped.State, func() AuthorityState { s := base; s.SecurityEpoch = 10; return s }(), "scope-a", 8, "release", valid}, {"different scope", stopped.State, func() AuthorityState { s := base; s.Scope = "scope-b"; return s }(), "scope-a", 8, "release", valid}, {"invalid mode", stopped.State, func() AuthorityState { s := base; s.Mode = ScopeSafeStop; return s }(), "scope-a", 8, "release", valid}, {"invalid policy", stopped.State, func() AuthorityState {
		s := base
		s.Roots = map[RootID]RootAuthority{"root-a": {Policy: PolicyBinding{}}}
		return s
	}(), "scope-a", 8, "release", valid}}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := q.Release(tc.current, tc.activation, tc.scope, tc.epoch, tc.cmd, "nonce-1", tc.sig); err == nil {
				t.Fatal("accepted invalid release")
			}
		})
	}
	max := stopped.State
	max.SecurityEpoch = Epoch(math.MaxUint64)
	next := base
	next.SecurityEpoch = Epoch(math.MaxUint64)
	if _, err = q.Release(max, next, "scope-a", Epoch(math.MaxUint64), "release", "nonce-1", nil); err == nil {
		t.Fatal("accepted overflow")
	}
}
func TestSafetyMessageContextAndQuorumConfiguration(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	msg, err := SafetyApprovalMessage(SafetyActionStop, "scope-a", 7, "cmd", "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	sig := []SafetySignature{{ids[0], ed25519.Sign(priv[0], msg)}, {ids[1], ed25519.Sign(priv[1], msg)}}
	if err = q.VerifySafetyApproval(state, SafetyActionStop, 7, "other", "nonce-1", sig); err == nil {
		t.Fatal("command not bound")
	}
	if err = q.VerifySafetyApproval(state, SafetyActionRelease, 7, "cmd", "nonce-1", sig); err == nil {
		t.Fatal("action not bound")
	}
	if err = q.VerifySafetyApproval(state, SafetyActionStop, 7, "cmd", "wrong-nonce", sig); err == nil {
		t.Fatal("nonce not bound")
	}
	if _, err = SafetyApprovalMessage(SafetyActionRelease, "scope-a", 7, "cmd", "nonce-1"); err == nil {
		t.Fatal("release message omitted activation digest")
	}
	bad := []SafetySigner{{"a", make([]byte, ed25519.PublicKeySize)}, {"a", make([]byte, ed25519.PublicKeySize)}, {"c", make([]byte, ed25519.PublicKeySize)}}
	if _, err = NewSafetyQuorum(bad); err == nil {
		t.Fatal("duplicate signer IDs accepted")
	}
}

func TestHoldExtendRevisionBindingAtEqualClockAndInt64Boundary(t *testing.T) {
	q, ids, keys, _ := safetyFixture(t)
	s, r, at := monitoringFixture(t)
	r = recordMonitoring(t, r, DecisionHold, at)
	sigs := signHoldExtend(t, r, ids[:2], keys[:2])
	message, err := HoldExtendApprovalMessage(r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
	if err != nil {
		t.Fatal(err)
	}
	next := recordMonitoring(t, r, DecisionHold, at)
	message2, err := HoldExtendApprovalMessage(next, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
	if err != nil || bytes.Equal(message, message2) {
		t.Fatal("equal-time re-record did not change signing bytes", err)
	}
	if _, err := q.HoldExtend(s, next, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, sigs, at); err == nil {
		t.Fatal("stale revision approval accepted")
	}
	for _, revision := range []int64{1 << 53, 1<<53 + 1, math.MaxInt64 - 1, math.MaxInt64} {
		r.Monitoring.DecisionRevision = revision
		message, err = HoldExtendApprovalMessage(r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap)
		if err != nil || bytes.Equal(message, message2) || !bytes.Contains(message, []byte(fmt.Sprintf(`"decision_revision":"%d"`, revision))) {
			t.Fatal("full int64 not bound exactly", revision, err)
		}
		sigs = signHoldExtend(t, r, ids[:2], keys[:2])
		out, err := q.HoldExtend(s, r, s.SecurityEpoch, "extend-1", "nonce-1", MonitoringExtendedCap, sigs, at)
		if err != nil || out.Monitoring.DecisionRevision != revision {
			t.Fatal("extension must preserve revision", revision, err)
		}
		message2 = message
	}
}
