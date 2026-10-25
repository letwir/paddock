package domain

import (
	"crypto/ed25519"
	"math"
	"testing"
)

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
func signSafety(t *testing.T, action SafetyAction, scope ScopeID, epoch Epoch, command string, digest *[32]byte, ids []string, priv []ed25519.PrivateKey) []SafetySignature {
	t.Helper()
	var msg []byte
	var err error
	if digest == nil {
		msg, err = SafetyApprovalMessage(action, scope, epoch, command)
	} else {
		msg, err = SafetyApprovalMessage(action, scope, epoch, command, *digest)
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
		result, err := q.Stop(state, "scope-a", 7, "stop-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", nil, signers, priv))
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
	if _, err := q.Stop(state, "scope-a", 7, "stop-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", nil, ids[:2], priv)); err != nil {
		t.Fatalf("pure transition retry from old snapshot should authenticate; persistence owns receipt/replay: %v", err)
	}
	stopped, err := q.Stop(state, "scope-a", 7, "stop-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Stop(stopped.State, "scope-a", 7, "stop-1", signSafety(t, SafetyActionStop, "scope-a", 7, "stop-1", nil, ids[:2], priv)); err == nil {
		t.Fatal("old-epoch stop approval replay accepted")
	}
}
func TestStopRejectsInvalidApprovalsAndState(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	valid := signSafety(t, SafetyActionStop, "scope-a", 7, "cmd", nil, ids[:2], priv)
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
			if _, err := q.Stop(tc.s, tc.scope, tc.epoch, tc.cmd, tc.sig); err == nil {
				t.Fatal("accepted invalid stop")
			}
		})
	}
	if _, err := q.Stop(func() AuthorityState { s := state; s.SecurityEpoch = Epoch(math.MaxUint64); return s }(), "scope-a", Epoch(math.MaxUint64), "cmd", signSafety(t, SafetyActionStop, "scope-a", Epoch(math.MaxUint64), "cmd", nil, ids[:2], priv)); err == nil {
		t.Fatal("accepted epoch overflow")
	}
}
func TestAuthenticatedReleaseBindsActivationDeterministically(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	stopped, err := q.Stop(state, "scope-a", 7, "stop", signSafety(t, SafetyActionStop, "scope-a", 7, "stop", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	activation := AuthorityState{Scope: "scope-a", ScopeActivationEpoch: 5, SecurityEpoch: 9, Mode: ScopeActive, DatabaseAvailable: true, Roots: map[RootID]RootAuthority{"root-a": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 3}, "root-b": {Policy: PolicyBinding{Digest: digestOf('c')}, AuthorizationEpoch: 4}}}
	// expected stop epoch 8, and release advances security exactly once to 9
	digest, err := ActivationDigest(activation)
	if err != nil {
		t.Fatal(err)
	}
	sig := signSafety(t, SafetyActionRelease, "scope-a", 8, "release", &digest, ids[:2], priv)
	result, err := q.Release(stopped.State, activation, "scope-a", 8, "release", sig)
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
	if _, err = q.Release(stopped.State, altered, "scope-a", 8, "release", sig); err == nil {
		t.Fatal("approval accepted changed activation")
	}
	if _, err = q.Release(result.State, activation, "scope-a", 9, "release", sig); err == nil {
		t.Fatal("old approval replay accepted")
	}
}
func TestReleaseRejectsBadApprovalAndActivation(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	stopped, err := q.Stop(state, "scope-a", 7, "stop", signSafety(t, SafetyActionStop, "scope-a", 7, "stop", nil, ids[:2], priv))
	if err != nil {
		t.Fatal(err)
	}
	base := AuthorityState{Scope: "scope-a", ScopeActivationEpoch: 5, SecurityEpoch: 9, Mode: ScopeActive, DatabaseAvailable: true, Roots: map[RootID]RootAuthority{"root-a": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 3}}}
	d, _ := ActivationDigest(base)
	valid := signSafety(t, SafetyActionRelease, "scope-a", 8, "release", &d, ids[:2], priv)
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
			if _, err := q.Release(tc.current, tc.activation, tc.scope, tc.epoch, tc.cmd, tc.sig); err == nil {
				t.Fatal("accepted invalid release")
			}
		})
	}
	max := stopped.State
	max.SecurityEpoch = Epoch(math.MaxUint64)
	next := base
	next.SecurityEpoch = Epoch(math.MaxUint64)
	if _, err = q.Release(max, next, "scope-a", Epoch(math.MaxUint64), "release", nil); err == nil {
		t.Fatal("accepted overflow")
	}
}
func TestSafetyMessageContextAndQuorumConfiguration(t *testing.T) {
	q, ids, priv, state := safetyFixture(t)
	msg, err := SafetyApprovalMessage(SafetyActionStop, "scope-a", 7, "cmd")
	if err != nil {
		t.Fatal(err)
	}
	sig := []SafetySignature{{ids[0], ed25519.Sign(priv[0], msg)}, {ids[1], ed25519.Sign(priv[1], msg)}}
	if err = q.VerifySafetyApproval(state, SafetyActionStop, 7, "other", sig); err == nil {
		t.Fatal("command not bound")
	}
	if err = q.VerifySafetyApproval(state, SafetyActionRelease, 7, "cmd", sig); err == nil {
		t.Fatal("action not bound")
	}
	if _, err = SafetyApprovalMessage(SafetyActionRelease, "scope-a", 7, "cmd"); err == nil {
		t.Fatal("release message omitted activation digest")
	}
	bad := []SafetySigner{{"a", make([]byte, ed25519.PublicKeySize)}, {"a", make([]byte, ed25519.PublicKeySize)}, {"c", make([]byte, ed25519.PublicKeySize)}}
	if _, err = NewSafetyQuorum(bad); err == nil {
		t.Fatal("duplicate signer IDs accepted")
	}
}
