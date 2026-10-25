package domain

import (
	"errors"
	"strings"
	"testing"
)

func digestOf(ch byte) Digest { return Digest(strings.Repeat(string(ch), 64)) }

func TestRolloutCannotStartOrPromoteWithAnySafeBaselineRoot(t *testing.T) {
	state := rolloutFixture()
	state.Roots["root-a"] = RootAuthority{Policy: PolicyBinding{SafeBaseline: true}, AuthorizationEpoch: 2}
	if _, _, err := StartCanary(state, "rollout-safe-start", "root-b", digestOf('b')); !errors.Is(err, ErrSafeStopped) {
		t.Fatalf("Canary started while an unrelated Root was on Safe Baseline: %v", err)
	}

	// Model Safe Baseline becoming active after the Canary snapshot. Promotion
	// must not replace that safety policy with the normal candidate.
	state = rolloutFixture()
	canary, rollout, err := StartCanary(state, "rollout-safe-promote", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	safe := cloneAuthority(canary)
	safe.Roots["root-a"] = RootAuthority{Policy: PolicyBinding{SafeBaseline: true}, AuthorizationEpoch: 2}
	if _, _, err := Promote(safe, rollout); !errors.Is(err, ErrSafeStopped) {
		t.Fatalf("Promote replaced an unrelated Root's Safe Baseline: %v", err)
	}
}

func TestRolloutRejectsStaleSecurityEpoch(t *testing.T) {
	state := rolloutFixture()
	canary, rollout, err := StartCanary(state, "rollout-security-stale", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	stale := cloneAuthority(canary)
	stale.SecurityEpoch++
	if _, _, err := Promote(stale, rollout); !errors.Is(err, ErrInvalidRollout) {
		t.Fatalf("stale Security epoch accepted by Promote: %v", err)
	}
}

func TestRolloutRejectsStaleScopeAndRootEpochSnapshots(t *testing.T) {
	state := rolloutFixture()
	canary, rollout, err := StartCanary(state, "rollout-stale", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	staleScope := cloneAuthority(canary)
	staleScope.ScopeActivationEpoch++
	if _, _, err := Promote(staleScope, rollout); !errors.Is(err, ErrInvalidRollout) {
		t.Fatalf("stale Scope epoch accepted: %v", err)
	}
	staleRoot := cloneAuthority(canary)
	root := staleRoot.Roots["root-a"]
	root.AuthorizationEpoch++
	staleRoot.Roots["root-a"] = root
	if _, _, err := Promote(staleRoot, rollout); !errors.Is(err, ErrInvalidRollout) {
		t.Fatalf("stale unrelated Root epoch accepted: %v", err)
	}
}

func TestRolloutTransitionsDoNotMutateInputs(t *testing.T) {
	initial := rolloutFixture()
	canary, rollout, err := StartCanary(initial, "rollout-immutable", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	if initial.Roots["root-b"].Policy.Digest != digestOf('a') || initial.ScopeActivationEpoch != 40 {
		t.Fatal("StartCanary mutated its authority input")
	}
	if rollout.State != RolloutCanary || rollout.Baseline["root-a"].Digest != digestOf('a') || rollout.BaseRootEpochs["root-a"] != 1 {
		t.Fatal("unexpected captured rollout snapshot")
	}
	promoted, promotedRollout, err := Promote(canary, rollout)
	if err != nil {
		t.Fatal(err)
	}
	if canary.ScopeActivationEpoch != 41 || canary.Roots["root-a"].Policy.Digest != digestOf('a') || rollout.State != RolloutCanary {
		t.Fatal("Promote mutated an input")
	}
	if promoted.ScopeActivationEpoch != 42 || promotedRollout.State != RolloutMonitoring {
		t.Fatal("Promote did not return transitioned values")
	}
}

func TestEffectivePolicySafeBaselineDenies(t *testing.T) {
	state := rolloutFixture()
	state.Mode = ScopeSafeStop
	state.Roots["root-a"] = RootAuthority{Policy: PolicyBinding{SafeBaseline: true}, AuthorizationEpoch: 2}
	if _, err := EffectivePolicy(state, "root-a"); !errors.Is(err, ErrSafeStopped) {
		t.Fatalf("Safe Baseline effective policy must deny: %v", err)
	}
}

func rolloutFixture() AuthorityState {
	return AuthorityState{
		Scope: "scope-fixture", ScopeActivationEpoch: 40, SecurityEpoch: 5,
		Mode: ScopeActive, DatabaseAvailable: true,
		Roots: map[RootID]RootAuthority{
			"root-a": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 1},
			"root-b": {Policy: PolicyBinding{Digest: digestOf('a')}, AuthorizationEpoch: 1},
		},
	}
}

func TestCanaryPromoteRollbackEpochFixture(t *testing.T) {
	initial := rolloutFixture()
	canary, rollout, err := StartCanary(initial, "rollout-1", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	if canary.ScopeActivationEpoch != 41 || canary.SecurityEpoch != initial.SecurityEpoch || canary.Roots["root-b"].AuthorizationEpoch != 2 || canary.Roots["root-a"].AuthorizationEpoch != 1 {
		t.Fatalf("Canary epochs = scope %d, Root A %d, Root B %d", canary.ScopeActivationEpoch, canary.Roots["root-a"].AuthorizationEpoch, canary.Roots["root-b"].AuthorizationEpoch)
	}
	rootA, err := EffectivePolicy(canary, "root-a")
	if err != nil || rootA.Policy.Digest != digestOf('a') {
		t.Fatalf("Root A changed in Root B Canary: %+v, %v", rootA, err)
	}
	rootB, err := EffectivePolicy(canary, "root-b")
	if err != nil || rootB.Policy.Digest != digestOf('b') {
		t.Fatalf("Root B candidate missing: %+v, %v", rootB, err)
	}

	promoted, rollout, err := Promote(canary, rollout)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.ScopeActivationEpoch != 42 || promoted.SecurityEpoch != initial.SecurityEpoch || promoted.Roots["root-a"].AuthorizationEpoch != 2 || promoted.Roots["root-b"].AuthorizationEpoch != 2 || rollout.State != RolloutMonitoring {
		t.Fatalf("Promote result = %+v, rollout %+v", promoted, rollout)
	}
	for _, root := range []RootID{"root-a", "root-b"} {
		got, err := EffectivePolicy(promoted, root)
		if err != nil || got.Policy.Digest != digestOf('b') {
			t.Errorf("promoted %s policy = %+v, %v", root, got, err)
		}
	}

	frozen, rollout, err := Rollback(promoted, rollout)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Mode != ScopeFrozen || rollout.State != RolloutRollingBack || frozen.ScopeActivationEpoch != 42 || frozen.Roots["root-a"].AuthorizationEpoch != 2 || frozen.Roots["root-b"].AuthorizationEpoch != 2 {
		t.Fatalf("rollback phase one changed epoch/state: %+v rollout %+v", frozen, rollout)
	}
	if _, err := EffectivePolicy(frozen, "root-a"); !errors.Is(err, ErrScopeFrozen) {
		t.Fatalf("frozen Scope must deny: %v", err)
	}

	restored, rollout, err := FinalizePolicyRollback(frozen, rollout, LKGUsable)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ScopeActivationEpoch != 43 || restored.SecurityEpoch != 5 || restored.Roots["root-a"].AuthorizationEpoch != 3 || restored.Roots["root-b"].AuthorizationEpoch != 3 || restored.Mode != ScopeActive || rollout.State != RolloutRolledBack {
		t.Fatalf("rollback final state = %+v rollout %+v", restored, rollout)
	}
	for _, root := range []RootID{"root-a", "root-b"} {
		got, err := EffectivePolicy(restored, root)
		if err != nil || got.Policy.Digest != digestOf('a') {
			t.Errorf("rollback %s policy = %+v, %v", root, got, err)
		}
	}
	if initial.ScopeActivationEpoch != 40 || initial.Roots["root-b"].Policy.Digest != digestOf('a') {
		t.Fatalf("transition mutated input snapshot: %+v", initial)
	}
}

func TestCanaryAndRollbackFailClosed(t *testing.T) {
	state := rolloutFixture()
	noDB := state
	noDB.DatabaseAvailable = false
	if _, _, err := StartCanary(noDB, "rollout-1", "root-b", digestOf('b')); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("Canary with unavailable DB = %v", err)
	}
	canary, rollout, err := StartCanary(state, "rollout-1", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	frozen, rollout, err := Rollback(canary, rollout)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []LKGStatus{LKGUnavailable, LKGInvalid, LKGStatus("UNKNOWN")} {
		stopped, done, err := FinalizePolicyRollback(frozen, rollout, status)
		if err != nil {
			t.Fatalf("status %s: %v", status, err)
		}
		if stopped.Mode != ScopeSafeStop || done.State != RolloutSafeStopped || stopped.ScopeActivationEpoch != 42 {
			t.Errorf("status %s did not select Safe Baseline: %+v %+v", status, stopped, done)
		}
		for root, authority := range stopped.Roots {
			wantEpoch := Epoch(2)
			if root == "root-b" {
				wantEpoch = 3
			}
			if !authority.Policy.SafeBaseline || authority.AuthorizationEpoch != wantEpoch {
				t.Errorf("status %s root %s = %+v, want epoch %d", status, root, authority, wantEpoch)
			}
			if _, err := EffectivePolicy(stopped, root); !errors.Is(err, ErrSafeStopped) {
				t.Errorf("Safe Baseline must deny Root %s: %v", root, err)
			}
		}
	}
}

func TestRolloutRejectsInvalidStateAndUnchangedCandidate(t *testing.T) {
	state := rolloutFixture()
	if _, _, err := StartCanary(state, "rollout-1", "missing", digestOf('b')); !errors.Is(err, ErrRootNotFound) {
		t.Fatalf("unknown Root error = %v", err)
	}
	if _, _, err := StartCanary(state, "rollout-1", "root-b", digestOf('a')); !errors.Is(err, ErrPolicyNoChange) {
		t.Fatalf("unchanged candidate error = %v", err)
	}
	canary, rollout, err := StartCanary(state, "rollout-1", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	rollout.State = RolloutCompleted
	if _, _, err := Promote(canary, rollout); !errors.Is(err, ErrInvalidRollout) {
		t.Fatalf("invalid Promote state error = %v", err)
	}

	canary, rollout, err = StartCanary(state, "rollout-2", "root-b", digestOf('b'))
	if err != nil {
		t.Fatal(err)
	}
	stale := cloneAuthority(canary)
	stale.Roots["root-b"] = RootAuthority{Policy: PolicyBinding{Digest: digestOf('c')}, AuthorizationEpoch: 3}
	if _, _, err := Rollback(stale, rollout); !errors.Is(err, ErrInvalidRollout) {
		t.Fatalf("stale authority state accepted by Rollback: %v", err)
	}
}
