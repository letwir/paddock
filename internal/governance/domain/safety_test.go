package domain

import (
	"errors"
	"strings"
	"testing"
)

func validPolicy() PolicyBinding { return PolicyBinding{Digest: Digest(strings.Repeat("a", 64))} }
func validLKG() Digest           { return Digest(strings.Repeat("b", 64)) }

func fixtureAuthority() AuthorityState {
	return AuthorityState{
		Scope: ScopeID("scope-a"), ScopeActivationEpoch: 40, SecurityEpoch: 7,
		Mode: ScopeActive, DatabaseAvailable: true,
		Roots: map[RootID]RootAuthority{
			"root-a": {Policy: validPolicy(), AuthorizationEpoch: 10},
			"root-b": {Policy: validPolicy(), AuthorizationEpoch: 20},
		},
	}
}

func TestRollbackFreezesThenSwitchesAndAdvancesOnlyTargetRoot(t *testing.T) {
	initial := fixtureAuthority()
	frozen, plan, err := BeginRollback(initial, "root-b")
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Mode != ScopeFrozen || plan.State != RolloutRollingBack || plan.Finalized {
		t.Fatalf("phase one = mode %s, plan %+v", frozen.Mode, plan)
	}
	if frozen.ScopeActivationEpoch != 40 || frozen.Roots["root-b"].AuthorizationEpoch != 20 {
		t.Fatalf("epochs advanced before switch: %+v", frozen)
	}
	if initial.Mode != ScopeActive || initial.ScopeActivationEpoch != 40 {
		t.Fatalf("input snapshot mutated: %+v", initial)
	}
	if _, err := EffectivePolicy(frozen, "root-a"); !errors.Is(err, ErrScopeFrozen) {
		t.Fatalf("frozen Scope did not fail closed: %v", err)
	}

	lkg := validLKG()
	active, done, err := FinalizeRollback(frozen, plan, LKGAssessment{Status: LKGUsable, Digest: lkg})
	if err != nil {
		t.Fatal(err)
	}
	if active.ScopeActivationEpoch != 41 || active.Roots["root-b"].AuthorizationEpoch != 21 || active.Roots["root-a"].AuthorizationEpoch != 10 {
		t.Fatalf("wrong epochs after switch: %+v", active)
	}
	if active.Mode != ScopeActive || done.State != RolloutRolledBack || !done.Finalized {
		t.Fatalf("phase two = mode %s, plan %+v", active.Mode, done)
	}
	if active.Roots["root-b"].Policy != (PolicyBinding{Digest: lkg}) {
		t.Fatalf("LKG not selected: %+v", active.Roots["root-b"])
	}
	if _, _, err := FinalizeRollback(active, done, LKGAssessment{Status: LKGUsable, Digest: lkg}); !errors.Is(err, ErrRollbackState) {
		t.Fatalf("second finalize must fail: %v", err)
	}
}

func TestRollbackWithoutUsableLKGSelectsSafeBaseline(t *testing.T) {
	for name, lkg := range map[string]LKGAssessment{
		"unavailable": {Status: LKGUnavailable},
		"invalid":     {Status: LKGInvalid, Digest: validLKG()},
		"malformed":   {Status: LKGUsable, Digest: Digest("bad")},
		"unknown":     {Status: LKGStatus("UNKNOWN"), Digest: validLKG()}} {
		t.Run(name, func(t *testing.T) {
			frozen, plan, err := BeginRollback(fixtureAuthority(), "root-b")
			if err != nil {
				t.Fatal(err)
			}
			stopped, done, err := FinalizeRollback(frozen, plan, lkg)
			if err != nil {
				t.Fatal(err)
			}
			root := stopped.Roots["root-b"]
			if stopped.Mode != ScopeSafeStop || !root.Policy.SafeBaseline || root.Policy.Digest != "" {
				t.Fatalf("fallback not fail closed: %+v", stopped)
			}
			if stopped.ScopeActivationEpoch != 41 || root.AuthorizationEpoch != 21 || done.State != RolloutSafeStopped {
				t.Fatalf("fallback epochs/state wrong: %+v, %+v", stopped, done)
			}
			if _, err := EffectivePolicy(stopped, "root-a"); !errors.Is(err, ErrSafeStopped) {
				t.Fatalf("Safe Baseline did not deny: %v", err)
			}
		})
	}
}

func TestDatabaseUnavailableAndGrantEpochsFailClosed(t *testing.T) {
	s := fixtureAuthority()
	grant := Grant{Root: "root-a", Policy: validPolicy(), AuthorizationEpoch: 10, SecurityEpoch: 7}
	if err := Authorize(s, grant); err != nil {
		t.Fatalf("current grant denied: %v", err)
	}

	bFrozen, plan, err := BeginRollback(s, "root-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := Authorize(bFrozen, grant); !errors.Is(err, ErrScopeFrozen) {
		t.Fatalf("Root A grant during Scope Freeze = %v", err)
	}
	lkg := validLKG()
	rolled, _, err := FinalizeRollback(bFrozen, plan, LKGAssessment{Status: LKGUsable, Digest: lkg})
	if err != nil {
		t.Fatal(err)
	}
	if err := Authorize(rolled, grant); err != nil {
		t.Fatalf("Root B rollback incorrectly invalidated Root A grant: %v", err)
	}

	unavailable := rolled
	unavailable.DatabaseAvailable = false
	if err := Authorize(unavailable, grant); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("DB unavailable authorization = %v", err)
	}
}

func TestEmergencyStopAdvancesOnlySecurityEpochAndDenies(t *testing.T) {
	initial := fixtureAuthority()
	stopped, err := ApplyEmergencyStop(initial)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.SecurityEpoch != 8 || stopped.ScopeActivationEpoch != 40 || stopped.Roots["root-a"].AuthorizationEpoch != 10 {
		t.Fatalf("emergency stop changed wrong generations: %+v", stopped)
	}
	if err := Authorize(stopped, Grant{Root: "root-a", Policy: validPolicy(), AuthorizationEpoch: 10, SecurityEpoch: 7}); !errors.Is(err, ErrSafeStopped) {
		t.Fatalf("emergency stop did not deny: %v", err)
	}
	if initial.Mode != ScopeActive || initial.SecurityEpoch != 7 {
		t.Fatalf("input snapshot mutated: %+v", initial)
	}
}

func TestBeginRollbackRejectsUnavailableOrUnknownRoot(t *testing.T) {
	unavailable := fixtureAuthority()
	unavailable.DatabaseAvailable = false
	if _, _, err := BeginRollback(unavailable, "root-a"); !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("unavailable begin rollback = %v", err)
	}
	if _, _, err := BeginRollback(fixtureAuthority(), "missing"); !errors.Is(err, ErrRootNotFound) {
		t.Fatalf("unknown root begin rollback = %v", err)
	}
}
