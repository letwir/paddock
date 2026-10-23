package domain

import (
	"crypto/ed25519"
	"crypto/rand"
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
		// The injected verifier represents a revoked LKG signature as invalid.
		"revoked_signature": {Status: LKGInvalid, Digest: validLKG()},
		"malformed":         {Status: LKGUsable, Digest: Digest("bad")},
		"unknown":           {Status: LKGStatus("UNKNOWN"), Digest: validLKG()}} {
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
			for id := range stopped.Roots {
				if _, err := EffectivePolicy(stopped, id); !errors.Is(err, ErrSafeStopped) {
					t.Fatalf("Safe Baseline did not deny root %q: %v", id, err)
				}
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

func TestSafetyQuorumStopAdvancesSecurityEpochAndDeniesOldGrant(t *testing.T) {
	initial := fixtureAuthority()
	// Inject an exact-three-key PoC quorum: the production package neither
	// creates nor provisions signer keys.
	signers := make([]SafetySigner, 3)
	privateKeys := make([]ed25519.PrivateKey, 3)
	for i := range signers {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = SafetySigner{ID: string(rune('a' + i)), PublicKey: publicKey}
		privateKeys[i] = privateKey
	}
	quorum, err := NewSafetyQuorum(signers)
	if err != nil {
		t.Fatal(err)
	}
	const commandID = "stop-command"
	message, err := SafetyApprovalMessage(SafetyActionStop, initial.Scope, initial.SecurityEpoch, commandID, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	signatures := []SafetySignature{
		{SignerID: signers[0].ID, Signature: ed25519.Sign(privateKeys[0], message)},
		{SignerID: signers[1].ID, Signature: ed25519.Sign(privateKeys[1], message)},
	}
	result, err := quorum.Stop(initial, initial.Scope, initial.SecurityEpoch, commandID, "nonce-1", signatures)
	if err != nil {
		t.Fatal(err)
	}
	stopped := result.State
	if stopped.SecurityEpoch != 8 || stopped.ScopeActivationEpoch != 40 || stopped.Roots["root-a"].AuthorizationEpoch != 10 {
		t.Fatalf("emergency stop changed wrong generations: %+v", stopped)
	}
	if stopped.Mode != ScopeSafeStop {
		t.Fatalf("stop mode = %s, want %s", stopped.Mode, ScopeSafeStop)
	}
	if err := Authorize(stopped, Grant{Root: "root-a", Policy: validPolicy(), AuthorizationEpoch: 10, SecurityEpoch: 7}); !errors.Is(err, ErrSafeStopped) {
		t.Fatalf("emergency stop did not deny: %v", err)
	}
	if initial.Mode != ScopeActive || initial.SecurityEpoch != 7 {
		t.Fatalf("input snapshot mutated: %+v", initial)
	}
	if initial.Roots["root-a"].AuthorizationEpoch != 10 || initial.Roots["root-a"].Policy != validPolicy() {
		t.Fatalf("input root snapshot mutated: %+v", initial.Roots["root-a"])
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
