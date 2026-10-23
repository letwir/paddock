package domain

import (
	"errors"
	"maps"
	"reflect"
	"testing"
)

func TestEffectivePolicyCanaryRootIsolationAndGlobalSecurityEpoch(t *testing.T) {
	v1 := PolicyBinding{Digest: digestOf('a')}
	v2 := PolicyBinding{Digest: digestOf('b')}
	initial := AuthorityState{
		Scope: "scope-fixture", ScopeActivationEpoch: 40, SecurityEpoch: 5,
		Mode: ScopeActive, DatabaseAvailable: true,
		Roots: map[RootID]RootAuthority{
			"root-a": {Policy: v1, AuthorizationEpoch: 1},
			"root-b": {Policy: v1, AuthorizationEpoch: 1},
		},
	}
	before := initial
	before.Roots = maps.Clone(initial.Roots)
	rootAGrant := Grant{Root: "root-a", Policy: v1, AuthorizationEpoch: 1, SecurityEpoch: 5}
	staleRootBGrant := Grant{Root: "root-b", Policy: v1, AuthorizationEpoch: 1, SecurityEpoch: 5}
	for _, grant := range []Grant{rootAGrant, staleRootBGrant} {
		if err := Authorize(initial, grant); err != nil {
			t.Fatalf("Authorize initial %s grant: %v", grant.Root, err)
		}
	}

	canary, _, err := StartCanary(initial, "rollout-epoch-isolation", "root-b", v2.Digest)
	if err != nil {
		t.Fatalf("StartCanary: %v", err)
	}
	wantCanary := before
	wantCanary.ScopeActivationEpoch = 41
	wantCanary.Roots = map[RootID]RootAuthority{
		"root-a": {Policy: v1, AuthorizationEpoch: 1},
		"root-b": {Policy: v2, AuthorizationEpoch: 2},
	}
	if !reflect.DeepEqual(canary, wantCanary) {
		t.Fatalf("Canary authority = %+v, want %+v", canary, wantCanary)
	}
	rootBGrant := Grant{Root: "root-b", Policy: v2, AuthorizationEpoch: 2, SecurityEpoch: 5}
	currentGrants := []Grant{rootAGrant, rootBGrant}
	for _, grant := range currentGrants {
		policy, err := EffectivePolicy(canary, grant.Root)
		if err != nil {
			t.Fatalf("EffectivePolicy Canary %s: %v", grant.Root, err)
		}
		if want := wantCanary.Roots[grant.Root]; policy != want {
			t.Fatalf("EffectivePolicy Canary %s = %+v, want %+v", grant.Root, policy, want)
		}
		if err := Authorize(canary, grant); err != nil {
			t.Fatalf("Authorize current Canary %s grant: %v", grant.Root, err)
		}
	}
	if err := Authorize(canary, staleRootBGrant); !errors.Is(err, ErrStaleGrant) {
		t.Fatalf("Authorize stale Root B v1 grant = %v, want ErrStaleGrant", err)
	}

	// Change only the global Security Epoch: ACTIVE mode and both Root-local
	// authorities stay current, so rejection cannot come from a safety-mode gate.
	revoked := canary
	revoked.SecurityEpoch = 6
	if revoked.Mode != ScopeActive {
		t.Fatalf("Security Epoch change left Scope mode %s, want ACTIVE", revoked.Mode)
	}
	for _, grant := range currentGrants {
		policy, err := EffectivePolicy(revoked, grant.Root)
		if err != nil {
			t.Fatalf("EffectivePolicy after Security Epoch change %s: %v", grant.Root, err)
		}
		if want := wantCanary.Roots[grant.Root]; policy != want {
			t.Fatalf("Security Epoch change altered %s authority: %+v, want %+v", grant.Root, policy, want)
		}
		if err := Authorize(revoked, grant); !errors.Is(err, ErrStaleGrant) {
			t.Fatalf("Authorize %s after Security Epoch change = %v, want ErrStaleGrant", grant.Root, err)
		}
	}
	if !reflect.DeepEqual(initial, before) {
		t.Fatalf("input authority mutated: got %+v, want %+v", initial, before)
	}
	if !reflect.DeepEqual(canary, wantCanary) {
		t.Fatalf("Canary authority mutated: got %+v, want %+v", canary, wantCanary)
	}
}
