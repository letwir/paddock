package domain

import (
	"errors"
	"reflect"
	"testing"
)

const capabilityTrustTestWorkerID WorkerID = "worker_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestWorkerCapabilityTrustProfileStoresTiersPerCapability(t *testing.T) {
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, []CapabilityTrustEntry{
		{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
		{Capability: "disk.read", Tier: CapabilityTrustQ2},
		{Capability: "network.ping", Tier: CapabilityTrustQ3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.WorkerID() != capabilityTrustTestWorkerID {
		t.Fatalf("WorkerID = %q, want %q", profile.WorkerID(), capabilityTrustTestWorkerID)
	}
	for capability, want := range map[string]CapabilityTrustTier{
		"cpu.probe":    CapabilityTrustQ1,
		"disk.read":    CapabilityTrustQ2,
		"network.ping": CapabilityTrustQ3,
		"unknown.cap":  CapabilityTrustQ0,
	} {
		got, err := profile.Tier(capability)
		if err != nil || got != want {
			t.Errorf("Tier(%q) = (%q, %v), want (%q, nil)", capability, got, err, want)
		}
	}
}

func TestWorkerCapabilityTrustProfileUpdatesOnlyTargetCapability(t *testing.T) {
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, []CapabilityTrustEntry{
		{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
		{Capability: "disk.read", Tier: CapabilityTrustQ2},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := profile.WithTier("cpu.probe", CapabilityTrustQ3)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		profile WorkerCapabilityTrustProfile
		cap     string
		want    CapabilityTrustTier
	}{
		{name: "original target unchanged", profile: profile, cap: "cpu.probe", want: CapabilityTrustQ1},
		{name: "updated target", profile: updated, cap: "cpu.probe", want: CapabilityTrustQ3},
		{name: "other capability unchanged", profile: updated, cap: "disk.read", want: CapabilityTrustQ2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.profile.Tier(tc.cap)
			if err != nil || got != tc.want {
				t.Fatalf("Tier(%q) = (%q, %v), want %q", tc.cap, got, err, tc.want)
			}
		})
	}

	reset, err := updated.WithTier("cpu.probe", CapabilityTrustQ0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reset.Tier("cpu.probe"); err != nil || got != CapabilityTrustQ0 {
		t.Fatalf("reset Tier = (%q, %v), want Q0", got, err)
	}
	if _, exists := reset.tiers["cpu.probe"]; exists {
		t.Fatal("Q0 should use the canonical absent-entry representation")
	}
}

func TestConnectivityInterruptionPreservesEveryCapabilityTier(t *testing.T) {
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, []CapabilityTrustEntry{
		{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
		{Capability: "network.ping", Tier: CapabilityTrustQ3},
	})
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := profile.OnConnectivityInterruption("network.ping")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profile, interrupted) {
		t.Fatalf("connectivity interruption changed Trust profile: before=%#v after=%#v", profile, interrupted)
	}
	if got, err := interrupted.Tier("network.ping"); err != nil || got != CapabilityTrustQ3 {
		t.Fatalf("interrupted capability tier = (%q, %v), want Q3", got, err)
	}
	if got, err := interrupted.Tier("cpu.probe"); err != nil || got != CapabilityTrustQ1 {
		t.Fatalf("unrelated capability tier = (%q, %v), want Q1", got, err)
	}
}

func TestEmptyWorkerCapabilityTrustProfileDefaultsToQ0(t *testing.T) {
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"cpu.probe", "network.ping"} {
		if got, err := profile.Tier(capability); err != nil || got != CapabilityTrustQ0 {
			t.Fatalf("empty profile Tier(%q) = (%q, %v), want Q0", capability, got, err)
		}
	}
	if _, err := (WorkerCapabilityTrustProfile{}).Tier("cpu.probe"); !errors.Is(err, ErrWorkerCapabilityTrust) {
		t.Fatalf("zero-value profile error = %v, want ErrWorkerCapabilityTrust", err)
	}
}

func TestWorkerCapabilityTrustProfileRejectsMalformedIdentityEntriesAndUpdates(t *testing.T) {
	validWorker := capabilityTrustTestWorkerID
	for _, tc := range []struct {
		name    string
		worker  WorkerID
		entries []CapabilityTrustEntry
	}{
		{name: "invalid WorkerID", worker: "worker_invalid"},
		{name: "empty capability", worker: validWorker, entries: []CapabilityTrustEntry{{Tier: CapabilityTrustQ1}}},
		{name: "non-trimmed capability", worker: validWorker, entries: []CapabilityTrustEntry{{Capability: " cpu.probe", Tier: CapabilityTrustQ1}}},
		{name: "duplicate capability", worker: validWorker, entries: []CapabilityTrustEntry{
			{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
			{Capability: "cpu.probe", Tier: CapabilityTrustQ2},
		}},
		{name: "unknown tier", worker: validWorker, entries: []CapabilityTrustEntry{{Capability: "cpu.probe", Tier: "Q4"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWorkerCapabilityTrustProfile(tc.worker, tc.entries); !errors.Is(err, ErrWorkerCapabilityTrust) {
				t.Fatalf("constructor error = %v, want ErrWorkerCapabilityTrust", err)
			}
		})
	}

	profile, err := NewWorkerCapabilityTrustProfile(validWorker, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]struct {
		capability string
		tier       CapabilityTrustTier
	}{
		"empty capability": {capability: " ", tier: CapabilityTrustQ1},
		"unknown tier":     {capability: "cpu.probe", tier: "Q4"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := profile.WithTier(change.capability, change.tier); !errors.Is(err, ErrWorkerCapabilityTrust) {
				t.Fatalf("update error = %v, want ErrWorkerCapabilityTrust", err)
			}
		})
	}
	if _, err := profile.OnConnectivityInterruption("\n"); !errors.Is(err, ErrWorkerCapabilityTrust) {
		t.Fatalf("connectivity capability error = %v, want ErrWorkerCapabilityTrust", err)
	}
}

func TestWorkerCapabilityTrustProfileCopiesCallerEntriesAndProfiles(t *testing.T) {
	entries := []CapabilityTrustEntry{{Capability: "cpu.probe", Tier: CapabilityTrustQ2}}
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, entries)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Tier = CapabilityTrustQ0
	if got, err := profile.Tier("cpu.probe"); err != nil || got != CapabilityTrustQ2 {
		t.Fatalf("constructor retained caller alias: got (%q, %v), want Q2", got, err)
	}
	updated, err := profile.WithTier("disk.read", CapabilityTrustQ1)
	if err != nil {
		t.Fatal(err)
	}
	updated.tiers["cpu.probe"] = CapabilityTrustQ0
	if got, err := profile.Tier("cpu.probe"); err != nil || got != CapabilityTrustQ2 {
		t.Fatalf("updated profile aliased original map: got (%q, %v), want Q2", got, err)
	}
}

func TestWorkerCapabilityTrustProfilePreservesExactCapabilityNames(t *testing.T) {
	profile, err := NewWorkerCapabilityTrustProfile(capabilityTrustTestWorkerID, []CapabilityTrustEntry{
		{Capability: "cpu.probe", Tier: CapabilityTrustQ1},
		{Capability: "CPU.probe", Tier: CapabilityTrustQ2},
	})
	if err != nil {
		t.Fatal(err)
	}
	for capability, want := range map[string]CapabilityTrustTier{
		"cpu.probe": CapabilityTrustQ1,
		"CPU.probe": CapabilityTrustQ2,
	} {
		got, err := profile.Tier(capability)
		if err != nil || got != want {
			t.Fatalf("Tier(%q) = (%q, %v), want %q", capability, got, err, want)
		}
	}
}
