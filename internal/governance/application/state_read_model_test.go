package application

import (
	"reflect"
	"strings"
	"testing"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func TestStateReadModelInvariantAcrossCLIGUIAPI(t *testing.T) {
	d := domain.Digest(strings.Repeat("a", 64))
	state := domain.AuthorityState{
		Scope:                "scope-1",
		Mode:                 domain.ScopeActive,
		DatabaseAvailable:    true,
		ScopeActivationEpoch: 41,
		SecurityEpoch:        6,
		Roots: map[domain.RootID]domain.RootAuthority{
			"root-a": {AuthorizationEpoch: 1, Policy: domain.PolicyBinding{Digest: d}},
			"root-b": {AuthorizationEpoch: 2, Policy: domain.PolicyBinding{Digest: domain.Digest(strings.Repeat("b", 64))}},
		},
	}
	rid := domain.RolloutID("rollout-1")
	rollout := &port.RolloutSnapshot{ID: rid, Scope: "scope-1", State: domain.RolloutCanary}

	cli, err := ProjectStateReadModel(state, rollout, SurfaceCLI)
	if err != nil {
		t.Fatal(err)
	}
	gui, err := ProjectStateReadModel(state, rollout, SurfaceGUI)
	if err != nil {
		t.Fatal(err)
	}
	api, err := ProjectStateReadModel(state, rollout, SurfaceAPI)
	if err != nil {
		t.Fatal(err)
	}

	for _, other := range []StateReadModel{gui, api} {
		if other.ScopeMode != cli.ScopeMode ||
			other.ScopeActivationEpoch != cli.ScopeActivationEpoch ||
			other.SecurityEpoch != cli.SecurityEpoch ||
			!reflect.DeepEqual(other.Roots, cli.Roots) ||
			!reflect.DeepEqual(other.AllowedTransitions, cli.AllowedTransitions) {
			t.Fatalf("surface %s altered authorization/transitions: %+v vs %+v", other.Surface, other, cli)
		}
	}
	if cli.PresentationFormatted == gui.PresentationFormatted || gui.PresentationFormatted == api.PresentationFormatted {
		t.Fatal("expected distinct presentation formatting across surfaces")
	}
}
