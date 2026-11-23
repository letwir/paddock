package application

import (
	"fmt"
	"sort"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type PresentationSurface string

const (
	SurfaceCLI PresentationSurface = "CLI"
	SurfaceGUI PresentationSurface = "GUI"
	SurfaceAPI PresentationSurface = "API"
)

type RootEffectiveView struct {
	RootID             domain.RootID
	AuthorizationEpoch domain.Epoch
	EffectivePolicy    domain.PolicyBinding
	Authorized         bool
}

// StateReadModel is the single read-only projection shared across GUI, CUI,
// and API presenters. Presentation formatting never alters authority or transitions.
type StateReadModel struct {
	Surface               PresentationSurface
	ScopeID               domain.ScopeID
	ScopeMode             domain.ScopeMode
	ScopeActivationEpoch  domain.Epoch
	SecurityEpoch         domain.Epoch
	LiveRolloutID         *domain.RolloutID
	RolloutState          *domain.RolloutState
	Roots                 []RootEffectiveView
	AllowedTransitions    []string
	PresentationFormatted string
}

// ProjectStateReadModel builds a surface-invariant governance projection from
// current AuthorityState and optional RolloutSnapshot.
func ProjectStateReadModel(state domain.AuthorityState, rollout *port.RolloutSnapshot, surface PresentationSurface) (StateReadModel, error) {
	if err := state.Validate(); err != nil {
		return StateReadModel{}, err
	}
	rootIDs := make([]domain.RootID, 0, len(state.Roots))
	for id := range state.Roots {
		rootIDs = append(rootIDs, id)
	}
	sort.Slice(rootIDs, func(i, j int) bool { return rootIDs[i] < rootIDs[j] })

	views := make([]RootEffectiveView, 0, len(rootIDs))
	for _, id := range rootIDs {
		r := state.Roots[id]
		_, authErr := domain.EffectivePolicy(state, id)
		views = append(views, RootEffectiveView{
			RootID:             id,
			AuthorizationEpoch: r.AuthorizationEpoch,
			EffectivePolicy:    r.Policy,
			Authorized:         authErr == nil,
		})
	}

	var transitions []string
	var rolloutState *domain.RolloutState
	var liveRolloutID *domain.RolloutID
	if rollout != nil {
		id := rollout.ID
		liveRolloutID = &id
	}
	if state.DatabaseAvailable && state.Mode == domain.ScopeActive {
		if rollout == nil {
			transitions = append(transitions, "START_CANARY")
		} else {
			rs := rollout.State
			rolloutState = &rs
			switch rollout.State {
			case domain.RolloutCanary:
				transitions = append(transitions, "PROMOTE", "ROLLBACK")
			case domain.RolloutMonitoring:
				transitions = append(transitions, "COMPLETE", "ROLLBACK")
			}
		}
		transitions = append(transitions, "EMERGENCY_STOP")
	} else if state.DatabaseAvailable && state.Mode == domain.ScopeFrozen && rollout != nil && rollout.State == domain.RolloutRollingBack {
		rs := rollout.State
		rolloutState = &rs
		transitions = append(transitions, "FINALIZE_ROLLBACK", "EMERGENCY_STOP")
	} else if state.DatabaseAvailable && state.Mode == domain.ScopeSafeStop {
		transitions = append(transitions, "SAFETY_RELEASE")
	}
	sort.Strings(transitions)

	formatted := fmt.Sprintf("[%s] scope=%s mode=%s epoch=%d sec=%d",
		surface, state.Scope, state.Mode, state.ScopeActivationEpoch, state.SecurityEpoch)

	return StateReadModel{
		Surface:               surface,
		ScopeID:               state.Scope,
		ScopeMode:             state.Mode,
		ScopeActivationEpoch:  state.ScopeActivationEpoch,
		SecurityEpoch:         state.SecurityEpoch,
		LiveRolloutID:         liveRolloutID,
		RolloutState:          rolloutState,
		Roots:                 views,
		AllowedTransitions:    transitions,
		PresentationFormatted: formatted,
	}, nil
}
