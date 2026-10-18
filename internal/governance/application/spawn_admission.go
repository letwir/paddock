package application

import (
	"errors"
	"github.com/letwir/paddock/internal/governance/domain"
	"time"
)

var ErrSpawnDenied = errors.New("spawn admission denied")

type SpawnUsage struct{ Descendants, LiveChildren, AttemptsForWorkOrder, RepeatFingerprint int }
type SpawnAdmission struct {
	Policy *domain.SpawnPolicy
	Now    time.Time
}

func (a SpawnAdmission) Admit(depth int, fingerprint string, u SpawnUsage) error {
	if a.Policy == nil || a.Policy.Validate() != nil || a.Now.IsZero() || fingerprint == "" {
		return ErrSpawnDenied
	}
	p := a.Policy
	if !a.Now.Before(p.RootDeadline) || depth < 0 || depth > p.MaxSpawnDepth || u.Descendants >= p.MaxTotalDescendants || u.LiveChildren >= p.MaxLiveChildren || u.AttemptsForWorkOrder >= p.MaxAttemptsPerWorkOrder || u.RepeatFingerprint >= p.MaxRepeatFingerprint {
		return ErrSpawnDenied
	}
	return nil
}
