package application

import (
	"github.com/letwir/paddock/internal/governance/domain"
	"testing"
	"time"
)

func TestSpawnAdmissionFailClosed(t *testing.T) {
	now := time.Now()
	p := domain.SpawnPolicy{MaxSpawnDepth: 2, MaxTotalDescendants: 5, MaxLiveChildren: 2, MaxAttemptsPerWorkOrder: 3, RootDeadline: now.Add(time.Hour), MaxRepeatFingerprint: 1}
	if (SpawnAdmission{&p, now}).Admit(1, "fp", SpawnUsage{}) != nil {
		t.Fatal("valid spawn denied")
	}
	if (SpawnAdmission{nil, now}).Admit(1, "fp", SpawnUsage{}) == nil {
		t.Fatal("missing policy admitted")
	}
	if (SpawnAdmission{&p, now}).Admit(1, "fp", SpawnUsage{RepeatFingerprint: 1}) == nil {
		t.Fatal("repeat cap ignored")
	}
}
