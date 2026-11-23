package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestOfflineBudgetReserveReconcileAndRefund(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	pool, err := NewOfflineBudgetPool("root_alpha", 1000)
	if err != nil {
		t.Fatalf("NewOfflineBudgetPool failed: %v", err)
	}
	if pool.PhysicalEnforcementGuaranteed {
		t.Fatal("PhysicalEnforcementGuaranteed must always be false")
	}

	res := OfflineBudgetReservation{
		GrantID:               "grant_01",
		RootID:                "root_alpha",
		WorkOrderID:           "wo_01",
		AttemptID:             "att_01",
		LeaseEpoch:            12,
		WorkerID:              "worker_01",
		ReservedUnits:         400,
		TrustedMeterPublicKey: pub,
	}
	if err := pool.ReserveOfflineBudget(res); err != nil {
		t.Fatalf("ReserveOfflineBudget failed: %v", err)
	}
	if pool.Available() != 600 || pool.Reserved != 400 || pool.Spent != 0 {
		t.Fatalf("unexpected pool state after reservation: avail=%d res=%d spent=%d", pool.Available(), pool.Reserved, pool.Spent)
	}

	// Second reservation within remaining 600 succeeds; 601 fails.
	if err := pool.ReserveOfflineBudget(OfflineBudgetReservation{
		GrantID:               "grant_02",
		RootID:                "root_alpha",
		WorkOrderID:           "wo_02",
		AttemptID:             "att_02",
		LeaseEpoch:            13,
		WorkerID:              "worker_02",
		ReservedUnits:         601,
		TrustedMeterPublicKey: pub,
	}); !errors.Is(err, ErrOfflineBudgetExceeded) {
		t.Fatalf("expected ErrOfflineBudgetExceeded, got %v", err)
	}

	signedReport, err := SignOfflineUsageReport(OfflineUsageReport{
		GrantID:     "grant_01",
		RootID:      "root_alpha",
		WorkOrderID: "wo_01",
		AttemptID:   "att_01",
		LeaseEpoch:  12,
		WorkerID:    "worker_01",
		UsedUnits:   150,
	}, priv)
	if err != nil {
		t.Fatalf("SignOfflineUsageReport failed: %v", err)
	}

	// Tampering UsedUnits from 150 to 0 while keeping original ReportDigest/signature MUST fail closed!
	tamperedUsed := signedReport
	tamperedUsed.UsedUnits = 0
	if _, err := pool.ReconcileOfflineBudget(tamperedUsed); !errors.Is(err, ErrBudgetReportTampered) {
		t.Fatalf("expected ErrBudgetReportTampered when UsedUnits altered with old digest/sig, got %v", err)
	}

	settlement, err := pool.ReconcileOfflineBudget(signedReport)
	if err != nil {
		t.Fatalf("ReconcileOfflineBudget failed: %v", err)
	}
	if settlement.PhysicalEnforcementGuaranteed {
		t.Fatal("settlement must not claim physical enforcement guarantee")
	}
	if settlement.RefundedUnits != 250 || settlement.AvailableAfter != 850 || pool.Reserved != 0 || pool.Spent != 150 {
		t.Fatalf("unexpected settlement/pool state: %+v pool=%+v", settlement, pool)
	}

	// Duplicate settlement must fail closed.
	if _, err := pool.ReconcileOfflineBudget(signedReport); !errors.Is(err, ErrBudgetGrantAlreadySettled) {
		t.Fatalf("expected ErrBudgetGrantAlreadySettled, got %v", err)
	}
}

func TestOfflineBudgetRejectsDishonestAndTamperedReports(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen2 failed: %v", err)
	}
	pool, err := NewOfflineBudgetPool("root_alpha", 500)
	if err != nil {
		t.Fatalf("NewOfflineBudgetPool failed: %v", err)
	}
	if err := pool.ReserveOfflineBudget(OfflineBudgetReservation{
		GrantID:               "grant_dishonest",
		RootID:                "root_alpha",
		WorkOrderID:           "wo_09",
		AttemptID:             "att_09",
		LeaseEpoch:            5,
		WorkerID:              "worker_09",
		ReservedUnits:         200,
		TrustedMeterPublicKey: pub,
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	validSigned, err := SignOfflineUsageReport(OfflineUsageReport{
		GrantID: "grant_dishonest", RootID: "root_alpha", WorkOrderID: "wo_09",
		AttemptID: "att_09", LeaseEpoch: 5, WorkerID: "worker_09", UsedUnits: 50,
	}, priv)
	if err != nil {
		t.Fatalf("sign valid failed: %v", err)
	}
	rogueSigned, err := SignOfflineUsageReport(OfflineUsageReport{
		GrantID: "grant_dishonest", RootID: "root_alpha", WorkOrderID: "wo_09",
		AttemptID: "att_09", LeaseEpoch: 5, WorkerID: "worker_09", UsedUnits: 0,
	}, roguePriv)
	if err != nil {
		t.Fatalf("sign rogue failed: %v", err)
	}
	overrunSigned, err := SignOfflineUsageReport(OfflineUsageReport{
		GrantID: "grant_dishonest", RootID: "root_alpha", WorkOrderID: "wo_09",
		AttemptID: "att_09", LeaseEpoch: 5, WorkerID: "worker_09", UsedUnits: 250,
	}, priv)
	if err != nil {
		t.Fatalf("sign overrun failed: %v", err)
	}

	tamperedDigest := validSigned
	tamperedDigest.ReportDigest = Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	negativeReport := validSigned
	negativeReport.UsedUnits = -10

	spoofWorker := validSigned
	spoofWorker.WorkerID = "worker_other"

	staleEpoch := validSigned
	staleEpoch.LeaseEpoch = 4

	cases := []struct {
		name    string
		report  OfflineUsageReport
		wantErr error
	}{
		{name: "negative usage", report: negativeReport, wantErr: ErrInvalidBudgetReport},
		{name: "worker identity spoof", report: spoofWorker, wantErr: ErrInvalidBudgetReport},
		{name: "stale lease epoch", report: staleEpoch, wantErr: ErrInvalidBudgetReport},
		{name: "tampered digest", report: tamperedDigest, wantErr: ErrBudgetReportTampered},
		{name: "rogue signer signature", report: rogueSigned, wantErr: ErrBudgetReportTampered},
		{name: "overrun exceeds reserved", report: overrunSigned, wantErr: ErrOfflineBudgetExceeded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.ReconcileOfflineBudget(tc.report); !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if pool.Reserved != 200 || pool.Spent != 0 || pool.Available() != 300 {
				t.Fatalf("pool mutated on rejected report: %+v", pool)
			}
		})
	}
}
