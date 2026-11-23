package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/letwir/paddock/internal/canonical"
)

var (
	ErrInvalidBudgetReservation  = errors.New("invalid offline budget reservation")
	ErrInvalidBudgetReport       = errors.New("invalid offline budget usage report")
	ErrOfflineBudgetExceeded     = errors.New("offline budget exceeded")
	ErrBudgetGrantAlreadySettled = errors.New("offline budget grant already settled")
	ErrBudgetReportTampered      = errors.New("offline budget report digest or signature invalid")
)

// OfflineBudgetPool tracks pre-allocated, spent, and available compute units
// for offline WorkOrders within a Root/Budget boundary.
// PhysicalEnforcementGuaranteed is always false because an untrusted Worker
// running offline cannot be physically prevented from exceeding resources.
type OfflineBudgetPool struct {
	RootID                        RootID
	TotalLimit                    int64
	Reserved                      int64
	Spent                         int64
	PhysicalEnforcementGuaranteed bool
	Reservations                  map[string]OfflineBudgetReservation
	SettledGrants                 map[string]OfflineBudgetSettlement
}

type OfflineBudgetReservation struct {
	GrantID               string
	RootID                RootID
	WorkOrderID           WorkOrderID
	AttemptID             string
	LeaseEpoch            Epoch
	WorkerID              string
	ReservedUnits         int64
	TrustedMeterPublicKey ed25519.PublicKey
}

type OfflineUsageReport struct {
	GrantID      string      `json:"grant_id"`
	RootID       RootID      `json:"root_id"`
	WorkOrderID  WorkOrderID `json:"work_order_id"`
	AttemptID    string      `json:"attempt_id"`
	LeaseEpoch   Epoch       `json:"lease_epoch"`
	WorkerID     string      `json:"worker_id"`
	UsedUnits    int64       `json:"used_units"`
	ReportDigest Digest      `json:"report_digest"`
	SignatureHex string      `json:"signature_hex"`
}

type OfflineBudgetSettlement struct {
	GrantID                       string
	ReservedUnits                 int64
	ReportedUsedUnits             int64
	RefundedUnits                 int64
	AvailableAfter                int64
	PhysicalEnforcementGuaranteed bool
}

// OfflineUsageReportCanonicalBytes serializes all usage report bindings plus
// UsedUnits under canonical JCS for digest and Ed25519 signature verification.
func OfflineUsageReportCanonicalBytes(report OfflineUsageReport) ([]byte, error) {
	payload := struct {
		SchemaVersion string      `json:"schema_version"`
		GrantID       string      `json:"grant_id"`
		RootID        RootID      `json:"root_id"`
		WorkOrderID   WorkOrderID `json:"work_order_id"`
		AttemptID     string      `json:"attempt_id"`
		LeaseEpoch    Epoch       `json:"lease_epoch"`
		WorkerID      string      `json:"worker_id"`
		UsedUnits     int64       `json:"used_units"`
	}{
		SchemaVersion: "paddock.offline-usage-report/1",
		GrantID:       report.GrantID,
		RootID:        report.RootID,
		WorkOrderID:   report.WorkOrderID,
		AttemptID:     report.AttemptID,
		LeaseEpoch:    report.LeaseEpoch,
		WorkerID:      report.WorkerID,
		UsedUnits:     report.UsedUnits,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return canonical.NewJCSCodec().CanonicalizeJSON(raw)
}

// ComputeOfflineUsageReportDigest computes the domain-separated SHA-256 over
// the canonical usage report including UsedUnits.
func ComputeOfflineUsageReportDigest(report OfflineUsageReport) (Digest, error) {
	b, err := OfflineUsageReportCanonicalBytes(report)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return Digest(hex.EncodeToString(sum[:])), nil
}

// SignOfflineUsageReport signs and populates ReportDigest and SignatureHex.
func SignOfflineUsageReport(report OfflineUsageReport, meterPriv ed25519.PrivateKey) (OfflineUsageReport, error) {
	if len(meterPriv) != ed25519.PrivateKeySize {
		return OfflineUsageReport{}, fmt.Errorf("%w: invalid meter signing key", ErrBudgetReportTampered)
	}
	d, err := ComputeOfflineUsageReportDigest(report)
	if err != nil {
		return OfflineUsageReport{}, err
	}
	b, err := OfflineUsageReportCanonicalBytes(report)
	if err != nil {
		return OfflineUsageReport{}, err
	}
	report.ReportDigest = d
	report.SignatureHex = hex.EncodeToString(ed25519.Sign(meterPriv, b))
	return report, nil
}

func NewOfflineBudgetPool(rootID RootID, totalLimit int64) (*OfflineBudgetPool, error) {
	if rootID.Validate() != nil || totalLimit <= 0 {
		return nil, fmt.Errorf("%w: valid root_id and positive total_limit required", ErrInvalidBudgetReservation)
	}
	return &OfflineBudgetPool{
		RootID:                        rootID,
		TotalLimit:                    totalLimit,
		PhysicalEnforcementGuaranteed: false,
		Reservations:                  make(map[string]OfflineBudgetReservation),
		SettledGrants:                 make(map[string]OfflineBudgetSettlement),
	}, nil
}

func (p *OfflineBudgetPool) Available() int64 {
	if p == nil {
		return 0
	}
	return p.TotalLimit - p.Reserved - p.Spent
}

// ReserveOfflineBudget pre-allocates budget units before disconnecting an offline
// Worker. Fail-closed on duplicate GrantID, mismatched RootID, missing meter
// verification key, invalid fields, arithmetic overflow, or insufficient budget.
func (p *OfflineBudgetPool) ReserveOfflineBudget(res OfflineBudgetReservation) error {
	if p == nil {
		return fmt.Errorf("%w: nil pool", ErrInvalidBudgetReservation)
	}
	p.PhysicalEnforcementGuaranteed = false
	if p.Reservations == nil {
		p.Reservations = make(map[string]OfflineBudgetReservation)
	}
	if p.SettledGrants == nil {
		p.SettledGrants = make(map[string]OfflineBudgetSettlement)
	}
	if validateID(res.GrantID) != nil ||
		res.RootID != p.RootID ||
		res.WorkOrderID.Validate() != nil ||
		validateID(res.AttemptID) != nil ||
		res.LeaseEpoch == 0 ||
		validateID(res.WorkerID) != nil ||
		res.ReservedUnits <= 0 ||
		len(res.TrustedMeterPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: incomplete or invalid reservation binding", ErrInvalidBudgetReservation)
	}
	if _, exists := p.Reservations[res.GrantID]; exists {
		return fmt.Errorf("%w: duplicate active grant %q", ErrInvalidBudgetReservation, res.GrantID)
	}
	if _, settled := p.SettledGrants[res.GrantID]; settled {
		return fmt.Errorf("%w: grant %q already settled", ErrBudgetGrantAlreadySettled, res.GrantID)
	}
	if p.Reserved > math.MaxInt64-res.ReservedUnits {
		return fmt.Errorf("%w: reserved units overflow", ErrOfflineBudgetExceeded)
	}
	if res.ReservedUnits > p.Available() {
		return fmt.Errorf("%w: requested %d exceeds available %d", ErrOfflineBudgetExceeded, res.ReservedUnits, p.Available())
	}
	keyCopy := append(ed25519.PublicKey(nil), res.TrustedMeterPublicKey...)
	res.TrustedMeterPublicKey = keyCopy
	p.Reserved += res.ReservedUnits
	p.Reservations[res.GrantID] = res
	return nil
}

// ReconcileOfflineBudget verifies a cryptographically authenticated offline usage
// report (recomputing canonical digest over UsedUnits + verifying Ed25519 signature)
// against the active pre-reservation, records spent units, and refunds unused budget.
// Does NOT claim physical enforcement; tampered/dishonest/overrun reports fail closed.
func (p *OfflineBudgetPool) ReconcileOfflineBudget(report OfflineUsageReport) (OfflineBudgetSettlement, error) {
	if p == nil {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: nil pool", ErrInvalidBudgetReport)
	}
	p.PhysicalEnforcementGuaranteed = false
	if _, settled := p.SettledGrants[report.GrantID]; settled {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: grant %q", ErrBudgetGrantAlreadySettled, report.GrantID)
	}
	res, ok := p.Reservations[report.GrantID]
	if !ok {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: unknown reservation for grant %q", ErrInvalidBudgetReport, report.GrantID)
	}
	if report.RootID != res.RootID ||
		report.WorkOrderID != res.WorkOrderID ||
		report.AttemptID != res.AttemptID ||
		report.LeaseEpoch != res.LeaseEpoch ||
		report.WorkerID != res.WorkerID {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: report binding mismatch", ErrInvalidBudgetReport)
	}
	if report.UsedUnits < 0 {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: negative reported usage %d", ErrInvalidBudgetReport, report.UsedUnits)
	}
	expectedDigest, err := ComputeOfflineUsageReportDigest(report)
	if err != nil {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: canonical digest computation failed: %v", ErrBudgetReportTampered, err)
	}
	if report.ReportDigest != expectedDigest {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: report digest mismatch with used_units/bindings", ErrBudgetReportTampered)
	}
	canonicalBytes, err := OfflineUsageReportCanonicalBytes(report)
	if err != nil {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: %v", ErrBudgetReportTampered, err)
	}
	sig, err := hex.DecodeString(report.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(res.TrustedMeterPublicKey, canonicalBytes, sig) {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: meter signature verification failed", ErrBudgetReportTampered)
	}
	if report.UsedUnits > res.ReservedUnits {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: reported %d exceeds pre-reserved %d (physical enforcement not guaranteed)", ErrOfflineBudgetExceeded, report.UsedUnits, res.ReservedUnits)
	}
	if p.Spent > math.MaxInt64-report.UsedUnits {
		return OfflineBudgetSettlement{}, fmt.Errorf("%w: spent overflow", ErrOfflineBudgetExceeded)
	}

	refund := res.ReservedUnits - report.UsedUnits
	p.Reserved -= res.ReservedUnits
	p.Spent += report.UsedUnits
	delete(p.Reservations, report.GrantID)

	settlement := OfflineBudgetSettlement{
		GrantID:                       report.GrantID,
		ReservedUnits:                 res.ReservedUnits,
		ReportedUsedUnits:             report.UsedUnits,
		RefundedUnits:                 refund,
		AvailableAfter:                p.Available(),
		PhysicalEnforcementGuaranteed: false,
	}
	p.SettledGrants[report.GrantID] = settlement
	return settlement, nil
}
