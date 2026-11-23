package domain

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrAuditLineageMismatch = errors.New("audit lineage mismatch")

// AuditLineageRecord binds long-term verification provenance to exact Git,
// schema, evidence, policy, and receipt digests.
type AuditLineageRecord struct {
	IssueID            string
	DecisionIDs        []string
	GitRevision        string
	SchemaVersion      string
	EvidenceSnapshotID GraphSnapshotID
	PolicyDigest       Digest
	KernelDigest       Digest
	ReceiptID          string
	ReceiptSHA256      Digest
	RecordedAt         time.Time
}

func (r AuditLineageRecord) Validate() error {
	if validateID(r.IssueID) != nil ||
		validateID(r.GitRevision) != nil ||
		validateID(r.SchemaVersion) != nil ||
		Digest(r.EvidenceSnapshotID).Validate() != nil ||
		r.PolicyDigest.Validate() != nil ||
		r.KernelDigest.Validate() != nil ||
		validateID(r.ReceiptID) != nil ||
		r.ReceiptSHA256.Validate() != nil ||
		r.RecordedAt.IsZero() {
		return fmt.Errorf("%w: malformed audit lineage record", ErrAuditLineageMismatch)
	}
	for _, d := range r.DecisionIDs {
		if validateID(d) != nil {
			return fmt.Errorf("%w: invalid decision ID %q", ErrAuditLineageMismatch, d)
		}
	}
	return nil
}

type AuditReconciliationReport struct {
	Matched    bool
	Mismatches []string
	Decisions  []string
}

// ReconcileAuditLineage re-verifies that stored Git revision, schema version,
// evidence snapshot ID, policy digest, kernel digest, and receipt digest match
// expected reference values.
func ReconcileAuditLineage(recorded, expected AuditLineageRecord) (AuditReconciliationReport, error) {
	if err := recorded.Validate(); err != nil {
		return AuditReconciliationReport{}, err
	}
	if err := expected.Validate(); err != nil {
		return AuditReconciliationReport{}, err
	}

	var mismatches []string
	if recorded.IssueID != expected.IssueID {
		mismatches = append(mismatches, "ISSUE_ID_MISMATCH")
	}
	if recorded.GitRevision != expected.GitRevision {
		mismatches = append(mismatches, "GIT_REVISION_MISMATCH")
	}
	if recorded.SchemaVersion != expected.SchemaVersion {
		mismatches = append(mismatches, "SCHEMA_VERSION_MISMATCH")
	}
	if recorded.EvidenceSnapshotID != expected.EvidenceSnapshotID {
		mismatches = append(mismatches, "EVIDENCE_SNAPSHOT_MISMATCH")
	}
	if recorded.PolicyDigest != expected.PolicyDigest {
		mismatches = append(mismatches, "POLICY_DIGEST_MISMATCH")
	}
	if recorded.KernelDigest != expected.KernelDigest {
		mismatches = append(mismatches, "KERNEL_DIGEST_MISMATCH")
	}
	if recorded.ReceiptSHA256 != expected.ReceiptSHA256 {
		mismatches = append(mismatches, "RECEIPT_SHA256_MISMATCH")
	}
	sort.Strings(mismatches)

	decisions := append([]string(nil), recorded.DecisionIDs...)
	sort.Strings(decisions)

	if len(mismatches) > 0 {
		return AuditReconciliationReport{
			Matched:    false,
			Mismatches: mismatches,
			Decisions:  decisions,
		}, fmt.Errorf("%w: %v", ErrAuditLineageMismatch, mismatches)
	}
	return AuditReconciliationReport{
		Matched:   true,
		Decisions: decisions,
	}, nil
}
