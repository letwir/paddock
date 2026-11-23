package domain

import (
	"errors"
	"testing"
	"time"
)

func TestAuditLineageReconciliation(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	base := AuditLineageRecord{
		IssueID:            "PDK-M14-S03",
		DecisionIDs:        []string{"D-015", "D-016"},
		GitRevision:        "df40050e93ef671afe2e98b0b0360cd65bb00caf",
		SchemaVersion:      "paddock.receipt/1",
		EvidenceSnapshotID: GraphSnapshotID(digestOf('a')),
		PolicyDigest:       digestOf('b'),
		KernelDigest:       digestOf('c'),
		ReceiptID:          "rcpt-1",
		ReceiptSHA256:      digestOf('d'),
		RecordedAt:         now,
	}

	report, err := ReconcileAuditLineage(base, base)
	if err != nil || !report.Matched || len(report.Mismatches) != 0 {
		t.Fatalf("matching lineage rejected: %+v err=%v", report, err)
	}

	cases := []struct {
		name   string
		mutate func(*AuditLineageRecord)
		code   string
	}{
		{"git revision", func(r *AuditLineageRecord) { r.GitRevision = "0000000" }, "GIT_REVISION_MISMATCH"},
		{"schema version", func(r *AuditLineageRecord) { r.SchemaVersion = "paddock.receipt/2" }, "SCHEMA_VERSION_MISMATCH"},
		{"evidence snapshot", func(r *AuditLineageRecord) { r.EvidenceSnapshotID = GraphSnapshotID(digestOf('e')) }, "EVIDENCE_SNAPSHOT_MISMATCH"},
		{"policy digest", func(r *AuditLineageRecord) { r.PolicyDigest = digestOf('f') }, "POLICY_DIGEST_MISMATCH"},
		{"kernel digest", func(r *AuditLineageRecord) { r.KernelDigest = digestOf('2') }, "KERNEL_DIGEST_MISMATCH"},
		{"receipt sha256", func(r *AuditLineageRecord) { r.ReceiptSHA256 = digestOf('1') }, "RECEIPT_SHA256_MISMATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base
			tc.mutate(&mut)
			rep, err := ReconcileAuditLineage(mut, base)
			if !errors.Is(err, ErrAuditLineageMismatch) || rep.Matched || len(rep.Mismatches) != 1 || rep.Mismatches[0] != tc.code {
				t.Fatalf("mismatch %s unexpected: %+v err=%v", tc.name, rep, err)
			}
		})
	}
}
