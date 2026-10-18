package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

func sampleCheckpoint() (CheckpointRequest, CheckpointPolicy) {
	p := []byte("payload")
	h := sha256.Sum256(p)
	return CheckpointRequest{OperationID: "op-1", Payload: p, Manifest: CheckpointManifest{SchemaVersion: "paddock.checkpoint/1", RootID: "root", WorkOrderID: "work", AttemptID: "attempt", LeaseEpoch: 1, DefinitionDigest: Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), PolicyDigest: Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), PayloadSHA256: hex.EncodeToString(h[:]), PayloadSize: int64(len(p))}}, CheckpointPolicy{MaxBytesPerCheckpoint: 4096, MaxTotalCheckpointBytes: 8192}
}
func TestCheckpointRejectsFalseHashAndUnsafeCaps(t *testing.T) {
	r, p := sampleCheckpoint()
	r.Manifest.PayloadSHA256 = strings.Repeat("0", 64)
	if _, _, err := ValidateCheckpointRequest(r, p); err == nil {
		t.Fatal("false payload hash accepted")
	}
	r, p = sampleCheckpoint()
	p.MaxTotalCheckpointBytes = int64(len(r.Payload))
	if _, _, err := ValidateCheckpointRequest(r, p); err == nil {
		t.Fatal("manifest bytes omitted from total cap")
	}
	p.MaxTotalCheckpointBytes = math.MaxInt64
	if _, _, err := ValidateCheckpointRequest(r, p); err != nil {
		t.Fatalf("large finite total cap rejected: %v", err)
	}
}
func TestCheckpointManifestCanonicalAndExactBytes(t *testing.T) {
	r, p := sampleCheckpoint()
	b, n, e := ValidateCheckpointRequest(r, p)
	if e != nil {
		t.Fatal(e)
	}
	if n != int64(len(b)+len(r.Payload)) {
		t.Fatal("wrong byte accounting")
	}
	r.Payload[0] = 'P'
	if _, _, e = ValidateCheckpointRequest(r, p); e == nil {
		t.Fatal("mutation accepted")
	}
}
func TestCheckpointCapsAndPolicy(t *testing.T) {
	r, p := sampleCheckpoint()
	p.MaxBytesPerCheckpoint = 2
	if _, _, e := ValidateCheckpointRequest(r, p); e == nil {
		t.Fatal("oversize accepted")
	}
	p = CheckpointPolicy{}
	if _, _, e := ValidateCheckpointRequest(r, p); e == nil {
		t.Fatal("unlimited/missing policy accepted")
	}
}
func TestCheckpointStatusIsOnlyL2OrQuarantine(t *testing.T) {
	if CheckpointL2 == CheckpointQuarantined {
		t.Fatal("statuses overlap")
	}
}
