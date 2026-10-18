package application

import (
	"context"
	"errors"
	"github.com/letwir/paddock/internal/governance/domain"
	"testing"
)

type checkpointStoreFunc func(context.Context, domain.CheckpointRequest, []byte, int64) (domain.Checkpoint, error)

func (f checkpointStoreFunc) StoreCheckpoint(c context.Context, r domain.CheckpointRequest, b []byte, n int64) (domain.Checkpoint, error) {
	return f(c, r, b, n)
}
func (f checkpointStoreFunc) RestoreCheckpoint(context.Context, string) (domain.Checkpoint, error) {
	return domain.Checkpoint{}, errors.New("not implemented")
}
func testCheckpointRequest() domain.CheckpointRequest {
	return domain.CheckpointRequest{OperationID: "op", Payload: []byte("x"), Manifest: domain.CheckpointManifest{SchemaVersion: "paddock.checkpoint/1", RootID: "r", WorkOrderID: "w", AttemptID: "a", LeaseEpoch: 1, DefinitionDigest: domain.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), PolicyDigest: domain.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), PayloadSHA256: "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", PayloadSize: 1}}
}
func TestCheckpointServiceSubmitsAndVerifies(t *testing.T) {
	r := testCheckpointRequest()
	s := CheckpointService{Policy: domain.CheckpointPolicy{MaxBytesPerCheckpoint: 4096, MaxTotalCheckpointBytes: 8192}, Store: checkpointStoreFunc(func(_ context.Context, r domain.CheckpointRequest, b []byte, n int64) (domain.Checkpoint, error) {
		return domain.Checkpoint{ID: r.OperationID, Manifest: r.Manifest, ManifestBytes: b, Status: domain.CheckpointQuarantined, StoredBytes: n}, nil
	})}
	got, e := s.Submit(context.Background(), r)
	if e != nil || got.Status != domain.CheckpointQuarantined {
		t.Fatalf("got %+v, %v", got, e)
	}
}
func TestCheckpointServiceRejectsBadResultAndStoreError(t *testing.T) {
	r := testCheckpointRequest()
	s := CheckpointService{Policy: domain.CheckpointPolicy{MaxBytesPerCheckpoint: 4096, MaxTotalCheckpointBytes: 8192}, Store: checkpointStoreFunc(func(context.Context, domain.CheckpointRequest, []byte, int64) (domain.Checkpoint, error) {
		return domain.Checkpoint{ID: "wrong"}, nil
	})}
	if _, e := s.Submit(context.Background(), r); !errors.Is(e, ErrCheckpointResult) {
		t.Fatalf("got %v", e)
	}
	s.Store = checkpointStoreFunc(func(context.Context, domain.CheckpointRequest, []byte, int64) (domain.Checkpoint, error) {
		return domain.Checkpoint{}, errors.New("rollback")
	})
	if _, e := s.Submit(context.Background(), r); e == nil {
		t.Fatal("store error hidden")
	}
}
