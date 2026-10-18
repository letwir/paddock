package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/governance/domain"
)

var ErrCheckpointResult = errors.New("invalid checkpoint store result")

// CheckpointStore owns the single transaction containing reserve, insert, and settle.
type CheckpointStore interface {
	StoreCheckpoint(context.Context, domain.CheckpointRequest, []byte, int64) (domain.Checkpoint, error)
	RestoreCheckpoint(context.Context, string) (domain.Checkpoint, error)
}
type CheckpointService struct {
	Store  CheckpointStore
	Policy domain.CheckpointPolicy
}

func (s CheckpointService) RestoreCheckpoint(ctx context.Context, checkpointID string) (domain.Checkpoint, error) {
	if s.Store == nil || ctx == nil || checkpointID == "" {
		return domain.Checkpoint{}, errors.New("invalid checkpoint restore")
	}
	result, err := s.Store.RestoreCheckpoint(ctx, checkpointID)
	if err != nil {
		return domain.Checkpoint{}, err
	}
	if result.ID != checkpointID || result.Status != domain.CheckpointL2 && result.Status != domain.CheckpointQuarantined || result.Status == domain.CheckpointQuarantined && len(result.Payload) != 0 || result.Status == domain.CheckpointL2 && len(result.ManifestBytes) == 0 {
		return domain.Checkpoint{}, fmt.Errorf("%w: unsafe restore result", ErrCheckpointResult)
	}
	return result, nil
}

func (s CheckpointService) Submit(ctx context.Context, req domain.CheckpointRequest) (domain.Checkpoint, error) {
	if s.Store == nil {
		return domain.Checkpoint{}, errors.New("checkpoint store unavailable")
	}
	if ctx == nil {
		return domain.Checkpoint{}, errors.New("nil context")
	}
	manifest, n, err := domain.ValidateCheckpointRequest(req, s.Policy)
	if err != nil {
		return domain.Checkpoint{}, err
	}
	result, err := s.Store.StoreCheckpoint(ctx, req, manifest, n)
	if err != nil {
		return domain.Checkpoint{}, err
	}
	if result.ID != req.OperationID || result.Status != domain.CheckpointL2 && result.Status != domain.CheckpointQuarantined || result.StoredBytes != n || string(result.ManifestBytes) != string(manifest) || result.Manifest != req.Manifest || result.Status == domain.CheckpointL2 && string(result.Payload) != string(req.Payload) || result.Status == domain.CheckpointQuarantined && len(result.Payload) != 0 {
		return domain.Checkpoint{}, fmt.Errorf("%w: returned checkpoint differs from submitted request", ErrCheckpointResult)
	}
	return result, nil
}
