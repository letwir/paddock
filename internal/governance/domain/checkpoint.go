package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/letwir/paddock/internal/canonical"
)

var ErrCheckpointInvalid = errors.New("invalid checkpoint")
var ErrCheckpointDenied = errors.New("checkpoint denied")

type CheckpointStatus string

const (
	CheckpointL2          CheckpointStatus = "L2"
	CheckpointQuarantined CheckpointStatus = "QUARANTINED"
)

// CheckpointManifest is the exact semantic identity envelope persisted with a payload.
type CheckpointManifest struct {
	SchemaVersion    string `json:"schema_version"`
	RootID           string `json:"root_id"`
	WorkOrderID      string `json:"work_order_id"`
	AttemptID        string `json:"attempt_id"`
	LeaseEpoch       uint64 `json:"lease_epoch"`
	DefinitionDigest Digest `json:"definition_digest"`
	PolicyDigest     Digest `json:"policy_digest"`
	PayloadSHA256    string `json:"payload_sha256"`
	PayloadSize      int64  `json:"payload_size"`
}

type CheckpointPolicy struct{ MaxBytesPerCheckpoint, MaxTotalCheckpointBytes int64 }

func (p CheckpointPolicy) Validate() error {
	if p.MaxBytesPerCheckpoint <= 0 || p.MaxTotalCheckpointBytes <= 0 || p.MaxBytesPerCheckpoint > p.MaxTotalCheckpointBytes {
		return fmt.Errorf("%w: finite positive checkpoint caps required", ErrCheckpointInvalid)
	}
	return nil
}

type CheckpointRequest struct {
	OperationID string
	Manifest    CheckpointManifest
	Payload     []byte
}
type Checkpoint struct {
	ID            string
	Manifest      CheckpointManifest
	ManifestBytes []byte
	Payload       []byte
	Status        CheckpointStatus
	StoredBytes   int64
}

func (m CheckpointManifest) Validate(payload []byte, policy CheckpointPolicy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	for _, v := range []string{m.SchemaVersion, m.RootID, m.WorkOrderID, m.AttemptID} {
		if strings.TrimSpace(v) == "" || strings.TrimSpace(v) != v {
			return nil, fmt.Errorf("%w: empty or padded identity", ErrCheckpointInvalid)
		}
	}
	if m.SchemaVersion != "paddock.checkpoint/1" || m.LeaseEpoch == 0 || m.LeaseEpoch > math.MaxInt64 {
		return nil, fmt.Errorf("%w: schema or lease epoch", ErrCheckpointInvalid)
	}
	if err := m.DefinitionDigest.Validate(); err != nil {
		return nil, err
	}
	if err := m.PolicyDigest.Validate(); err != nil {
		return nil, err
	}
	if m.PayloadSize < 0 || int64(len(payload)) != m.PayloadSize || m.PayloadSize > policy.MaxBytesPerCheckpoint {
		return nil, fmt.Errorf("%w: payload size cap or mismatch", ErrCheckpointInvalid)
	}
	sum := sha256.Sum256(payload)
	if m.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		return nil, fmt.Errorf("%w: payload digest mismatch", ErrCheckpointInvalid)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	encoded, err := canonical.NewJCSCodec().CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > math.MaxInt64-m.PayloadSize || int64(len(encoded))+m.PayloadSize > policy.MaxTotalCheckpointBytes {
		return nil, fmt.Errorf("%w: stored byte cap", ErrCheckpointInvalid)
	}
	return encoded, nil
}

func ValidateCheckpointRequest(r CheckpointRequest, p CheckpointPolicy) ([]byte, int64, error) {
	if strings.TrimSpace(r.OperationID) == "" || strings.TrimSpace(r.OperationID) != r.OperationID {
		return nil, 0, ErrCheckpointInvalid
	}
	b, e := r.Manifest.Validate(r.Payload, p)
	if e != nil {
		return nil, 0, e
	}
	n := int64(len(b)) + int64(len(r.Payload))
	return b, n, nil
}
