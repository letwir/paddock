package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/domain"
)

type SpawnStore struct{ pool *pgxpool.Pool }

func NewSpawnStore(pool *pgxpool.Pool) (*SpawnStore, error) {
	if pool == nil {
		return nil, errors.New("spawn store: nil pool")
	}
	return &SpawnStore{pool: pool}, nil
}

func (s *SpawnStore) SetPolicy(ctx context.Context, rootID, operationID string, p domain.SpawnPolicy) (json.RawMessage, error) {
	if s == nil || s.pool == nil || ctx == nil || rootID == "" || operationID == "" {
		return nil, errors.New("spawn store: invalid request")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode spawn policy: %w", err)
	}
	var raw []byte
	if err = s.pool.QueryRow(ctx, `SELECT raw.spawn_policy_set($1,$2,$3::jsonb)`, rootID, operationID, string(payload)).Scan(&raw); err != nil {
		return nil, fmt.Errorf("set spawn policy (commit outcome may be unknown): %w", err)
	}
	if !json.Valid(raw) {
		return nil, errors.New("spawn store: invalid result")
	}
	return json.RawMessage(raw), nil
}

type SpawnTask struct {
	Key        string   `json:"key"`
	Title      string   `json:"title"`
	Goal       string   `json:"goal"`
	Acceptance string   `json:"acceptance"`
	DependsOn  []string `json:"depends_on"`
}
type SpawnRequest struct {
	ParentWorkOrderID string      `json:"parent_work_order_id"`
	Tasks             []SpawnTask `json:"tasks"`
}

func (s *SpawnStore) Spawn(ctx context.Context, rootID, operationID string, request json.RawMessage) (json.RawMessage, error) {
	if s == nil || s.pool == nil || ctx == nil || rootID == "" || operationID == "" || !json.Valid(request) {
		return nil, errors.New("spawn store: invalid request")
	}
	if _, err := canonical.NewJCSCodec().CanonicalizeJSON(request); err != nil {
		return nil, fmt.Errorf("validate spawn JSON: %w", err)
	}
	var req SpawnRequest
	decoder := json.NewDecoder(bytes.NewReader(request))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("decode spawn request: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("spawn store: trailing JSON data")
	}
	if strings.TrimSpace(req.ParentWorkOrderID) == "" || len(req.Tasks) == 0 {
		return nil, errors.New("spawn store: parent and tasks are required")
	}
	fingerprints := make([]domain.SemanticNode, len(req.Tasks))
	for i, task := range req.Tasks {
		if strings.TrimSpace(task.Key) == "" || strings.TrimSpace(task.Title) == "" || strings.TrimSpace(task.Goal) == "" || strings.TrimSpace(task.Acceptance) == "" {
			return nil, fmt.Errorf("spawn store: invalid task %q", task.Key)
		}
		fingerprints[i] = domain.SemanticNode{ID: task.Key, Title: task.Title, Goal: task.Goal, Acceptance: task.Acceptance, Dependencies: append([]string(nil), task.DependsOn...)}
	}
	// Digests are read from the same transaction snapshot as the admission call;
	// SQL independently rechecks them under its Root advisory lock.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin spawn transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var definitionDigest, policyDigest string
	err = tx.QueryRow(ctx, `SELECT effective_bundle_digest,policy_digest FROM raw.spawn_fingerprint_context($1,$2)`, rootID, req.ParentWorkOrderID).Scan(&definitionDigest, &policyDigest)
	if err != nil {
		return nil, fmt.Errorf("read spawn digest context: %w", err)
	}
	for i := range fingerprints {
		fingerprints[i].DefinitionDigest = definitionDigest
		fingerprints[i].PolicyDigest = policyDigest
	}
	fps, err := domain.SemanticFingerprints(fingerprints)
	if err != nil {
		return nil, fmt.Errorf("compute semantic fingerprints: %w", err)
	}
	encodedRequest, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode spawn request: %w", err)
	}
	canonicalRequest, err := canonical.NewJCSCodec().CanonicalizeJSON(encodedRequest)
	if err != nil {
		return nil, fmt.Errorf("canonicalize spawn request: %w", err)
	}
	fpJSON, err := json.Marshal(fps)
	if err != nil {
		return nil, fmt.Errorf("encode spawn fingerprints: %w", err)
	}
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT raw.spawn_admit($1,$2,$3::jsonb,$4,$5,$6::jsonb)`, rootID, operationID, string(canonicalRequest), definitionDigest, policyDigest, string(fpJSON)).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("admit spawn (commit outcome may be unknown): %w", err)
	}
	if !json.Valid(raw) {
		return nil, errors.New("spawn store: invalid result")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit spawn admission (outcome may be unknown): %w", err)
	}
	return json.RawMessage(raw), nil
}
