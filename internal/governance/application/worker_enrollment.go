package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type WorkerEnrollmentProof struct {
	ChallengeID string
	PublicKey   []byte
	Signature   []byte
}

// WorkerEnrollmentService is Coordinator-side only. Its production constructor
// uses crypto/rand; no Worker-supplied identity, audience, schema, or nonce is accepted.
type WorkerEnrollmentService struct {
	store  port.WorkerEnrollmentStore
	codec  *canonical.JCSCodec
	random io.Reader
}

func NewWorkerEnrollmentService(store port.WorkerEnrollmentStore, codec *canonical.JCSCodec) *WorkerEnrollmentService {
	return &WorkerEnrollmentService{store: store, codec: codec, random: rand.Reader}
}

func (s *WorkerEnrollmentService) ready(ctx context.Context) error {
	if s == nil || s.store == nil || s.codec == nil || s.random == nil || ctx == nil {
		return domain.ErrWorkerEnrollment
	}
	return ctx.Err()
}

func (s *WorkerEnrollmentService) IssueChallenge(ctx context.Context, fingerprint domain.WorkerKeyFingerprint) (domain.EnrollmentChallenge, error) {
	if err := s.ready(ctx); err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	if err := fingerprint.Validate(); err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	id, err := s.opaqueToken()
	if err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	nonce, err := s.opaqueToken()
	if err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	challenge := domain.EnrollmentChallenge{ID: id, Nonce: nonce, Fingerprint: fingerprint, Schema: domain.WorkerEnrollmentSchema, Audience: domain.WorkerEnrollmentAudience}
	if err := s.store.CreateEnrollmentChallenge(ctx, challenge); err != nil {
		return domain.EnrollmentChallenge{}, fmt.Errorf("persist enrollment challenge: %w", err)
	}
	return challenge, nil
}

func (s *WorkerEnrollmentService) Enroll(ctx context.Context, proof WorkerEnrollmentProof) (domain.QuarantinedWorker, error) {
	if err := s.ready(ctx); err != nil {
		return domain.QuarantinedWorker{}, err
	}
	if err := domain.ValidateEnrollmentChallengeID(proof.ChallengeID); err != nil {
		return domain.QuarantinedWorker{}, err
	}
	challenge, err := s.store.ReadEnrollmentChallenge(ctx, proof.ChallengeID)
	if err != nil {
		return domain.QuarantinedWorker{}, fmt.Errorf("read enrollment challenge: %w", err)
	}
	if challenge.ID != proof.ChallengeID {
		return domain.QuarantinedWorker{}, domain.ErrEnrollmentTicket
	}
	verified, err := domain.VerifyWorkerEnrollment(s.codec, challenge, proof.PublicKey, proof.Signature)
	if err != nil {
		return domain.QuarantinedWorker{}, err
	}
	token, err := s.opaqueToken()
	if err != nil {
		return domain.QuarantinedWorker{}, err
	}
	id := domain.WorkerID("worker_" + token)
	worker, err := s.store.ConsumeEnrollment(ctx, verified, id)
	if err != nil {
		return domain.QuarantinedWorker{}, fmt.Errorf("consume enrollment ticket: %w", err)
	}
	if worker.Validate() != nil || worker.ID != id || worker.Fingerprint != challenge.Fingerprint {
		return domain.QuarantinedWorker{}, fmt.Errorf("unsafe enrollment store result: %w", domain.ErrWorkerEnrollment)
	}
	return worker, nil
}

func (s *WorkerEnrollmentService) opaqueToken() (string, error) {
	var token [32]byte // 256 bits of independent Coordinator-generated entropy.
	if _, err := io.ReadFull(s.random, token[:]); err != nil {
		return "", fmt.Errorf("generate enrollment token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}
