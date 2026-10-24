package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type workerEnrollmentDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
type WorkerEnrollmentStore struct{ db workerEnrollmentDB }

var _ port.WorkerEnrollmentStore = (*WorkerEnrollmentStore)(nil)

func NewWorkerEnrollmentStore(db workerEnrollmentDB) *WorkerEnrollmentStore {
	return &WorkerEnrollmentStore{db: db}
}
func (s *WorkerEnrollmentStore) ready(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return domain.ErrWorkerEnrollment
	}
	return ctx.Err()
}

func (s *WorkerEnrollmentStore) CreateEnrollmentChallenge(ctx context.Context, c domain.EnrollmentChallenge) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	var created bool
	err := s.db.QueryRow(ctx, `SELECT raw.issue_worker_enrollment_challenge($1,$2,$3,$4,$5)`, c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience).Scan(&created)
	if err != nil {
		return workerEnrollmentError("issue challenge", err)
	}
	if !created {
		return domain.ErrEnrollmentTicket
	}
	return nil
}
func (s *WorkerEnrollmentStore) ReadEnrollmentChallenge(ctx context.Context, id string) (domain.EnrollmentChallenge, error) {
	if err := s.ready(ctx); err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	if err := domain.ValidateEnrollmentChallengeID(id); err != nil {
		return domain.EnrollmentChallenge{}, err
	}
	var c domain.EnrollmentChallenge
	var fingerprint string
	err := s.db.QueryRow(ctx, `SELECT challenge_id,nonce,fingerprint,schema_version,audience FROM raw.read_worker_enrollment_challenge($1)`, id).Scan(&c.ID, &c.Nonce, &fingerprint, &c.Schema, &c.Audience)
	if err != nil {
		return domain.EnrollmentChallenge{}, workerEnrollmentError("read challenge", err)
	}
	c.Fingerprint = domain.WorkerKeyFingerprint(fingerprint)
	if c.Validate() != nil || c.ID != id {
		return domain.EnrollmentChallenge{}, domain.ErrEnrollmentTicket
	}
	return c, nil
}
func (s *WorkerEnrollmentStore) ConsumeEnrollment(ctx context.Context, v domain.VerifiedWorkerEnrollment, id domain.WorkerID) (domain.QuarantinedWorker, error) {
	if err := s.ready(ctx); err != nil {
		return domain.QuarantinedWorker{}, err
	}
	if v.Validate() != nil || domain.ValidateEnrollmentWorkerID(id) != nil {
		return domain.QuarantinedWorker{}, domain.ErrWorkerEnrollmentProof
	}
	c, key := v.Challenge(), v.PublicKey()
	var worker domain.QuarantinedWorker
	var storedID, fingerprint string
	// One statement invokes one DB transaction: lock/recheck, unique insert, consume.
	// DB capabilities are private to the trusted Coordinator app role; Ed25519
	// verification is done above that boundary, not claimed as a PostgreSQL primitive.
	err := s.db.QueryRow(ctx, `SELECT worker_id,fingerprint,quarantine_tier,state FROM raw.consume_worker_enrollment($1,$2,$3,$4,$5,$6,$7)`, c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience, key[:], string(id)).Scan(&storedID, &fingerprint, &worker.Tier, &worker.State)
	if err != nil {
		return domain.QuarantinedWorker{}, workerEnrollmentError("consume ticket", err)
	}
	worker.ID, worker.Fingerprint = domain.WorkerID(storedID), domain.WorkerKeyFingerprint(fingerprint)
	if worker.Validate() != nil || worker.ID != id || worker.Fingerprint != c.Fingerprint {
		return domain.QuarantinedWorker{}, domain.ErrWorkerEnrollment
	}
	return worker, nil
}
func workerEnrollmentError(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", op, domain.ErrEnrollmentTicket)
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		switch pgerr.Code {
		case "P1001":
			return fmt.Errorf("%s: %w", op, domain.ErrEnrollmentTicket)
		case "P1002":
			return fmt.Errorf("%s: %w", op, domain.ErrWorkerAlreadyEnrolled)
		}
	}
	return fmt.Errorf("worker enrollment %s: %w", op, err)
}
