package postgres

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type workerCredentialDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
type WorkerCredentialStore struct{ db workerCredentialDB }

var _ port.WorkerCredentialStore = (*WorkerCredentialStore)(nil)

func NewWorkerCredentialStore(db workerCredentialDB) *WorkerCredentialStore {
	return &WorkerCredentialStore{db: db}
}
func (s *WorkerCredentialStore) ready(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return domain.ErrWorkerCredential
	}
	return ctx.Err()
}
func (s *WorkerCredentialStore) IssueWorkerCredential(ctx context.Context, c domain.WorkerCredential) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if c.Validate() != nil || c.Revoked {
		return domain.ErrWorkerCredential
	}
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT raw.issue_worker_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, c.ID, string(c.Fingerprint), string(c.Lease.WorkOrderID), string(c.Lease.AttemptID), string(c.Lease.WorkerID), string(c.Lease.SessionID), int64(c.Lease.LeaseEpoch), c.Audience, c.Issuer.IssuerID, strconv.FormatUint(c.Issuer.Revision, 10), string(c.Issuer.CeilingDigest)).Scan(&ok)
	if err != nil {
		return credentialStorageError("issue", err)
	}
	if !ok {
		return domain.ErrWorkerCredential
	}
	return nil
}
func (s *WorkerCredentialStore) RevokeWorkerCredential(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := domain.ValidateWorkerCredentialID(id); err != nil {
		return err
	}
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT raw.revoke_worker_credential($1)`, id).Scan(&ok); err != nil {
		return credentialStorageError("revoke", err)
	}
	if !ok {
		return domain.ErrWorkerCredential
	}
	return nil
}

func lockWorkerCredential(ctx context.Context, db workerCredentialDB, id string) (domain.WorkerCredential, []byte, error) {
	if ctx == nil || db == nil || domain.ValidateWorkerCredentialID(id) != nil {
		return domain.WorkerCredential{}, nil, domain.ErrWorkerCredential
	}
	if err := ctx.Err(); err != nil {
		return domain.WorkerCredential{}, nil, err
	}
	var c domain.WorkerCredential
	var fingerprint, work, attempt, worker, session, revision, ceiling string
	var epoch int64
	var key []byte
	err := db.QueryRow(ctx, `SELECT credential_id,fingerprint,work_order_id,attempt_id,worker_id,session_id,lease_epoch,audience,issuer_id,issuer_revision,ceiling_digest,revoked,public_key FROM raw.lock_worker_credential($1)`, id).Scan(&c.ID, &fingerprint, &work, &attempt, &worker, &session, &epoch, &c.Audience, &c.Issuer.IssuerID, &revision, &ceiling, &c.Revoked, &key)
	if err != nil {
		return domain.WorkerCredential{}, nil, credentialStorageError("lock", err)
	}
	c.Fingerprint = domain.WorkerKeyFingerprint(fingerprint)
	c.Lease = domain.AttemptLeaseBinding{WorkOrderID: domain.WorkOrderID(work), AttemptID: domain.AttemptID(attempt), WorkerID: domain.WorkerID(worker), SessionID: domain.SessionID(session), LeaseEpoch: domain.LeaseEpoch(epoch)}
	c.Issuer.Revision, err = strconv.ParseUint(revision, 10, 64)
	c.Issuer.CeilingDigest = domain.Digest(ceiling)
	fp, keyErr := domain.FingerprintWorkerKey(key)
	if err != nil || keyErr != nil || c.Validate() != nil || c.ID != id || fp != c.Fingerprint {
		return domain.WorkerCredential{}, nil, domain.ErrWorkerCredential
	}
	return c, append([]byte(nil), key...), nil
}

// Only a borrowed SafetyGate transaction exposes this read. There is no app
// mutation capability for the deployment-owned registry.
func lockCurrentCredentialIssuer(ctx context.Context, db workerCredentialDB, id string) (domain.CredentialIssuerContext, error) {
	if ctx == nil || db == nil || domain.ValidateCredentialIssuerID(id) != nil {
		return domain.CredentialIssuerContext{}, domain.ErrWorkerCredential
	}
	if err := ctx.Err(); err != nil {
		return domain.CredentialIssuerContext{}, err
	}
	var issuer domain.CredentialIssuerContext
	var revision, ceiling string
	if err := db.QueryRow(ctx, `SELECT issuer_id,issuer_revision,ceiling_digest FROM raw.lock_current_worker_issuer_context($1)`, id).Scan(&issuer.IssuerID, &revision, &ceiling); err != nil {
		return domain.CredentialIssuerContext{}, credentialStorageError("lock issuer", err)
	}
	var err error
	issuer.Revision, err = strconv.ParseUint(revision, 10, 64)
	issuer.CeilingDigest = domain.Digest(ceiling)
	if err != nil || issuer.Validate() != nil || issuer.IssuerID != id {
		return domain.CredentialIssuerContext{}, domain.ErrWorkerCredential
	}
	return issuer, nil
}

func credentialStorageError(op string, err error) error {
	// No query arguments, opaque IDs, keys, or DB diagnostic text in this wrapper.
	// Preserve the cause for classification; callers must not expose it to ingress.
	return fmt.Errorf("worker credential %s: %w: %w", op, domain.ErrWorkerCredential, err)
}
