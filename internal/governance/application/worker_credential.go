package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// WorkerCredentialService is a trusted Coordinator-only API. Audience and
// issuer selection are deployment context, never Worker-provided claim fields.
type WorkerCredentialService struct {
	store    port.WorkerCredentialStore
	issuers  port.CredentialIssuerProvider
	audience string
	issuerID string
	random   io.Reader
}

func NewWorkerCredentialService(store port.WorkerCredentialStore, issuers port.CredentialIssuerProvider, audience, issuerID string) *WorkerCredentialService {
	return &WorkerCredentialService{store: store, issuers: issuers, audience: audience, issuerID: issuerID, random: rand.Reader}
}

func (s *WorkerCredentialService) ready(ctx context.Context) error {
	if s == nil || s.store == nil || s.issuers == nil || s.random == nil || ctx == nil {
		return domain.ErrWorkerCredential
	}
	return ctx.Err()
}

func (s *WorkerCredentialService) Issue(ctx context.Context, fingerprint domain.WorkerKeyFingerprint, lease domain.AttemptLeaseBinding) (domain.WorkerCredential, error) {
	if err := s.ready(ctx); err != nil {
		return domain.WorkerCredential{}, err
	}
	issuer, err := s.issuers.CurrentCredentialIssuer(ctx, s.issuerID)
	if err != nil {
		return domain.WorkerCredential{}, fmt.Errorf("read current credential issuer: %w", err)
	}
	if issuer.IssuerID != s.issuerID {
		return domain.WorkerCredential{}, domain.ErrWorkerCredential
	}
	var token [32]byte
	if _, err := io.ReadFull(s.random, token[:]); err != nil {
		return domain.WorkerCredential{}, fmt.Errorf("generate credential identity: %w", err)
	}
	c := domain.WorkerCredential{ID: hex.EncodeToString(token[:]), Fingerprint: fingerprint, Lease: lease, Audience: s.audience, Issuer: issuer}
	if err := c.Validate(); err != nil {
		return domain.WorkerCredential{}, err
	}
	if err := s.store.IssueWorkerCredential(ctx, c); err != nil {
		return domain.WorkerCredential{}, fmt.Errorf("persist worker credential: %w", err)
	}
	return c, nil
}

func (s *WorkerCredentialService) Revoke(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := domain.ValidateWorkerCredentialID(id); err != nil {
		return err
	}
	if err := s.store.RevokeWorkerCredential(ctx, id); err != nil {
		return fmt.Errorf("revoke worker credential: %w", err)
	}
	return nil
}
