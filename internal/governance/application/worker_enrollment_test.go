package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/domain"
)

// This deterministic fake tests application sequencing, not PostgreSQL isolation.
type enrollmentMemory struct {
	mu                                sync.Mutex
	tickets                           map[string]domain.EnrollmentChallenge
	workers                           map[domain.WorkerKeyFingerprint]domain.QuarantinedWorker
	creates, reads, consumes          int
	failCreate, failRead, failConsume error
	readOverride                      *domain.EnrollmentChallenge
	resultOverride                    *domain.QuarantinedWorker
}

func newEnrollmentMemory() *enrollmentMemory {
	return &enrollmentMemory{tickets: make(map[string]domain.EnrollmentChallenge), workers: make(map[domain.WorkerKeyFingerprint]domain.QuarantinedWorker)}
}
func (m *enrollmentMemory) CreateEnrollmentChallenge(_ context.Context, c domain.EnrollmentChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates++
	if m.failCreate != nil {
		return m.failCreate
	}
	if _, exists := m.workers[c.Fingerprint]; exists {
		return domain.ErrWorkerAlreadyEnrolled
	}
	if _, exists := m.tickets[c.ID]; exists {
		return domain.ErrEnrollmentTicket
	}
	m.tickets[c.ID] = c
	return nil
}
func (m *enrollmentMemory) ReadEnrollmentChallenge(_ context.Context, id string) (domain.EnrollmentChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if m.failRead != nil {
		return domain.EnrollmentChallenge{}, m.failRead
	}
	if m.readOverride != nil {
		return *m.readOverride, nil
	}
	c, ok := m.tickets[id]
	if !ok {
		return c, domain.ErrEnrollmentTicket
	}
	return c, nil
}
func (m *enrollmentMemory) ConsumeEnrollment(_ context.Context, v domain.VerifiedWorkerEnrollment, id domain.WorkerID) (domain.QuarantinedWorker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consumes++
	if m.failConsume != nil {
		return domain.QuarantinedWorker{}, m.failConsume
	}
	if err := v.Validate(); err != nil {
		return domain.QuarantinedWorker{}, err
	}
	c := v.Challenge()
	stored, ok := m.tickets[c.ID]
	if !ok || stored != c {
		return domain.QuarantinedWorker{}, domain.ErrEnrollmentTicket
	}
	if _, exists := m.workers[c.Fingerprint]; exists {
		return domain.QuarantinedWorker{}, domain.ErrWorkerAlreadyEnrolled
	}
	w := domain.QuarantinedWorker{ID: id, Fingerprint: c.Fingerprint, Tier: domain.WorkerQuarantineTier, State: domain.WorkerQuarantined}
	m.workers[c.Fingerprint] = w
	delete(m.tickets, c.ID)
	if m.resultOverride != nil {
		return *m.resultOverride, nil
	}
	return w, nil
}
func enrollmentAppFixture(t *testing.T) (*WorkerEnrollmentService, *enrollmentMemory, ed25519.PrivateKey, domain.WorkerKeyFingerprint) {
	t.Helper()
	m := newEnrollmentMemory()
	s := NewWorkerEnrollmentService(m, canonical.NewJCSCodec())
	entropy := make([]byte, 32*32)
	for i := range entropy {
		entropy[i] = byte(i/32 + 1)
	}
	s.random = bytes.NewReader(entropy)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	fingerprint, err := domain.FingerprintWorkerKey(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return s, m, key, fingerprint
}
func signEnrollment(t *testing.T, c domain.EnrollmentChallenge, key ed25519.PrivateKey) WorkerEnrollmentProof {
	t.Helper()
	message, err := c.SigningBytes(canonical.NewJCSCodec())
	if err != nil {
		t.Fatal(err)
	}
	return WorkerEnrollmentProof{ChallengeID: c.ID, PublicKey: key.Public().(ed25519.PublicKey), Signature: ed25519.Sign(key, message)}
}
func TestWorkerEnrollmentInvalidProofRetrySuccessReplayAndDuplicateKey(t *testing.T) {
	s, m, key, fingerprint := enrollmentAppFixture(t)
	ctx := context.Background()
	c, err := s.IssueChallenge(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.IssueChallenge(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == c.Nonce || c.ID == other.ID || c.Fingerprint != fingerprint {
		t.Fatal("challenge binding or entropy reuse")
	}
	proof := signEnrollment(t, c, key)
	for _, kind := range []string{"signature", "key", "nonce", "ticket"} {
		bad := proof
		bad.Signature = append([]byte(nil), proof.Signature...)
		switch kind {
		case "signature":
			bad.Signature[0] ^= 1
		case "key":
			bad.PublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
		case "nonce":
			altered := c
			altered.Nonce = strings.Repeat("a", 64)
			bad = signEnrollment(t, altered, key)
		case "ticket":
			bad.ChallengeID = other.ID
		}
		if _, err := s.Enroll(ctx, bad); !errors.Is(err, domain.ErrWorkerEnrollmentProof) {
			t.Fatalf("%s: %v", kind, err)
		}
		if len(m.tickets) != 2 || len(m.workers) != 0 || m.consumes != 0 {
			t.Fatal("invalid proof consumed ticket or reached mutation")
		}
	}
	w, err := s.Enroll(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if w.Validate() != nil || w.ID == domain.WorkerID(fingerprint) || w.Fingerprint != fingerprint || len(m.workers) != 1 || len(m.tickets) != 1 {
		t.Fatal("unsafe registration")
	}
	if _, err := s.Enroll(ctx, proof); !errors.Is(err, domain.ErrEnrollmentTicket) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := s.Enroll(ctx, signEnrollment(t, other, key)); !errors.Is(err, domain.ErrWorkerAlreadyEnrolled) {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, ok := m.tickets[other.ID]; !ok {
		t.Fatal("duplicate-key failure consumed unused ticket")
	}
	if _, err := s.IssueChallenge(ctx, fingerprint); !errors.Is(err, domain.ErrWorkerAlreadyEnrolled) {
		t.Fatalf("new duplicate challenge: %v", err)
	}
}
func TestWorkerEnrollmentFailureBoundaries(t *testing.T) {
	boom := errors.New("store unavailable")
	for _, kind := range []string{"create", "read", "consume", "entropy-issue", "entropy-enroll", "bad-result", "wrong-ticket", "bad-schema", "nil-codec", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, m, key, fp := enrollmentAppFixture(t)
			ctx := context.Background()
			if kind == "create" {
				m.failCreate = boom
				if _, err := s.IssueChallenge(ctx, fp); !errors.Is(err, boom) {
					t.Fatal(err)
				}
				return
			}
			if kind == "entropy-issue" {
				s.random = bytes.NewReader(make([]byte, 33))
				if _, err := s.IssueChallenge(ctx, fp); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
				if m.creates != 0 {
					t.Fatal("persisted partial random challenge")
				}
				return
			}
			c, err := s.IssueChallenge(ctx, fp)
			if err != nil {
				t.Fatal(err)
			}
			proof := signEnrollment(t, c, key)
			switch kind {
			case "read":
				m.failRead = boom
			case "consume":
				m.failConsume = boom
			case "entropy-enroll":
				s.random = bytes.NewReader(nil)
			case "bad-result":
				m.resultOverride = &domain.QuarantinedWorker{ID: "chosen-by-worker", Fingerprint: fp, Tier: "Q1", State: "ACTIVE"}
			case "wrong-ticket":
				bad := c
				bad.ID = strings.Repeat("b", 64)
				m.readOverride = &bad
			case "bad-schema":
				bad := c
				bad.Schema = "other"
				m.readOverride = &bad
			case "nil-codec":
				s.codec = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if _, err := s.Enroll(ctx, proof); err == nil {
				t.Fatal("failure was hidden")
			}
			if kind != "bad-result" && len(m.workers) != 0 {
				t.Fatal("failure registered Worker")
			}
			if kind != "consume" && kind != "bad-result" && m.consumes != 0 {
				t.Fatal("precondition failure reached consume")
			}
			if kind != "bad-result" && len(m.tickets) != 1 {
				t.Fatal("failure consumed ticket")
			}
		})
	}
}
func TestWorkerEnrollmentRejectsInvalidServiceInputs(t *testing.T) {
	s, m, _, fp := enrollmentAppFixture(t)
	if _, err := s.IssueChallenge(nil, fp); err == nil {
		t.Fatal("nil context")
	}
	if _, err := s.IssueChallenge(context.Background(), "bad"); err == nil {
		t.Fatal("bad fingerprint")
	}
	if _, err := s.Enroll(context.Background(), WorkerEnrollmentProof{ChallengeID: "bad"}); err == nil {
		t.Fatal("bad ticket")
	}
	var absent *WorkerEnrollmentService
	if _, err := absent.IssueChallenge(context.Background(), fp); err == nil {
		t.Fatal("nil service")
	}
	if m.creates != 0 || m.reads != 0 || m.consumes != 0 {
		t.Fatal("invalid inputs reached persistence")
	}
}
