//go:build paddock_test

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/letwir/paddock/internal/canonical"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// The recorder captures exact candidate IDs before each write, including an
// ambiguous transport failure. Cleanup never uses prefixes, TRUNCATE, or broad deletes.
type enrollmentFixtureRecorder struct {
	mu         sync.Mutex
	challenges []domain.EnrollmentChallenge
	candidates []struct {
		proof domain.VerifiedWorkerEnrollment
		id    domain.WorkerID
	}
}
type enrollmentRecordingStore struct {
	port.WorkerEnrollmentStore
	recorder *enrollmentFixtureRecorder
}

func (s enrollmentRecordingStore) CreateEnrollmentChallenge(ctx context.Context, c domain.EnrollmentChallenge) error {
	s.recorder.mu.Lock()
	s.recorder.challenges = append(s.recorder.challenges, c)
	s.recorder.mu.Unlock()
	return s.WorkerEnrollmentStore.CreateEnrollmentChallenge(ctx, c)
}
func (s enrollmentRecordingStore) ConsumeEnrollment(ctx context.Context, v domain.VerifiedWorkerEnrollment, id domain.WorkerID) (domain.QuarantinedWorker, error) {
	s.recorder.mu.Lock()
	s.recorder.candidates = append(s.recorder.candidates, struct {
		proof domain.VerifiedWorkerEnrollment
		id    domain.WorkerID
	}{v, id})
	s.recorder.mu.Unlock()
	return s.WorkerEnrollmentStore.ConsumeEnrollment(ctx, v, id)
}

// TestWorkerEnrollmentIntegration is opt-in DB-writing source. It requires an
// independently approved/applied M10-S01 migration. It never applies a migration.
// Compile-only: unset DB variables and use -tags paddock_test -run '^$'.
func TestWorkerEnrollmentIntegration(t *testing.T) {
	if os.Getenv("PADDOCK_WORKER_ENROLLMENT_INTEGRATION") != "1" {
		t.Skip("explicit enrollment integration opt-in required")
	}
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("both fixture and app DB configurations required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	setup, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect enrollment fixture database")
	}
	t.Cleanup(setup.Close)
	var database, sessionUser, currentUser string
	if err := setup.QueryRow(ctx, `SELECT current_database(),session_user,current_user`).Scan(&database, &sessionUser, &currentUser); err != nil || database != "paddock_test" || sessionUser != "paddock_migrator" || currentUser != "paddock_migrator" {
		t.Fatal("fixture database must be paddock_test as paddock_migrator")
	}
	// Distinct pools model independent Active-Active Coordinator connections.
	appA, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("cannot connect Coordinator A app role")
	}
	t.Cleanup(appA.Close)
	appB, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("cannot connect Coordinator B app role")
	}
	t.Cleanup(appB.Close)
	for _, pool := range []workerEnrollmentDB{appA, appB} {
		if err := pool.QueryRow(ctx, `SELECT current_database(),session_user,current_user`).Scan(&database, &sessionUser, &currentUser); err != nil || database != "paddock_test" || sessionUser != "paddock_app" || currentUser != "paddock_app" {
			t.Fatal("Coordinator connection must be paddock_test as paddock_app")
		}
	}
	var schema bool
	if err := setup.QueryRow(ctx, `SELECT to_regprocedure('raw.issue_worker_enrollment_challenge(text,text,text,text,text)') IS NOT NULL AND to_regprocedure('raw.read_worker_enrollment_challenge(text)') IS NOT NULL AND to_regprocedure('raw.consume_worker_enrollment(text,text,text,text,text,bytea,text)') IS NOT NULL`).Scan(&schema); err != nil || !schema {
		t.Fatal("apply enrollment schema separately before this opt-in test")
	}
	var directAccess, badAPI bool
	err = setup.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM unnest(ARRAY['worker_enrollment_challenges','worker_enrollment_workers']) tab(name)
 CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) priv(name)
 WHERE has_table_privilege('paddock_app','raw.'||tab.name,priv.name))
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['worker_enrollment_challenges','worker_enrollment_workers']) tab(name)
 CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) priv(name)
 WHERE has_any_column_privilege('paddock_app','raw.'||tab.name,priv.name)),
 EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
 WHERE p.oid=ANY(ARRAY['raw.issue_worker_enrollment_challenge(text,text,text,text,text)'::regprocedure,'raw.read_worker_enrollment_challenge(text)'::regprocedure,'raw.consume_worker_enrollment(text,text,text,text,text,bytea,text)'::regprocedure])
 AND (NOT p.prosecdef OR NOT COALESCE(p.proconfig @> ARRAY['search_path=pg_catalog'],false) OR owner.rolname<>'paddock_migrator'
 OR NOT has_function_privilege('paddock_app',p.oid,'EXECUTE')
 OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app')))))`).Scan(&directAccess, &badAPI)
	if err != nil || directAccess || badAPI {
		t.Fatal("enrollment privilege contract mismatch")
	}

	recorder := &enrollmentFixtureRecorder{}
	// Register exact cleanup before the first application write. Fingerprints are
	// collision-checked before challenge creation; no pre-existing rows are owned.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		for _, c := range recorder.challenges {
			if _, err := setup.Exec(cleanup, `DELETE FROM raw.worker_enrollment_challenges WHERE challenge_id=$1 AND nonce=$2 AND fingerprint=$3 AND schema_version=$4 AND audience=$5`, c.ID, c.Nonce, string(c.Fingerprint), c.Schema, c.Audience); err != nil {
				t.Error("exact enrollment challenge cleanup failed")
			}
		}
		for _, candidate := range recorder.candidates {
			key := candidate.proof.PublicKey()
			if _, err := setup.Exec(cleanup, `DELETE FROM raw.worker_enrollment_workers WHERE worker_id=$1 AND fingerprint=$2 AND public_key=$3`, string(candidate.id), string(candidate.proof.Challenge().Fingerprint), key[:]); err != nil {
				t.Error("exact enrollment Worker cleanup failed")
			}
		}
	})
	stores := []enrollmentRecordingStore{{NewWorkerEnrollmentStore(appA), recorder}, {NewWorkerEnrollmentStore(appB), recorder}}
	services := []*application.WorkerEnrollmentService{application.NewWorkerEnrollmentService(stores[0], canonical.NewJCSCodec()), application.NewWorkerEnrollmentService(stores[1], canonical.NewJCSCodec())}
	newKey := func() (ed25519.PublicKey, ed25519.PrivateKey, domain.WorkerKeyFingerprint) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("generate ephemeral enrollment fixture key")
		}
		fp, err := domain.FingerprintWorkerKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		var collision bool
		if err := setup.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.worker_enrollment_workers WHERE fingerprint=$1) OR EXISTS(SELECT 1 FROM raw.worker_enrollment_challenges WHERE fingerprint=$1)`, string(fp)).Scan(&collision); err != nil || collision {
			t.Fatal("fixture key collision; refusing writes")
		}
		return pub, key, fp
	}
	issue := func(service int, fp domain.WorkerKeyFingerprint) domain.EnrollmentChallenge {
		c, err := services[service].IssueChallenge(ctx, fp)
		if err != nil {
			t.Fatal("issue enrollment fixture challenge")
		}
		return c
	}
	sign := func(c domain.EnrollmentChallenge, pub ed25519.PublicKey, key ed25519.PrivateKey) application.WorkerEnrollmentProof {
		message, err := c.SigningBytes(canonical.NewJCSCodec())
		if err != nil {
			t.Fatal(err)
		}
		return application.WorkerEnrollmentProof{ChallengeID: c.ID, PublicKey: pub, Signature: ed25519.Sign(key, message)}
	}
	checkState := func(c domain.EnrollmentChallenge, consumed bool, workers int) {
		var used bool
		var count int
		if err := setup.QueryRow(ctx, `SELECT consumed_worker_id IS NOT NULL,(SELECT count(*) FROM raw.worker_enrollment_workers w WHERE w.fingerprint=$2 AND w.quarantine_tier='Q0' AND w.state='QUARANTINED') FROM raw.worker_enrollment_challenges WHERE challenge_id=$1 AND fingerprint=$2`, c.ID, string(c.Fingerprint)).Scan(&used, &count); err != nil || used != consumed || count != workers {
			t.Fatal("atomic ticket/Q0 state mismatch")
		}
	}
	pub, key, fp := newKey()
	c, duplicate := issue(0, fp), issue(1, fp)
	proof := sign(c, pub, key)
	invalid := proof
	invalid.Signature = append([]byte(nil), proof.Signature...)
	invalid.Signature[0] ^= 1
	if _, err := services[1].Enroll(ctx, invalid); !errors.Is(err, domain.ErrWorkerEnrollmentProof) {
		t.Fatal("invalid proof accepted")
	}
	checkState(c, false, 0)
	mismatch := proof
	mismatch.ChallengeID = duplicate.ID
	if _, err := services[1].Enroll(ctx, mismatch); !errors.Is(err, domain.ErrWorkerEnrollmentProof) {
		t.Fatal("mismatched ticket proof accepted")
	}
	checkState(duplicate, false, 0)
	worker, err := services[1].Enroll(ctx, proof)
	if err != nil || worker.Validate() != nil || worker.ID == domain.WorkerID(fp) {
		t.Fatal("valid proof did not register opaque Q0 Worker")
	}
	checkState(c, true, 1)
	if _, err := services[0].Enroll(ctx, proof); !errors.Is(err, domain.ErrEnrollmentTicket) {
		t.Fatal("successful ticket replay accepted")
	}
	if _, err := services[0].Enroll(ctx, sign(duplicate, pub, key)); !errors.Is(err, domain.ErrWorkerAlreadyEnrolled) {
		t.Fatal("duplicate public key accepted")
	}
	checkState(duplicate, false, 1)

	// Both Coordinators verify before racing the DB call. This forces the locked
	// compare/consume boundary rather than relying on a pre-consume read race.
	for _, sameTicket := range []bool{true, false} {
		pub, key, fp := newKey()
		first := issue(0, fp)
		second := first
		if !sameTicket {
			second = issue(1, fp)
		}
		tickets := []domain.EnrollmentChallenge{first, second}
		verified := make([]domain.VerifiedWorkerEnrollment, 2)
		ids := make([]domain.WorkerID, 2)
		for i, c := range tickets {
			proof := sign(c, pub, key)
			verified[i], err = domain.VerifyWorkerEnrollment(canonical.NewJCSCodec(), c, proof.PublicKey, proof.Signature)
			if err != nil {
				t.Fatal(err)
			}
			var entropy [32]byte
			if _, err := rand.Read(entropy[:]); err != nil {
				t.Fatal("generate Coordinator fixture identity")
			}
			ids[i] = domain.WorkerID("worker_" + hex.EncodeToString(entropy[:]))
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				w, err := stores[i].ConsumeEnrollment(ctx, verified[i], ids[i])
				if err == nil && w.Validate() != nil {
					err = domain.ErrWorkerEnrollment
				}
				results <- err
			}(i)
		}
		close(start)
		wg.Wait()
		close(results)
		successes, denied := 0, 0
		expected := domain.ErrWorkerAlreadyEnrolled
		if sameTicket {
			expected = domain.ErrEnrollmentTicket
		}
		for err := range results {
			if err == nil {
				successes++
			} else if errors.Is(err, expected) {
				denied++
			} else {
				t.Fatal("unexpected concurrent enrollment result")
			}
		}
		if successes != 1 || denied != 1 {
			t.Fatal("Active-Active enrollment did not select exactly one winner")
		}
		var used, count int
		if err := setup.QueryRow(ctx, `SELECT count(*) FILTER(WHERE consumed_worker_id IS NOT NULL),(SELECT count(*) FROM raw.worker_enrollment_workers WHERE fingerprint=$1) FROM raw.worker_enrollment_challenges WHERE fingerprint=$1`, string(fp)).Scan(&used, &count); err != nil || used != 1 || count != 1 {
			t.Fatal("concurrent consume/registration was not atomic and unique")
		}
	}
}
