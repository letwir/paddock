//go:build integration && paddock_test

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type pocKeyResolver struct{ public ed25519.PublicKey }

func (k pocKeyResolver) ResolveBundleKey(context.Context, string) (application.BundleSigningKey, error) {
	return application.BundleSigningKey{
		KeyID:      "poc-key",
		PublicKey:  k.public,
		ValidFrom:  time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

type pocLKG struct{}

func (pocLKG) VerifyLKG(_ context.Context, d domain.Digest) (domain.LKGAssessment, error) {
	return domain.LKGAssessment{Digest: d, Status: domain.LKGUsable}, nil
}

type pocFixture struct {
	prefix     string
	scope      domain.ScopeID
	rootA      domain.RootID
	rootB      domain.RootID
	workA      string
	workB      string
	rolloutID  domain.RolloutID
	otherRID   domain.RolloutID
	baseline   domain.CanonicalBundle
	candidate  domain.CanonicalBundle
	key        ed25519.PrivateKey
	public     ed25519.PublicKey
	kernel     domain.KernelSnapshot
	kernelPin  domain.Digest
	security   domain.Epoch
	bindings   map[domain.RootID]domain.AttemptLeaseBinding
	commands   []string
	events     []string
	consumerID string
}

func openIsolatedPools(ctx context.Context, t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	migratorURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if migratorURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required")
	}
	migrator, err := openPullPool(ctx, migratorURL, false)
	if err != nil {
		t.Fatal("unable to open migrator pool")
	}
	t.Cleanup(migrator.Close)
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to open app pool")
	}
	t.Cleanup(app.Close)
	for _, entry := range []struct {
		pool *pgxpool.Pool
		role string
	}{{migrator, "paddock_migrator"}, {app, "paddock_app"}} {
		var db, u, su string
		if err := entry.pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &u, &su); err != nil || db != "paddock_test" || u != entry.role || su != entry.role {
			t.Fatal("unexpected database/role identity")
		}
	}
	return migrator, app, appURL
}

func setupPoCFixture(ctx context.Context, t *testing.T, migrator, app *pgxpool.Pool, tag string, extraCommands int) pocFixture {
	t.Helper()
	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("unable to generate unique prefix")
	}
	prefix := fmt.Sprintf("it_%s_%s", tag, hex.EncodeToString(suffix))
	baseline, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"version":1}`, prefix)))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"version":2}`, prefix)))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	kernel := domain.KernelSnapshot{
		SchemaVersion:  domain.KernelSnapshotSchema,
		Version:        1,
		Signers:        []domain.KernelSigner{{ID: "signer", PublicKey: public}},
		Thresholds:     []domain.TierThreshold{{Tier: domain.TierG0, Threshold: 1}, {Tier: domain.TierG1, Threshold: 1}},
		Capabilities:   []string{"governance"},
		IssuerCeilings: []domain.IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"governance"}}},
	}
	pin, err := kernel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.ScopeID(prefix + "_scope")
	rootA := domain.RootID(prefix + "_root_a")
	rootB := domain.RootID(prefix + "_root_b")
	workA := prefix + "_wo_a"
	workB := prefix + "_wo_b"
	rid := domain.RolloutID(prefix + "_rollout")
	otherRID := domain.RolloutID(prefix + "_rollout_2")
	consumerID := prefix + "_consumer"

	var security domain.Epoch
	if err := migrator.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&security); err != nil {
		t.Fatalf("read security epoch failed: %v", err)
	}

	seed, err := migrator.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,$3,'poc-key',$4)`, []any{string(baseline.Digest()), baseline.CanonicalBytes(), baseline.SchemaVersion(), ed25519.Sign(key, baseline.SigningBytes())}},
		{`INSERT INTO raw.policy_scopes(scope_id,activation_epoch,baseline_bundle_digest,mode) VALUES($1,40,$2,'ACTIVE')`, []any{string(scope), string(baseline.Digest())}},
		{`INSERT INTO raw.roots(root_id,scope_id,authorization_epoch,effective_bundle_digest,safe_baseline) VALUES($1,$3,1,$4,false),($2,$3,1,$4,false)`, []any{string(rootA), string(rootB), string(scope), string(baseline.Digest())}},
		{`INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$3,NULL),($2,$4,NULL)`, []any{workA, workB, string(rootA), string(rootB)}},
	} {
		if _, err := seed.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed insert failed: %v", err)
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	cmds := make([]string, extraCommands)
	evts := make([]string, extraCommands)
	for i := 0; i < extraCommands; i++ {
		cmds[i] = fmt.Sprintf("%s_cmd_%d", prefix, i)
		evts[i] = "rollout/" + cmds[i]
	}

	t.Cleanup(func() {
		cleanCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		tx, err := migrator.Begin(cleanCtx)
		if err != nil {
			t.Errorf("cleanup begin failed: %v", err)
			return
		}
		defer tx.Rollback(cleanCtx)
		workIDs := []string{workA, workB}
		rids := []string{string(rid), string(otherRID)}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM raw.event_inbox WHERE consumer_id=$1 OR event_id=ANY($2::text[])`, []any{consumerID, evts}},
			{`DELETE FROM raw.event_consumer_projection WHERE consumer_id=$1`, []any{consumerID}},
			{`DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, []any{evts}},
			{`DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])`, []any{evts}},
			{`DELETE FROM raw.command_receipts WHERE command_id=ANY($1::text[])`, []any{cmds}},
			{`UPDATE raw.policy_scopes SET live_rollout_id=NULL WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.rollout_targets WHERE rollout_id=ANY($1::text[])`, []any{rids}},
			{`DELETE FROM raw.policy_rollouts WHERE rollout_id=ANY($1::text[])`, []any{rids}},
			{`DELETE FROM raw.work_order_leases WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_order_pull_slots WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_order_attempts WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_orders WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.roots WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2`, []any{string(baseline.Digest()), string(candidate.Digest())}},
		} {
			if _, err := tx.Exec(cleanCtx, q.sql, q.args...); err != nil {
				t.Errorf("cleanup step failed: %v", err)
				return
			}
		}
		if err := tx.Commit(cleanCtx); err != nil {
			t.Errorf("cleanup commit failed: %v", err)
		}
	})

	bindings := make(map[domain.RootID]domain.AttemptLeaseBinding, 2)
	for _, entry := range []struct {
		work string
		root domain.RootID
	}{{workA, rootA}, {workB, rootB}} {
		for _, q := range []string{`SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, `SELECT raw.mark_work_order_pull_ready($1)`} {
			var ok bool
			if err := app.QueryRow(ctx, q, entry.work).Scan(&ok); err != nil || !ok {
				t.Fatalf("work_order configure/ready failed: %v", err)
			}
		}
		b := domain.AttemptLeaseBinding{
			WorkOrderID: domain.WorkOrderID(entry.work),
			AttemptID:   domain.AttemptID(entry.work + "_att"),
			WorkerID:    domain.WorkerID(entry.work + "_worker"),
			SessionID:   domain.SessionID(entry.work + "_session"),
		}
		var att, slot string
		var expires time.Time
		if err := app.QueryRow(ctx, `SELECT attempt_id,slot_id,lease_epoch,expires_at FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,'10 minutes'::interval)`,
			entry.work, string(b.WorkerID), string(b.SessionID), string(b.AttemptID), entry.work+"_slot").Scan(&att, &slot, &b.LeaseEpoch, &expires); err != nil {
			t.Fatalf("issue_work_order_lease failed: %v", err)
		}
		bindings[entry.root] = b
	}

	return pocFixture{
		prefix:     prefix,
		scope:      scope,
		rootA:      rootA,
		rootB:      rootB,
		workA:      workA,
		workB:      workB,
		rolloutID:  rid,
		otherRID:   otherRID,
		baseline:   baseline,
		candidate:  candidate,
		key:        key,
		public:     public,
		kernel:     kernel,
		kernelPin:  pin,
		security:   security,
		bindings:   bindings,
		commands:   cmds,
		events:     evts,
		consumerID: consumerID,
	}
}

func buildRolloutService(t *testing.T, pool *pgxpool.Pool, f pocFixture) *application.RolloutService {
	t.Helper()
	tx, err := NewRolloutTransactor(pool)
	if err != nil {
		t.Fatal(err)
	}
	safety, err := NewSafetyTransactor(pool)
	if err != nil {
		t.Fatal(err)
	}
	bundles := application.NewBundleRegistrationService(safety, pocKeyResolver{f.public})
	svc, err := application.NewRolloutService(tx, bundles, pocLKG{}, f.kernel, f.kernelPin)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// tcpCommitDropProxy forwards PostgreSQL TCP traffic over loopback and severs
// the connection right as COMMIT CommandComplete leaves PostgreSQL when armed.
type tcpCommitDropProxy struct {
	listener net.Listener
	upstream string
	armDrop  atomic.Bool
	dropped  atomic.Int32
	wg       sync.WaitGroup
}

func startTCPCommitDropProxy(t *testing.T, upstreamHost string, upstreamPort uint16) *tcpCommitDropProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback tcp proxy: %v", err)
	}
	p := &tcpCommitDropProxy{
		listener: ln,
		upstream: net.JoinHostPort(upstreamHost, strconv.Itoa(int(upstreamPort))),
	}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		p.wg.Wait()
	})
	return p
}

func (p *tcpCommitDropProxy) Port() uint16 {
	return uint16(p.listener.Addr().(*net.TCPAddr).Port)
}

func (p *tcpCommitDropProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		clientConn, err := p.listener.Accept()
		if err != nil {
			return
		}
		upstreamConn, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
		if err != nil {
			_ = clientConn.Close()
			continue
		}
		p.wg.Add(2)
		go func() {
			defer p.wg.Done()
			defer clientConn.Close()
			defer upstreamConn.Close()
			_, _ = io.Copy(upstreamConn, clientConn)
		}()
		go func() {
			defer p.wg.Done()
			defer clientConn.Close()
			defer upstreamConn.Close()
			buf := make([]byte, 4096)
			var tail []byte
			commitTag := []byte("COMMIT\x00")
			for {
				n, readErr := upstreamConn.Read(buf)
				if n > 0 {
					chunk := buf[:n]
					combined := append(tail, chunk...)
					if p.armDrop.Load() && bytes.Contains(combined, commitTag) {
						if p.armDrop.CompareAndSwap(true, false) {
							p.dropped.Add(1)
							return
						}
					}
					if _, writeErr := clientConn.Write(chunk); writeErr != nil {
						return
					}
					if len(combined) > 16 {
						tail = append([]byte(nil), combined[len(combined)-16:]...)
					} else {
						tail = append([]byte(nil), combined...)
					}
				}
				if readErr != nil {
					return
				}
			}
		}()
	}
}

// TestM04S03_ConcurrentScopeRolloutContention verifies two simulated Coordinators
// racing StartCanary on the same Scope produce exactly one active rollout.
func TestM04S03_ConcurrentScopeRolloutContention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	migrator, app1, appURL := openIsolatedPools(ctx, t)
	app2, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to open second coordinator app pool")
	}
	t.Cleanup(app2.Close)

	f := setupPoCFixture(ctx, t, migrator, app1, "m04s03", 3)
	svc1 := buildRolloutService(t, app1, f)
	svc2 := buildRolloutService(t, app2, f)

	proposer := domain.ProposalContext{ProposerID: "author"}
	propID := f.prefix + "_prop"
	if _, err := svc1.Propose(ctx, application.ProposeRequest{
		CommandID: f.commands[0], Nonce: "n0", Scope: f.scope, ProposalID: propID,
		ProposerID: proposer.ProposerID, BundleKeyID: "poc-key", Bundle: f.candidate,
		Signature: ed25519.Sign(f.key, f.candidate.SigningBytes()),
	}); err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	candidate := domain.DomainCandidate{
		Bundle: f.candidate, Tier: domain.TierG0, IssuerID: "issuer",
		ProposalID: propID, Nonce: "n1", CapabilityIDs: []string{"governance"},
	}
	msg, err := domain.DomainApprovalSigningBytes(candidate, f.kernelPin, proposer.ProposerID)
	if err != nil {
		t.Fatal(err)
	}
	approvals := []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, msg)}}

	type outcome struct {
		rid domain.RolloutID
		res application.StartCanaryResult
		err error
	}
	reqs := []struct {
		svc *application.RolloutService
		cmd string
		rid domain.RolloutID
	}{
		{svc1, f.commands[1], f.rolloutID},
		{svc2, f.commands[2], f.otherRID},
	}
	ready := make(chan struct{}, 2)
	goCh := make(chan struct{})
	outCh := make(chan outcome, 2)
	for _, rq := range reqs {
		go func(svc *application.RolloutService, cmd string, rid domain.RolloutID) {
			ready <- struct{}{}
			<-goCh
			res, err := svc.StartCanary(ctx, application.StartCanaryRequest{
				CommandID: cmd, Nonce: "canary-" + cmd, Scope: f.scope, Rollout: rid, Root: f.rootB,
				Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 1, ExpectedSecurityEpoch: f.security,
			}, proposer)
			outCh <- outcome{rid: rid, res: res, err: err}
		}(rq.svc, rq.cmd, rq.rid)
	}
	<-ready
	<-ready
	close(goCh)

	var successes, failures int
	var winnerRID domain.RolloutID
	for i := 0; i < 2; i++ {
		o := <-outCh
		if o.err == nil {
			successes++
			winnerRID = o.rid
			if o.res.ScopeEpoch != 41 || o.res.RootEpoch != 2 {
				t.Fatalf("unexpected winning epoch: %+v", o.res)
			}
		} else {
			failures++
			var cf *application.CommandFailure
			if !errors.As(o.err, &cf) || (cf.Kind != application.FailureBusy && cf.Kind != application.FailureStale) {
				t.Fatalf("unexpected failure kind for losing coordinator: %v", o.err)
			}
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("expected 1 winner and 1 loser, got successes=%d failures=%d", successes, failures)
	}

	var activeCount int
	var persistedLive string
	var scopeEpoch domain.Epoch
	if err := migrator.QueryRow(ctx, `SELECT (SELECT count(*) FROM raw.policy_rollouts WHERE scope_id=$1 AND state IN ('CANARY','MONITORING','ROLLING_BACK')), live_rollout_id, activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, string(f.scope)).Scan(&activeCount, &persistedLive, &scopeEpoch); err != nil {
		t.Fatalf("readback failed: %v", err)
	}
	if activeCount != 1 || persistedLive != string(winnerRID) || scopeEpoch != 41 {
		t.Fatalf("unexpected scope state: active=%d live=%q epoch=%d", activeCount, persistedLive, scopeEpoch)
	}
}

// TestM04S06_M15S07_TCPFaultProxyCommitUnknownReconciliation exercises a real
// loopback TCP fault proxy that severs the connection mid-COMMIT-ACK, then verifies
// same-CommandID replay reconciles cleanly without duplicating events/outbox rows.
func TestM04S06_M15S07_TCPFaultProxyCommitUnknownReconciliation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	migrator, app, appURL := openIsolatedPools(ctx, t)
	cfg, err := pgxpool.ParseConfig(appURL)
	if err != nil {
		t.Fatal("parse app config failed")
	}
	origPort := cfg.ConnConfig.Port
	if origPort == 0 {
		origPort = 5432
	}
	proxy := startTCPCommitDropProxy(t, cfg.ConnConfig.Host, origPort)
	cfg.ConnConfig.Host = "127.0.0.1"
	cfg.ConnConfig.Port = proxy.Port()
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var db, u string
		if err := conn.QueryRow(ctx, "SELECT current_database(), current_user").Scan(&db, &u); err != nil || db != "paddock_test" || u != "paddock_app" {
			return errors.New("proxy app identity mismatch")
		}
		return nil
	}
	proxyPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open proxy pool: %v", err)
	}
	t.Cleanup(proxyPool.Close)

	f := setupPoCFixture(ctx, t, migrator, app, "m04s06", 4)
	svc := buildRolloutService(t, proxyPool, f)
	proposer := domain.ProposalContext{ProposerID: "author"}
	propID := f.prefix + "_prop"
	if _, err := svc.Propose(ctx, application.ProposeRequest{
		CommandID: f.commands[0], Nonce: "n0", Scope: f.scope, ProposalID: propID,
		ProposerID: proposer.ProposerID, BundleKeyID: "poc-key", Bundle: f.candidate,
		Signature: ed25519.Sign(f.key, f.candidate.SigningBytes()),
	}); err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	candidate := domain.DomainCandidate{
		Bundle: f.candidate, Tier: domain.TierG0, IssuerID: "issuer",
		ProposalID: propID, Nonce: "n1", CapabilityIDs: []string{"governance"},
	}
	msg, err := domain.DomainApprovalSigningBytes(candidate, f.kernelPin, proposer.ProposerID)
	if err != nil {
		t.Fatal(err)
	}
	approvals := []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, msg)}}

	canaryReq := application.StartCanaryRequest{
		CommandID: f.commands[1], Nonce: "n-canary", Scope: f.scope, Rollout: f.rolloutID, Root: f.rootB,
		Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 1, ExpectedSecurityEpoch: f.security,
	}

	// Arm proxy fault to drop the TCP socket right when PostgreSQL returns COMMIT CommandComplete.
	proxy.armDrop.Store(true)
	if _, err := svc.StartCanary(ctx, canaryReq, proposer); err == nil {
		t.Fatal("expected Commit-unknown TCP error when fault proxy dropped mid-COMMIT ACK")
	}
	if proxy.dropped.Load() != 1 {
		t.Fatalf("expected proxy to drop exactly once, dropped=%d", proxy.dropped.Load())
	}

	// Retry with exact same CommandID reconciles idempotently without duplicate side effects.
	res, err := svc.StartCanary(ctx, canaryReq, proposer)
	if err != nil || res.ScopeEpoch != 41 || res.RootEpoch != 2 {
		t.Fatalf("same-CommandID reconciliation failed: res=%+v err=%v", res, err)
	}

	// Retry with DIFFERENT CommandID at old Epoch=40 must fail with typed STALE or BUSY, never double-apply.
	dupReq := canaryReq
	dupReq.CommandID = f.commands[2]
	_, dupErr := svc.StartCanary(ctx, dupReq, proposer)
	var dupCF *application.CommandFailure
	if !errors.As(dupErr, &dupCF) || (dupCF.Kind != application.FailureBusy && dupCF.Kind != application.FailureStale) {
		t.Fatalf("different CommandID must return typed BUSY/STALE without re-executing transition, got %v", dupErr)
	}

	var eventCount, outboxCount, receiptCount int
	if err := migrator.QueryRow(ctx, `SELECT (SELECT count(*) FROM raw.domain_events WHERE event_id=$1),(SELECT count(*) FROM raw.event_outbox WHERE event_id=$1),(SELECT count(*) FROM raw.command_receipts WHERE command_id=$2)`,
		f.events[1], f.commands[1]).Scan(&eventCount, &outboxCount, &receiptCount); err != nil {
		t.Fatalf("db readback failed: %v", err)
	}
	if eventCount != 1 || outboxCount != 1 || receiptCount != 1 {
		t.Fatalf("duplicate side effects after Commit-unknown reconciliation: events=%d outbox=%d receipts=%d", eventCount, outboxCount, receiptCount)
	}
}

// TestM15_PoCEndToEndAutonomousPolicyRecovery drives M15-S01..S04 end-to-end:
// Baseline v1/Epoch40 -> Concurrent Root B Canary v2/Epoch41 -> Promote Both=v2/Epoch42
// -> Rollback Fault Recovery Both=v1/Epoch43 + stale rejection -> Outbox/Inbox idempotent delivery.
func TestM15_PoCEndToEndAutonomousPolicyRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	migrator, app1, appURL := openIsolatedPools(ctx, t)
	app2, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("unable to open second coordinator pool")
	}
	t.Cleanup(app2.Close)

	f := setupPoCFixture(ctx, t, migrator, app1, "m15e2e", 7)
	svc1 := buildRolloutService(t, app1, f)
	svc2 := buildRolloutService(t, app2, f)

	// M15-S01 Readback: Root A & Root B at v1 (baseline), Scope Activation Epoch 40.
	var initEpoch domain.Epoch
	var initMatches int
	if err := migrator.QueryRow(ctx, `SELECT s.activation_epoch, (SELECT count(*) FROM raw.roots WHERE scope_id=$1 AND effective_bundle_digest=$2 AND authorization_epoch=1) FROM raw.policy_scopes s WHERE s.scope_id=$1`,
		string(f.scope), string(f.baseline.Digest())).Scan(&initEpoch, &initMatches); err != nil || initEpoch != 40 || initMatches != 2 {
		t.Fatalf("M15-S01 baseline mismatch: epoch=%d rootMatches=%d err=%v", initEpoch, initMatches, err)
	}

	proposer := domain.ProposalContext{ProposerID: "candidate-author"}
	transitionProposer := domain.ProposalContext{ProposerID: "release-author"}
	propID := f.prefix + "_prop"
	if _, err := svc1.Propose(ctx, application.ProposeRequest{
		CommandID: f.commands[0], Nonce: "n-prop", Scope: f.scope, ProposalID: propID,
		ProposerID: proposer.ProposerID, BundleKeyID: "poc-key", Bundle: f.candidate,
		Signature: ed25519.Sign(f.key, f.candidate.SigningBytes()),
	}); err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	candidate := domain.DomainCandidate{
		Bundle: f.candidate, Tier: domain.TierG0, IssuerID: "issuer",
		ProposalID: propID, Nonce: "n-cand", CapabilityIDs: []string{"governance"},
	}
	msg, err := domain.DomainApprovalSigningBytes(candidate, f.kernelPin, proposer.ProposerID)
	if err != nil {
		t.Fatal(err)
	}
	approvals := []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, msg)}}

	// M15-S02: 2 Coordinators race StartCanary on Root B -> exactly 1 succeeds; Root A=v1, Root B=v2, Epoch=41.
	type canaryRes struct {
		err error
	}
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	ch := make(chan canaryRes, 2)
	for i, svc := range []*application.RolloutService{svc1, svc2} {
		cmd := f.commands[1+i]
		rid := f.rolloutID
		if i == 1 {
			rid = f.otherRID
		}
		go func(s *application.RolloutService, c string, r domain.RolloutID) {
			ready <- struct{}{}
			<-start
			_, e := s.StartCanary(ctx, application.StartCanaryRequest{
				CommandID: c, Nonce: "canary-" + c, Scope: f.scope, Rollout: r, Root: f.rootB,
				Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 1, ExpectedSecurityEpoch: f.security,
			}, proposer)
			ch <- canaryRes{err: e}
		}(svc, cmd, rid)
	}
	<-ready
	<-ready
	close(start)
	var winIdx int
	var okCount int
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("M15-S02 expected 1 winner, got %d", okCount)
	}
	_ = winIdx
	var activeRID string
	var epoch41 domain.Epoch
	var digestA, digestB string
	if err := migrator.QueryRow(ctx, `SELECT activation_epoch, live_rollout_id, (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$2), (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$3) FROM raw.policy_scopes WHERE scope_id=$1`,
		string(f.scope), string(f.rootA), string(f.rootB)).Scan(&epoch41, &activeRID, &digestA, &digestB); err != nil {
		t.Fatal(err)
	}
	if epoch41 != 41 || digestA != string(f.baseline.Digest()) || digestB != string(f.candidate.Digest()) {
		t.Fatalf("M15-S02 state mismatch: epoch=%d rootA=%s rootB=%s", epoch41, digestA, digestB)
	}

	// Verify SafetyGate & Authority isolation: Root A remains dispatchable at baseline v1 while Root B baseline grant is stale.
	gateTx, err := NewSafetyGateTransactor(app1)
	if err != nil {
		t.Fatal(err)
	}
	gate := application.NewSafetyGate(gateTx, "paddock.coordinator")
	if err := gate.CheckNewDispatch(ctx, f.scope, f.rootA); err != nil {
		t.Fatalf("Root A dispatch check failed during Root B Canary: %v", err)
	}
	authState := domain.AuthorityState{
		Scope:                f.scope,
		ScopeActivationEpoch: 41,
		SecurityEpoch:        f.security,
		Mode:                 domain.ScopeActive,
		DatabaseAvailable:    true,
		Roots: map[domain.RootID]domain.RootAuthority{
			f.rootA: {AuthorizationEpoch: 1, Policy: domain.PolicyBinding{Digest: f.baseline.Digest()}},
			f.rootB: {AuthorizationEpoch: 2, Policy: domain.PolicyBinding{Digest: f.candidate.Digest()}},
		},
	}
	if err := domain.Authorize(authState, domain.Grant{Root: f.rootA, Policy: domain.PolicyBinding{Digest: f.baseline.Digest()}, AuthorizationEpoch: 1, SecurityEpoch: f.security}); err != nil {
		t.Fatalf("Root A v1 grant rejected during Root B Canary: %v", err)
	}
	if err := domain.Authorize(authState, domain.Grant{Root: f.rootB, Policy: domain.PolicyBinding{Digest: f.baseline.Digest()}, AuthorizationEpoch: 1, SecurityEpoch: f.security}); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatalf("expected ErrStaleGrant for Root B v1 grant, got %v", err)
	}

	// M15-S03 Part 1: Promote -> both Root A and Root B become v2 at Epoch 42.
	promoteApproval := domain.RolloutTransitionApproval{
		Scope: f.scope, Roots: []domain.RootID{f.rootA, f.rootB}, ScopeEpoch: 41, SecurityEpoch: f.security,
		RootEpochs: map[domain.RootID]domain.Epoch{f.rootA: 1, f.rootB: 2}, RolloutID: domain.RolloutID(activeRID),
		RolloutState: domain.RolloutCanary, CandidateDigest: f.candidate.Digest(), KernelDigest: f.kernelPin,
		Tier: domain.TierG0, ProposerID: transitionProposer.ProposerID, ProposalID: propID, Nonce: "n-promote",
	}
	pm, err := promoteApproval.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	promoteApproval.Approvals = []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(f.key, pm)}}
	promoted, err := svc1.Promote(ctx, application.PromoteRequest{
		CommandID: f.commands[3], Nonce: "n-promote", Scope: f.scope, Rollout: domain.RolloutID(activeRID),
		ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: f.security,
		ExpectedRootEpochs: promoteApproval.RootEpochs, Candidate: candidate, CandidateApprovals: approvals, Approval: promoteApproval,
	}, proposer, transitionProposer)
	if err != nil || promoted.ScopeEpoch != 42 {
		t.Fatalf("M15-S03 Promote failed: res=%+v err=%v", promoted, err)
	}
	var epoch42 domain.Epoch
	var promotedA, promotedB string
	if err := migrator.QueryRow(ctx, `SELECT activation_epoch, (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$2), (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$3) FROM raw.policy_scopes WHERE scope_id=$1`,
		string(f.scope), string(f.rootA), string(f.rootB)).Scan(&epoch42, &promotedA, &promotedB); err != nil {
		t.Fatal(err)
	}
	if epoch42 != 42 || promotedA != string(f.candidate.Digest()) || promotedB != string(f.candidate.Digest()) {
		t.Fatalf("M15-S03 promoted state mismatch before rollback: epoch=%d rootA=%s rootB=%s", epoch42, promotedA, promotedB)
	}

	// M15-S03 Part 2: Fault-triggered Rollback -> both Roots revert to v1 at Epoch 43.
	rbRes, err := svc1.Rollback(ctx, application.RollbackRequest{
		CommandID: f.commands[4], Nonce: "n-rollback", Scope: f.scope, Rollout: domain.RolloutID(activeRID),
		ExpectedState: domain.RolloutMonitoring, ExpectedScopeEpoch: 42, ExpectedSecurityEpoch: f.security,
		ExpectedRootEpochs: map[domain.RootID]domain.Epoch{f.rootA: 2, f.rootB: 2},
	})
	if err != nil || rbRes.ScopeEpoch != 43 || rbRes.State != domain.RolloutRolledBack {
		t.Fatalf("M15-S03 Rollback failed: res=%+v err=%v", rbRes, err)
	}
	if err := migrator.QueryRow(ctx, `SELECT activation_epoch, (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$2), (SELECT effective_bundle_digest FROM raw.roots WHERE root_id=$3) FROM raw.policy_scopes WHERE scope_id=$1`,
		string(f.scope), string(f.rootA), string(f.rootB)).Scan(&epoch41, &digestA, &digestB); err != nil {
		t.Fatal(err)
	}
	if epoch41 != 43 || digestA != string(f.baseline.Digest()) || digestB != string(f.baseline.Digest()) {
		t.Fatalf("M15-S03 post-rollback mismatch: epoch=%d rootA=%s rootB=%s", epoch41, digestA, digestB)
	}
	// Stale epoch operation after rollback MUST fail.
	if _, err := svc1.Rollback(ctx, application.RollbackRequest{
		CommandID: f.commands[5], Nonce: "n-stale", Scope: f.scope, Rollout: domain.RolloutID(activeRID),
		ExpectedState: domain.RolloutMonitoring, ExpectedScopeEpoch: 42, ExpectedSecurityEpoch: f.security,
		ExpectedRootEpochs: map[domain.RootID]domain.Epoch{f.rootA: 2, f.rootB: 2},
	}); !errors.Is(err, port.ErrStaleWrite) {
		t.Fatalf("expected ErrStaleWrite for stale epoch operation, got %v", err)
	}

	// M15-S04: Idempotent Inbox delivery across simulated duplicate Outbox event delivery.
	inbox, err := NewPostgresConsumerInboxStore(app1)
	if err != nil {
		t.Fatal(err)
	}
	targetEvent := f.events[3] // RolloutPromoted event
	firstApply, err := inbox.ApplyEventOnce(ctx, f.consumerID, targetEvent)
	if err != nil || !firstApply {
		t.Fatalf("M15-S04 initial event apply failed: applied=%v err=%v", firstApply, err)
	}
	redeliveryApply, err := inbox.ApplyEventOnce(ctx, f.consumerID, targetEvent)
	if err != nil || redeliveryApply {
		t.Fatalf("M15-S04 duplicate redelivery must be deduplicated: applied=%v err=%v", redeliveryApply, err)
	}
	var projCount int
	if err := migrator.QueryRow(ctx, `SELECT processed_event_count FROM raw.event_consumer_projection WHERE consumer_id=$1`, f.consumerID).Scan(&projCount); err != nil || projCount != 1 {
		t.Fatalf("M15-S04 projection count mismatch: got %d want 1 err=%v", projCount, err)
	}
}
