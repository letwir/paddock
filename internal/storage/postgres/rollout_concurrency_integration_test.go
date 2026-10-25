//go:build integration && paddock_test && rollout_concurrency

package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SOURCE ONLY for M04-S03: running either test body requires separate exact
// approval against isolated paddock_test with the existing APIs installed.
// Compile offline with -run '^$'; this file never applies a migration.
const rolloutConcurrencyHelperEnv = "PADDOCK_ROLLOUT_CONCURRENCY_HELPER"

type rolloutConcurrencyInput struct {
	Prefix   string
	Security domain.Epoch
	Index    int
}

func (q rolloutConcurrencyInput) commandID() string {
	return fmt.Sprintf("%s_canary_%d", q.Prefix, q.Index)
}

func (q rolloutConcurrencyInput) rolloutID() domain.RolloutID {
	return domain.RolloutID(fmt.Sprintf("%s_rollout_%d", q.Prefix, q.Index))
}

type rolloutConcurrencyResult struct {
	PID       int
	CommandID string
	Outcome   string
	Result    application.StartCanaryResult
}

// Reconstruct immutable candidate bytes in each process; CanonicalBundle has
// private fields and must not be round-tripped through encoding/json.
func rolloutConcurrencyService(t *testing.T, app *pgxpool.Pool, prefix string) (*application.RolloutService, domain.CanonicalBundle, domain.DomainCandidate, []domain.DomainApproval) {
	t.Helper()
	bundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"rule":"candidate"}`, prefix)))
	if err != nil {
		t.Fatal("candidate construction failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	kernel := domain.KernelSnapshot{SchemaVersion: domain.KernelSnapshotSchema, Version: 1,
		Signers: []domain.KernelSigner{{ID: "signer", PublicKey: public}}, Thresholds: []domain.TierThreshold{{Tier: domain.TierG0, Threshold: 1}, {Tier: domain.TierG1, Threshold: 1}},
		Capabilities: []string{"governance"}, IssuerCeilings: []domain.IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"governance"}}}}
	pin, err := kernel.Digest()
	if err != nil {
		t.Fatal("kernel digest failed")
	}
	tx, err := NewRolloutTransactor(app)
	if err != nil {
		t.Fatal("rollout transactor construction failed")
	}
	safety, err := NewSafetyTransactor(app)
	if err != nil {
		t.Fatal("safety transactor construction failed")
	}
	// Reuse the existing application integration fixture's test-only key/LKG helpers.
	bundles := application.NewBundleRegistrationService(safety, rolloutIntegrationKey{public})
	service, err := application.NewRolloutService(tx, bundles, rolloutIntegrationLKG{}, kernel, pin)
	if err != nil {
		t.Fatal("rollout service construction failed")
	}
	candidate := domain.DomainCandidate{Bundle: bundle, Tier: domain.TierG0, IssuerID: "issuer", ProposalID: prefix + "_proposal", Nonce: "candidate-nonce", CapabilityIDs: []string{"governance"}}
	message, err := domain.DomainApprovalSigningBytes(candidate, pin, "candidate-author")
	if err != nil {
		t.Fatal("candidate approval construction failed")
	}
	return service, bundle, candidate, []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(key, message)}}
}

func rolloutConcurrencyPool(t *testing.T, ctx context.Context, appRole bool) *pgxpool.Pool {
	t.Helper()
	name, role := "PADDOCK_DB_URL", "paddock_migrator"
	if appRole {
		name, role = "PADDOCK_APP_DB_URL", "paddock_app"
	}
	url := os.Getenv(name)
	if url == "" {
		t.Fatal("isolated database configuration required")
	}
	pool, err := openPullPool(ctx, url, appRole)
	if err != nil {
		t.Fatal("cannot open concurrency fixture pool")
	}
	t.Cleanup(pool.Close)
	var db, user, session string
	if err := pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != role || session != role {
		t.Fatal("refusing unexpected database/session identity")
	}
	return pool
}

func TestRolloutScopeConflictProcessHelper(t *testing.T) {
	if os.Getenv(rolloutConcurrencyHelperEnv) != "1" {
		t.Skip("parent-controlled helper only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	input := bufio.NewReader(os.Stdin)
	line, err := input.ReadString('\n')
	if err != nil {
		t.Fatal("helper configuration pipe failed")
	}
	var q rolloutConcurrencyInput
	if err := json.Unmarshal([]byte(line), &q); err != nil || q.Prefix == "" || q.Index < 0 || q.Index > 1 {
		t.Fatal("invalid helper configuration")
	}
	// Every helper opens its own app-role pool before READY; no pool/connection
	// or migrator session is shared with the parent or the other OS process.
	app := rolloutConcurrencyPool(t, ctx, true)
	service, _, candidate, approvals := rolloutConcurrencyService(t, app, q.Prefix)
	request := application.StartCanaryRequest{CommandID: q.commandID(), Nonce: "canary-nonce", Scope: domain.ScopeID(q.Prefix + "_scope"), Rollout: q.rolloutID(), Root: domain.RootID(q.Prefix + "_b"), Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: q.Security}
	if _, err := fmt.Fprintln(os.Stdout, "READY"); err != nil {
		t.Fatal("helper READY pipe failed")
	}
	if line, err := input.ReadString('\n'); err != nil || line != "GO\n" {
		t.Fatal("helper GO pipe failed")
	}
	result, err := service.StartCanary(ctx, request, domain.ProposalContext{ProposerID: "candidate-author"})
	out := rolloutConcurrencyResult{PID: os.Getpid(), CommandID: q.commandID(), Outcome: "COMMITTED", Result: result}
	if err != nil {
		var failure *application.CommandFailure
		// FailureBusy can also mean a lock timeout. Only the locked occupied-slot
		// outcome counts; arbitrary failures, stale snapshots and uncertainty fail.
		if !errors.As(err, &failure) || failure.Kind != application.FailureBusy || failure.Cause == nil || failure.Cause.Error() != "scope active rollout slot is occupied" {
			t.Fatal("StartCanary failed without the competing slot outcome")
		}
		out.Outcome = "BUSY"
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		t.Fatal("helper result pipe failed")
	}
}

type rolloutConcurrencyChild struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	waited bool
}

func startRolloutConcurrencyChild(t *testing.T, ctx context.Context, q rolloutConcurrencyInput) *rolloutConcurrencyChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate helper test binary")
	}
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, binary, "-test.run=^TestRolloutScopeConflictProcessHelper$", "-test.count=1", "-test.timeout=45s")
	// Do not pass fixture-principal configuration to helpers or print DB errors.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "PADDOCK_DB_URL=") && !strings.HasPrefix(entry, rolloutConcurrencyHelperEnv+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, rolloutConcurrencyHelperEnv+"=1")
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal("cannot open helper stdin")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		stdin.Close()
		t.Fatal("cannot open helper stdout")
	}
	child := &rolloutConcurrencyChild{cmd: cmd, stdin: stdin, stdout: bufio.NewScanner(stdout)}
	t.Cleanup(func() {
		cancel()
		stdin.Close()
		if cmd.Process != nil && !child.waited {
			// Cancellation kills a helper even if blocked waiting for GO. Wait
			// reaps it before fixture cleanup runs (Cleanup is last-in first-out).
			if err := cmd.Wait(); err != nil && ctx.Err() == nil {
				t.Error("helper aborted before successful completion")
			}
		}
		stdout.Close()
	})
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot launch helper process")
	}
	if err := json.NewEncoder(stdin).Encode(q); err != nil {
		t.Fatal("cannot send helper configuration")
	}
	return child
}

func TestRolloutScopeConflictTwoProcessesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	migrator := rolloutConcurrencyPool(t, ctx, false)
	app := rolloutConcurrencyPool(t, ctx, true)
	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("fixture ID generation failed")
	}
	prefix := "it_rollout_race_" + hex.EncodeToString(suffix)
	scope := domain.ScopeID(prefix + "_scope")
	rootA, rootB := domain.RootID(prefix+"_a"), domain.RootID(prefix+"_b")
	service, bundle, _, _ := rolloutConcurrencyService(t, app, prefix)
	baseline, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"rule":"baseline"}`, prefix)))
	if err != nil {
		t.Fatal("baseline construction failed")
	}
	seed, err := migrator.Begin(ctx)
	if err != nil {
		t.Fatal("fixture transaction failed")
	}
	defer seed.Rollback(context.Background())
	var collision bool
	if err := seed.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2)`, string(baseline.Digest()), string(bundle.Digest())).Scan(&collision); err != nil || collision {
		t.Fatal("fixture digest collision")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,$3,'rollout-test',$4)`, []any{string(baseline.Digest()), baseline.CanonicalBytes(), baseline.SchemaVersion(), ed25519.Sign(key, baseline.SigningBytes())}},
		{`INSERT INTO raw.policy_scopes(scope_id,activation_epoch,baseline_bundle_digest,mode) VALUES($1,40,$2,'ACTIVE')`, []any{string(scope), string(baseline.Digest())}},
		{`INSERT INTO raw.roots(root_id,scope_id,authorization_epoch,effective_bundle_digest,safe_baseline) VALUES($1,$3,3,$4,false),($2,$3,5,$4,false)`, []any{string(rootA), string(rootB), string(scope), string(baseline.Digest())}},
	} {
		if _, err := seed.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("fixture insert failed")
		}
	}
	commands := []string{prefix + "_propose", (rolloutConcurrencyInput{Prefix: prefix, Index: 0}).commandID(), (rolloutConcurrencyInput{Prefix: prefix, Index: 1}).commandID()}
	rollouts := []string{string((rolloutConcurrencyInput{Prefix: prefix, Index: 0}).rolloutID()), string((rolloutConcurrencyInput{Prefix: prefix, Index: 1}).rolloutID())}
	events := []string{"rollout/" + commands[0], "rollout/" + commands[1], "rollout/" + commands[2]}
	// Register before Commit so an uncertain fixture commit still gets cleanup.
	// Only named fixture rows are removed; global Security Epoch is never rewound.
	t.Cleanup(func() {
		cleanCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		tx, err := migrator.Begin(cleanCtx)
		if err != nil {
			t.Error("cleanup begin failed")
			return
		}
		defer tx.Rollback(cleanCtx)
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, []any{events}},
			{`DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])`, []any{events}},
			{`DELETE FROM raw.command_receipts WHERE command_id=ANY($1::text[])`, []any{commands}},
			{`UPDATE raw.policy_scopes SET live_rollout_id=NULL WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.rollout_targets WHERE rollout_id=ANY($1::text[])`, []any{rollouts}},
			{`DELETE FROM raw.policy_rollouts WHERE rollout_id=ANY($1::text[])`, []any{rollouts}},
			{`DELETE FROM raw.roots WHERE root_id=ANY($1::text[]) AND scope_id=$2`, []any{[]string{string(rootA), string(rootB)}, string(scope)}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2`, []any{string(baseline.Digest()), string(bundle.Digest())}},
		} {
			if _, err := tx.Exec(cleanCtx, q.sql, q.args...); err != nil {
				t.Error("named fixture cleanup failed")
				return
			}
		}
		if err := tx.Commit(cleanCtx); err != nil {
			t.Error("cleanup commit outcome unknown")
		}
	})
	if err := seed.Commit(ctx); err != nil {
		t.Fatal("fixture commit outcome unknown")
	}
	var security domain.Epoch
	if err := migrator.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&security); err != nil {
		t.Fatal("read fixture Security Epoch failed")
	}
	if _, err := service.Propose(ctx, application.ProposeRequest{CommandID: commands[0], Nonce: "proposal-nonce", Scope: scope, ProposalID: prefix + "_proposal", ProposerID: "candidate-author", BundleKeyID: "rollout-test", Bundle: bundle, Signature: ed25519.Sign(key, bundle.SigningBytes())}); err != nil {
		t.Fatal("candidate proposal failed")
	}

	children := make([]*rolloutConcurrencyChild, 2)
	for i := range children {
		children[i] = startRolloutConcurrencyChild(t, ctx, rolloutConcurrencyInput{Prefix: prefix, Security: security, Index: i})
	}
	// Parent-controlled READY/GO pipe barrier: both independent processes must be
	// ready before either receives GO. No timing sleeps or goroutine contenders.
	for _, child := range children {
		if !child.stdout.Scan() || child.stdout.Text() != "READY" {
			t.Fatal("helper did not reach READY barrier")
		}
	}
	for _, child := range children {
		if _, err := io.WriteString(child.stdin, "GO\n"); err != nil {
			t.Fatal("cannot release helper GO barrier")
		}
		if err := child.stdin.Close(); err != nil {
			t.Fatal("cannot close helper input")
		}
	}
	results := make([]rolloutConcurrencyResult, 2)
	committed, busy, winner := 0, 0, -1
	for i, child := range children {
		if !child.stdout.Scan() || json.Unmarshal(child.stdout.Bytes(), &results[i]) != nil {
			t.Fatal("invalid helper result")
		}
		// Drain testing's trailing PASS line before Wait closes StdoutPipe.
		for child.stdout.Scan() {
		}
		if err := child.stdout.Err(); err != nil {
			t.Fatal("helper result pipe failed")
		}
		err := child.cmd.Wait()
		child.waited = true
		if err != nil {
			t.Fatal("helper process failed")
		}
		r := results[i]
		if r.PID != child.cmd.Process.Pid || r.PID == os.Getpid() || r.CommandID != commands[i+1] {
			t.Fatal("helper process or command identity mismatch")
		}
		switch r.Outcome {
		case "COMMITTED":
			committed++
			winner = i
			if r.Result.CommandID != commands[i+1] || r.Result.State != domain.RolloutCanary || r.Result.ScopeEpoch != 41 || r.Result.RootEpoch != 6 {
				t.Fatal("unexpected committed transition")
			}
		case "BUSY":
			busy++
		default:
			t.Fatal("unexpected helper outcome")
		}
	}
	if results[0].PID == results[1].PID || commands[1] == commands[2] || committed != 1 || busy != 1 {
		t.Fatal("expected two distinct processes/commands, exactly one commit and one occupied-slot failure")
	}
	winningRollout := domain.RolloutID(rollouts[winner])
	// App-visible state must point to the successful process's Rollout. Inspection
	// uses existing transaction capabilities, not any new product API.
	transactor, err := NewRolloutTransactor(app)
	if err != nil {
		t.Fatal("observation transactor failed")
	}
	err = transactor.WithinRolloutTransaction(ctx, func(tx port.RolloutTx) error {
		snap, err := tx.LockScope(ctx, scope)
		if err != nil {
			return err
		}
		if snap.LiveRolloutID == nil || *snap.LiveRolloutID != winningRollout || snap.ActivationEpoch != 41 || snap.SecurityEpoch != security || snap.Roots[rootB].AuthorizationEpoch != 6 || snap.Roots[rootB].Policy.Digest != bundle.Digest() || snap.Roots[rootA].AuthorizationEpoch != 3 {
			return errors.New("app Scope observation mismatch")
		}
		r, err := tx.LockRollout(ctx, scope, winningRollout)
		if err != nil {
			return err
		}
		if r.ID != winningRollout || r.Scope != scope || r.State != domain.RolloutCanary || r.TargetRoot == nil || *r.TargetRoot != rootB {
			return errors.New("app Rollout observation mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal("app-visible winner observation failed")
	}
	var active, slots, total, receipts, outbox int
	var live string
	if err := migrator.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM raw.policy_rollouts WHERE scope_id=$1 AND state IN ('CANARY','MONITORING','ROLLING_BACK')),
 (SELECT count(*) FROM raw.policy_scopes WHERE scope_id=$1 AND live_rollout_id IS NOT NULL),
 (SELECT count(*) FROM raw.policy_rollouts WHERE scope_id=$1),
 (SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($2::text[]) AND status='SUCCEEDED'),
 (SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($3::text[])),
 live_rollout_id FROM raw.policy_scopes WHERE scope_id=$1`, string(scope), commands[1:], events[1:]).Scan(&active, &slots, &total, &receipts, &outbox, &live); err != nil || active != 1 || slots != 1 || total != 1 || receipts != 1 || outbox != 1 || live != string(winningRollout) {
		t.Fatal("persisted single active Rollout/Scope slot invariant failed")
	}
}
