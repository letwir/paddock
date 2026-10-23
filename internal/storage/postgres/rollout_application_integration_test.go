//go:build integration && paddock_test

package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

// SOURCE ONLY for M04-S01, M07-S03 and M07-S07. Compile checks are offline; running this body needs
// separate exact approval. No migration is applied here. Both pools must already
// point at isolated paddock_test with governance_rollout_api.sql installed.
// All signing keys below are local test-only seeds, never external keys.
type rolloutIntegrationKey struct{ public ed25519.PublicKey }

func (k rolloutIntegrationKey) ResolveBundleKey(context.Context, string) (application.BundleSigningKey, error) {
	return application.BundleSigningKey{KeyID: "rollout-test", PublicKey: k.public, ValidFrom: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

type rolloutIntegrationLKG struct{}

func (rolloutIntegrationLKG) VerifyLKG(_ context.Context, d domain.Digest) (domain.LKGAssessment, error) {
	return domain.LKGAssessment{Digest: d, Status: domain.LKGUsable}, nil
}

func TestRolloutApplicationAppOnlyIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	migratorURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if migratorURL == "" || appURL == "" {
		t.Fatal("isolated migrator and app connection configuration required")
	}
	migrator, err := openPullPool(ctx, migratorURL, false)
	if err != nil {
		t.Fatal("cannot open fixture pool")
	}
	t.Cleanup(migrator.Close)
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("cannot open app pool")
	}
	t.Cleanup(app.Close)
	for _, entry := range []struct {
		pool *pgxpool.Pool
		role string
	}{{migrator, "paddock_migrator"}, {app, "paddock_app"}} {
		var db, user, session string
		if err := entry.pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != entry.role || session != entry.role {
			t.Fatal("refusing unexpected database/session identity")
		}
	}
	// Inspect both table and column ACLs; app needs only EXECUTE on these APIs.
	var badACL bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='raw' AND c.relname IN ('policy_rollouts','rollout_targets')
   AND (pg_catalog.has_table_privilege('paddock_app',c.oid,'INSERT,UPDATE,DELETE')
    OR pg_catalog.has_any_column_privilege('paddock_app',c.oid,'INSERT,UPDATE')))
 `).Scan(&badACL); err != nil || badACL {
		t.Fatal("app has forbidden direct DML privileges")
	}
	for _, signature := range []string{
		"raw.safety_create_rollout(text,text,bigint,bigint,json)",
		"raw.safety_cas_rollout(text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text)",
		"raw.safety_cas_rollout_target(text,text,bigint,text,text,text,text,text,bigint)",
	} {
		var valid bool
		if err := migrator.QueryRow(ctx, `SELECT p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']::text[]
   AND r.rolname='paddock_migrator' AND pg_catalog.has_function_privilege('paddock_app',p.oid,'EXECUTE')
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE a.privilege_type='EXECUTE' AND a.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='paddock_app')))
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE p.oid=pg_catalog.to_regprocedure($1)`, signature).Scan(&valid); err != nil || !valid {
			t.Fatal("invalid rollout function owner/path/ACL")
		}
	}
	suffix := make([]byte, 12)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal("fixture ID generation failed")
	}
	prefix := "it_rollout_" + hex.EncodeToString(suffix)
	scope := domain.ScopeID(prefix + "_scope")
	rootA, rootB := domain.RootID(prefix+"_a"), domain.RootID(prefix+"_b")
	rid := domain.RolloutID(prefix + "_rollout")
	blockedRID := domain.RolloutID(prefix + "_blocked_rollout")
	workA, workB, expiredWork := prefix+"_work_a", prefix+"_work_b", prefix+"_work_expired"
	workIDs := []string{workA, workB, expiredWork}
	baseline, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"rule":"baseline"}`, prefix)))
	if err != nil {
		t.Fatal(err)
	}
	candidateBundle, err := domain.NewCanonicalBundle(domain.BundleSchemaVersion, []byte(fmt.Sprintf(`{"fixture":%q,"rule":"candidate"}`, prefix)))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	// Seed baseline/Scope/Roots and exact WorkOrders as migrator, never as app.
	seed, err := migrator.Begin(ctx)
	if err != nil {
		t.Fatal("fixture transaction failed")
	}
	defer seed.Rollback(context.Background())
	var collision bool
	if err := seed.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2)`, string(baseline.Digest()), string(candidateBundle.Digest())).Scan(&collision); err != nil || collision {
		t.Fatal("fixture digest collision")
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,$3,'rollout-test',$4)`, []any{string(baseline.Digest()), baseline.CanonicalBytes(), baseline.SchemaVersion(), ed25519.Sign(key, baseline.SigningBytes())}},
		{`INSERT INTO raw.policy_scopes(scope_id,activation_epoch,baseline_bundle_digest,mode) VALUES($1,40,$2,'ACTIVE')`, []any{string(scope), string(baseline.Digest())}},
		{`INSERT INTO raw.roots(root_id,scope_id,authorization_epoch,effective_bundle_digest,safe_baseline) VALUES($1,$3,3,$4,false),($2,$3,5,$4,false)`, []any{string(rootA), string(rootB), string(scope), string(baseline.Digest())}},
		{`INSERT INTO raw.work_orders(work_order_id,root_id,parent_id) VALUES($1,$4,NULL),($2,$5,NULL),($3,$5,$2)`, []any{workA, workB, expiredWork, string(rootA), string(rootB)}},
	} {
		if _, err := seed.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal("fixture insert failed")
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal("fixture commit outcome unknown")
	}
	commands := []string{prefix + "_propose", prefix + "_canary", prefix + "_promote", prefix + "_rollback", prefix + "_blocked_canary", prefix + "_competing_rollback", prefix + "_stop"}
	events := make([]string, len(commands))
	for i, id := range commands {
		events[i] = "rollout/" + id
	}
	events[6] = "safety/" + commands[6]
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
			{`DELETE FROM raw.rollout_targets WHERE rollout_id=ANY($1::text[])`, []any{[]string{string(rid), string(blockedRID)}}},
			{`DELETE FROM raw.policy_rollouts WHERE rollout_id=ANY($1::text[])`, []any{[]string{string(rid), string(blockedRID)}}},
			{`DELETE FROM raw.work_order_leases WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_order_pull_slots WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_order_attempts WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.work_orders WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{`DELETE FROM raw.roots WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id=$1`, []any{string(scope)}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2`, []any{string(baseline.Digest()), string(candidateBundle.Digest())}},
		} {
			if _, err := tx.Exec(cleanCtx, q.sql, q.args...); err != nil {
				t.Error("fixture cleanup failed")
				return
			}
		}
		if err := tx.Commit(cleanCtx); err != nil {
			t.Error("cleanup commit outcome unknown")
			return
		}
		for _, q := range []struct {
			name string
			sql  string
			args []any
		}{
			{"outbox", `SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($1::text[])`, []any{events}},
			{"events", `SELECT count(*) FROM raw.domain_events WHERE event_id=ANY($1::text[])`, []any{events}},
			{"receipts", `SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($1::text[])`, []any{commands}},
			{"targets", `SELECT count(*) FROM raw.rollout_targets WHERE rollout_id=ANY($1::text[])`, []any{[]string{string(rid), string(blockedRID)}}},
			{"rollouts", `SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id=ANY($1::text[])`, []any{[]string{string(rid), string(blockedRID)}}},
			{"leases", `SELECT count(*) FROM raw.work_order_leases WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{"slots", `SELECT count(*) FROM raw.work_order_pull_slots WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{"attempts", `SELECT count(*) FROM raw.work_order_attempts WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{"work_orders", `SELECT count(*) FROM raw.work_orders WHERE work_order_id=ANY($1::text[])`, []any{workIDs}},
			{"roots", `SELECT count(*) FROM raw.roots WHERE scope_id=$1`, []any{string(scope)}},
			{"scope", `SELECT count(*) FROM raw.policy_scopes WHERE scope_id=$1`, []any{string(scope)}},
			{"bundles", `SELECT count(*) FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2`, []any{string(baseline.Digest()), string(candidateBundle.Digest())}},
		} {
			var remaining int
			if err := migrator.QueryRow(cleanCtx, q.sql, q.args...).Scan(&remaining); err != nil || remaining != 0 {
				t.Errorf("post-cleanup %s: remaining=%d err=%v", q.name, remaining, err)
			}
		}
	})
	// Real leases are app-issued using the existing configured/READY lifecycle.
	// Expire only the real expired fixture after issuance, preserving heartbeat_at < expires_at.
	bindings := make(map[domain.RootID]domain.AttemptLeaseBinding)
	var expiredBinding domain.AttemptLeaseBinding
	for _, entry := range []struct {
		work string
		root domain.RootID
		ttl  string
	}{
		{workA, rootA, "10 minutes"}, {workB, rootB, "10 minutes"}, {expiredWork, rootB, "10 minutes"},
	} {
		for _, query := range []string{`SELECT raw.configure_work_order_capabilities($1,'[]'::jsonb)`, `SELECT raw.mark_work_order_pull_ready($1)`} {
			var ok bool
			if err := app.QueryRow(ctx, query, entry.work).Scan(&ok); err != nil || !ok {
				t.Fatal("app lease fixture configure/ready failed")
			}
		}
		binding := domain.AttemptLeaseBinding{WorkOrderID: domain.WorkOrderID(entry.work), AttemptID: domain.AttemptID(entry.work + "_attempt"), WorkerID: domain.WorkerID(entry.work + "_worker"), SessionID: domain.SessionID(entry.work + "_session")}
		var attempt, slot string
		var expires time.Time
		if err := app.QueryRow(ctx, `SELECT attempt_id,slot_id,lease_epoch,expires_at FROM raw.issue_work_order_lease($1,$2,$3,$4,$5,'[]'::jsonb,'[]'::jsonb,$6::interval)`, entry.work, string(binding.WorkerID), string(binding.SessionID), string(binding.AttemptID), entry.work+"_slot", entry.ttl).Scan(&attempt, &slot, &binding.LeaseEpoch, &expires); err != nil || attempt != string(binding.AttemptID) || slot != entry.work+"_slot" || binding.LeaseEpoch != 1 {
			t.Fatal("app lease fixture issue failed")
		}
		if entry.work == expiredWork {
			updated, err := migrator.Exec(ctx, `UPDATE raw.work_order_leases SET expires_at = heartbeat_at + interval '1 microsecond' WHERE work_order_id=$1 AND attempt_id=$2 AND lease_epoch=$3`, entry.work, string(binding.AttemptID), binding.LeaseEpoch)
			if err != nil || updated.RowsAffected() != 1 {
				t.Fatal("expire exact lease fixture failed")
			}
			expiredBinding = binding
		} else {
			bindings[entry.root] = binding
		}
	}
	authorization := func(grant domain.Grant) domain.HighRiskAuthorization {
		return domain.HighRiskAuthorization{Grant: grant, Lease: bindings[grant.Root]}
	}
	gateTransactor, err := NewSafetyGateTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	transactor, err := NewRolloutTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	safety, err := NewSafetyTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	bundles := application.NewBundleRegistrationService(safety, rolloutIntegrationKey{public})
	kernel := domain.KernelSnapshot{SchemaVersion: domain.KernelSnapshotSchema, Version: 1,
		Signers: []domain.KernelSigner{{ID: "signer", PublicKey: public}}, Thresholds: []domain.TierThreshold{{Tier: domain.TierG0, Threshold: 1}, {Tier: domain.TierG1, Threshold: 1}},
		Capabilities: []string{"governance"}, IssuerCeilings: []domain.IssuerCeiling{{IssuerID: "issuer", Capabilities: []string{"governance"}}}}
	pin, err := kernel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	service, err := application.NewRolloutService(transactor, bundles, rolloutIntegrationLKG{}, kernel, pin)
	if err != nil {
		t.Fatal(err)
	}
	var security domain.Epoch
	if err := migrator.QueryRow(ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&security); err != nil {
		t.Fatal("read fixture Security Epoch failed")
	}
	candidateProposer, transitionProposer := domain.ProposalContext{ProposerID: "candidate-author"}, domain.ProposalContext{ProposerID: "release-author"}
	proposalID := prefix + "_proposal"
	if _, err := service.Propose(ctx, application.ProposeRequest{CommandID: commands[0], Nonce: "proposal-nonce", Scope: scope, ProposalID: proposalID, ProposerID: candidateProposer.ProposerID, BundleKeyID: "rollout-test", Bundle: candidateBundle, Signature: ed25519.Sign(key, candidateBundle.SigningBytes())}); err != nil {
		t.Fatal(err)
	}
	candidate := domain.DomainCandidate{Bundle: candidateBundle, Tier: domain.TierG0, IssuerID: "issuer", ProposalID: proposalID, Nonce: "candidate-nonce", CapabilityIDs: []string{"governance"}}
	message, err := domain.DomainApprovalSigningBytes(candidate, pin, candidateProposer.ProposerID)
	if err != nil {
		t.Fatal(err)
	}
	approvals := []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(key, message)}}
	if !t.Run("creation blocks concurrent Security Epoch advance", func(t *testing.T) {
		// Keep two app transactions open concurrently. Roll back both, including
		// on the old KEY SHARE bug, so this probe never commits a global epoch.
		creator, err := app.Begin(ctx)
		if err != nil {
			t.Fatal("creation lock probe transaction failed")
		}
		defer creator.Rollback(context.Background())
		payload, err := json.Marshal([]rolloutCreateTarget{
			{RootID: string(rootA), Target: false, BaselineDigest: string(baseline.Digest()), CandidateDigest: string(candidateBundle.Digest()), BaseRootEpoch: 3},
			{RootID: string(rootB), Target: true, BaselineDigest: string(baseline.Digest()), CandidateDigest: string(candidateBundle.Digest()), BaseRootEpoch: 5},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := creator.Exec(ctx, `SELECT raw.safety_create_rollout($1,$2,40,$3,$4::json)`, string(rid), string(scope), security, string(payload)); err != nil {
			t.Fatal("creation lock probe failed")
		}
		advance, err := app.Begin(ctx)
		if err != nil {
			t.Fatal("epoch lock probe transaction failed")
		}
		defer advance.Rollback(context.Background())
		if _, err := advance.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
			t.Fatal("epoch lock probe timeout setup failed")
		}
		var updated bool
		err = advance.QueryRow(ctx, `SELECT raw.safety_cas_security_epoch($1,$2)`, security, security+1).Scan(&updated)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("epoch advance did not wait for creation: updated=%v expected lock timeout", updated)
		}
	}) {
		t.Fatal("Security Epoch serialization probe failed")
	}
	start := application.StartCanaryRequest{CommandID: commands[1], Nonce: "canary-nonce", Scope: scope, Rollout: rid, Root: rootB, Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 40, ExpectedRootEpoch: 5, ExpectedSecurityEpoch: security}
	first, err := service.StartCanary(ctx, start, candidateProposer)
	if err != nil || first.ScopeEpoch != 41 || first.RootEpoch != 6 {
		t.Fatalf("Canary: %+v err=%v", first, err)
	}
	// Do not repair application metadata from this persistence fixture. This
	// assertion also exposes a service that forgets to set its live Scope slot.
	var liveCanary bool
	if err := migrator.QueryRow(ctx, `SELECT live_rollout_id IS NOT DISTINCT FROM $2 FROM raw.policy_scopes WHERE scope_id=$1`, string(scope), string(rid)).Scan(&liveCanary); err != nil || !liveCanary {
		t.Fatal("StartCanary did not persist the live Rollout ID")
	}
	replay, err := service.StartCanary(ctx, start, candidateProposer)
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatal("Canary receipt replay failed")
	}
	// The PoC Gateway boundary is a fresh app-only transaction per check,
	// not a deployed network Gateway or elimination of external-action TOCTOU.
	gate := application.NewSafetyGate(gateTransactor)
	baselinePolicy := domain.PolicyBinding{Digest: baseline.Digest()}
	grantA := domain.Grant{Root: rootA, Policy: baselinePolicy, AuthorizationEpoch: 3, SecurityEpoch: security}
	grantB := domain.Grant{Root: rootB, Policy: baselinePolicy, AuthorizationEpoch: 5, SecurityEpoch: security}
	if err := gate.CheckHighRiskAction(ctx, scope, authorization(grantA)); err != nil {
		t.Fatalf("Root B Canary invalidated Root A baseline/v1 grant at epoch 3: %v", err)
	}
	if err := gate.CheckHighRiskAction(ctx, scope, authorization(grantB)); !errors.Is(err, domain.ErrStaleGrant) {
		t.Fatalf("Root B baseline/v1 grant at epoch 5 after Canary: got %v, want ErrStaleGrant", err)
	}
	approval := domain.RolloutTransitionApproval{Scope: scope, Roots: []domain.RootID{rootA, rootB}, ScopeEpoch: 41, SecurityEpoch: security, RootEpochs: map[domain.RootID]domain.Epoch{rootA: 3, rootB: 6}, RolloutID: rid, RolloutState: domain.RolloutCanary, CandidateDigest: candidateBundle.Digest(), KernelDigest: pin, Tier: domain.TierG0, ProposerID: transitionProposer.ProposerID, ProposalID: proposalID, Nonce: "promote-nonce"}
	message, err = approval.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	approval.Approvals = []domain.DomainApproval{{SignerID: "signer", Signature: ed25519.Sign(key, message)}}
	promote := application.PromoteRequest{CommandID: commands[2], Nonce: approval.Nonce, Scope: scope, Rollout: rid, ExpectedState: domain.RolloutCanary, ExpectedScopeEpoch: 41, ExpectedSecurityEpoch: security, ExpectedRootEpochs: approval.RootEpochs, Candidate: candidate, CandidateApprovals: approvals, Approval: approval}
	var dbClockBeforePromote, dbClockAfterPromote time.Time
	if err := migrator.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbClockBeforePromote); err != nil {
		t.Fatal("read database clock before Promote failed")
	}
	promoted, err := service.Promote(ctx, promote, candidateProposer, transitionProposer)
	if err != nil || promoted.ScopeEpoch != 42 {
		t.Fatalf("Promote: %+v err=%v", promoted, err)
	}
	if err := migrator.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbClockAfterPromote); err != nil {
		t.Fatal("read database clock after Promote failed")
	}
	var promotedEpoch domain.Epoch
	var promotedState string
	var promotedLiveID string
	if err := migrator.QueryRow(ctx, `SELECT activation_epoch,live_rollout_id FROM raw.policy_scopes WHERE scope_id=$1`, string(scope)).Scan(&promotedEpoch, &promotedLiveID); err != nil {
		t.Fatal("read promoted Scope state failed")
	}
	if err := migrator.QueryRow(ctx, `SELECT state FROM raw.policy_rollouts WHERE rollout_id=$1`, string(rid)).Scan(&promotedState); err != nil || promotedEpoch != 42 || promotedState != string(domain.RolloutMonitoring) || promotedLiveID != string(rid) {
		t.Fatalf("Promote persisted Scope/active slot mismatch: epoch=%d state=%q live=%q err=%v", promotedEpoch, promotedState, promotedLiveID, err)
	}
	var monitoringStarted, monitoringLastObserved, observationDeadline time.Time
	var holdBudget time.Duration
	var monitoringDecision string
	var decisionRevision int64
	if err := migrator.QueryRow(ctx, `SELECT monitoring_started_at,monitoring_last_observed_at,observation_deadline,hold_budget,monitoring_decision,decision_revision FROM raw.policy_rollouts WHERE rollout_id=$1`, string(rid)).Scan(&monitoringStarted, &monitoringLastObserved, &observationDeadline, &holdBudget, &monitoringDecision, &decisionRevision); err != nil {
		t.Fatalf("Promote monitoring window readback: %v", err)
	}
	if monitoringStarted.IsZero() || monitoringStarted.Before(dbClockBeforePromote) || monitoringStarted.After(dbClockAfterPromote) || !monitoringLastObserved.Equal(monitoringStarted) || !observationDeadline.Equal(monitoringStarted.Add(168*time.Hour)) || holdBudget != 24*time.Hour || monitoringDecision != "" || decisionRevision != 0 {
		t.Fatalf("Promote monitoring window mismatch: started=%s last_observed=%s deadline=%s hold_budget=%s decision=%q revision=%d", monitoringStarted, monitoringLastObserved, observationDeadline, holdBudget, monitoringDecision, decisionRevision)
	}
	var badPromotedRoots bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.roots WHERE scope_id=$1 AND (effective_bundle_digest<>$2 OR safe_baseline OR authorization_epoch<>CASE WHEN root_id=$3 THEN 4 ELSE 6 END))`, string(scope), string(candidateBundle.Digest()), string(rootA)).Scan(&badPromotedRoots); err != nil || badPromotedRoots {
		t.Fatalf("Promote did not apply candidate to both Roots: bad=%v err=%v", badPromotedRoots, err)
	}
	blocked := application.StartCanaryRequest{CommandID: commands[4], Nonce: "blocked-canary-nonce", Scope: scope, Rollout: blockedRID, Root: rootA, Candidate: candidate, Approvals: approvals, ExpectedScopeEpoch: 42, ExpectedRootEpoch: 4, ExpectedSecurityEpoch: security}
	_, blockedErr := service.StartCanary(ctx, blocked, candidateProposer)
	var commandFailure *application.CommandFailure
	if !errors.As(blockedErr, &commandFailure) || commandFailure.Kind != application.FailureBusy {
		t.Fatalf("StartCanary during MONITORING must return typed BUSY, got %v", blockedErr)
	}
	var unchangedEpoch domain.Epoch
	var unchangedLive string
	if err := migrator.QueryRow(ctx, `SELECT activation_epoch,live_rollout_id FROM raw.policy_scopes WHERE scope_id=$1`, string(scope)).Scan(&unchangedEpoch, &unchangedLive); err != nil || unchangedEpoch != 42 || unchangedLive != string(rid) {
		t.Fatalf("BUSY StartCanary changed active Scope slot: epoch=%d live=%q err=%v", unchangedEpoch, unchangedLive, err)
	}
	var blockedRollouts, blockedTargets, blockedEvents int
	if err := migrator.QueryRow(ctx, `SELECT (SELECT count(*) FROM raw.policy_rollouts WHERE rollout_id=$1),(SELECT count(*) FROM raw.rollout_targets WHERE rollout_id=$1),(SELECT count(*) FROM raw.domain_events WHERE event_id=$2)`, string(blockedRID), events[4]).Scan(&blockedRollouts, &blockedTargets, &blockedEvents); err != nil || blockedRollouts != 0 || blockedTargets != 0 || blockedEvents != 0 {
		t.Fatalf("BUSY StartCanary created fixture rows: rollouts=%d targets=%d events=%d err=%v", blockedRollouts, blockedTargets, blockedEvents, err)
	}
	activeRows, err := migrator.Query(ctx, `SELECT rollout_id,state FROM raw.policy_rollouts WHERE scope_id=$1 AND state IN ('CANARY','MONITORING','ROLLING_BACK')`, string(scope))
	if err != nil {
		t.Fatalf("read active Scope rollouts failed: %v", err)
	}
	defer activeRows.Close()
	var activeCount int
	var activeRID, activeState string
	for activeRows.Next() {
		activeCount++
		if err := activeRows.Scan(&activeRID, &activeState); err != nil {
			t.Fatalf("scan active Scope rollout failed: %v", err)
		}
	}
	if err := activeRows.Err(); err != nil {
		t.Fatalf("read active Scope rollouts failed: %v", err)
	}
	if activeCount != 1 || activeRID != string(rid) || activeState != string(domain.RolloutMonitoring) {
		t.Fatalf("BUSY StartCanary changed active rollouts: count=%d rollout=%q state=%q", activeCount, activeRID, activeState)
	}
	promote.CommandID = prefix + "_stale"
	if _, err := service.Promote(ctx, promote, candidateProposer, transitionProposer); !errors.Is(err, port.ErrStaleWrite) {
		t.Fatalf("stale expected state accepted: %v", err)
	}
	// Both commands compete from the same current epochs. Rollback's Freeze
	// and final switch remain one transaction; no committed intermediate Freeze
	// is asserted here (the in-memory phase is covered by M01-S06 Domain tests).
	type rollbackOutcome struct {
		command string
		result  application.RollbackResult
		err     error
	}
	rollbackIDs := []string{commands[3], commands[5]}
	ready := make(chan struct{}, len(rollbackIDs))
	startRollback := make(chan struct{})
	results := make(chan rollbackOutcome, len(rollbackIDs))
	for _, id := range rollbackIDs {
		go func(id string) {
			request := application.RollbackRequest{CommandID: id, Nonce: "rollback-nonce", Scope: scope, Rollout: rid, ExpectedState: domain.RolloutMonitoring, ExpectedScopeEpoch: 42, ExpectedSecurityEpoch: security, ExpectedRootEpochs: map[domain.RootID]domain.Epoch{rootA: 4, rootB: 6}}
			ready <- struct{}{}
			<-startRollback
			result, err := service.Rollback(ctx, request)
			results <- rollbackOutcome{command: id, result: result, err: err}
		}(id)
	}
	for range rollbackIDs {
		<-ready
	}
	close(startRollback)
	// Drain both calls before any fatal assertion, so cleanup never races them.
	outcomes := make([]rollbackOutcome, len(rollbackIDs))
	for i := range outcomes {
		outcomes[i] = <-results
	}
	var winner string
	var successes, staleFailures int
	for _, outcome := range outcomes {
		if outcome.err == nil {
			successes++
			winner = outcome.command
			if outcome.result.CommandID != winner || outcome.result.ScopeEpoch != 43 || outcome.result.State != domain.RolloutRolledBack || outcome.result.Mode != domain.ScopeActive {
				t.Fatalf("Rollback winner: %+v", outcome.result)
			}
			continue
		}
		var failure *application.CommandFailure
		if !errors.As(outcome.err, &failure) || failure.Kind != application.FailureStale || !errors.Is(outcome.err, port.ErrStaleWrite) {
			t.Fatalf("competing Rollback %q: got %v, want typed STALE preserving ErrStaleWrite", outcome.command, outcome.err)
		}
		staleFailures++
	}
	if successes != 1 || staleFailures != 1 {
		t.Fatalf("Rollback competition: successes=%d stale=%d, want one each", successes, staleFailures)
	}
	for _, id := range rollbackIDs {
		var receiptCount, eventCount, outboxCount int
		var status, eventType string
		if err := migrator.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM raw.command_receipts WHERE command_id=$1),
 (SELECT COALESCE(min(status),'') FROM raw.command_receipts WHERE command_id=$1),
 (SELECT count(*) FROM raw.domain_events WHERE event_id=$2),
 (SELECT COALESCE(min(event_type),'') FROM raw.domain_events WHERE event_id=$2),
 (SELECT count(*) FROM raw.event_outbox WHERE event_id=$2)`, id, "rollout/"+id).Scan(&receiptCount, &status, &eventCount, &eventType, &outboxCount); err != nil {
			t.Fatalf("read competing Rollback effects: %v", err)
		}
		wantCount, wantStatus, wantEventType := 0, "", ""
		if id == winner {
			wantCount, wantStatus, wantEventType = 1, "SUCCEEDED", "RolloutRolledBack"
		}
		if receiptCount != wantCount || status != wantStatus || eventCount != wantCount || eventType != wantEventType || outboxCount != wantCount {
			t.Fatalf("Rollback %q effects: receipts=%d status=%q events=%d type=%q outbox=%d, want count=%d status=%q type=%q", id, receiptCount, status, eventCount, eventType, outboxCount, wantCount, wantStatus, wantEventType)
		}
	}
	// Independent fixture-principal observations: state+Targets+Receipt+Outbox.
	var epoch uint64
	var state string
	var receipts, outbox int
	var slotReleased bool
	if err := migrator.QueryRow(ctx, `SELECT live_rollout_id IS NULL FROM raw.policy_scopes WHERE scope_id=$1`, string(scope)).Scan(&slotReleased); err != nil || !slotReleased {
		t.Fatal("terminal rollout retained live Scope slot")
	}
	if err := migrator.QueryRow(ctx, `SELECT s.activation_epoch,r.state,(SELECT count(*) FROM raw.command_receipts WHERE command_id=ANY($2::text[])),(SELECT count(*) FROM raw.event_outbox WHERE event_id=ANY($3::text[])) FROM raw.policy_scopes s JOIN raw.policy_rollouts r ON r.scope_id=s.scope_id WHERE s.scope_id=$1`, string(scope), commands, events).Scan(&epoch, &state, &receipts, &outbox); err != nil || epoch != 43 || state != "ROLLED_BACK" || receipts != 4 || outbox != 4 {
		t.Fatal("atomic lifecycle observation failed")
	}
	var badRoots bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM raw.roots WHERE scope_id=$1 AND (effective_bundle_digest<>$2 OR safe_baseline OR authorization_epoch<>CASE WHEN root_id=$3 THEN 5 ELSE 7 END))`, string(scope), string(baseline.Digest()), string(rootA)).Scan(&badRoots); err != nil || badRoots {
		t.Fatal("rollback Root policies/epochs differ")
	}
	// JSON ambiguity rejection is checked through a real app session, preserving
	// duplicate keys in json text. Every failed statement is in its own rollback.
	target := map[string]any{"root_id": string(rootA), "target": true, "baseline_digest": string(baseline.Digest()), "candidate_digest": string(candidateBundle.Digest()), "base_root_epoch": 5}
	validJSON, err := json.Marshal([]any{target})
	if err != nil {
		t.Fatal(err)
	}
	badPayloads := []string{`[{"root_id":"first","root_id":"second","target":true,"baseline_digest":null,"candidate_digest":"x","base_root_epoch":5}]`, string(validJSON[:len(validJSON)-2]) + `,"unknown":1}]`, `[{"root_id":"missing"}]`}
	for _, payload := range badPayloads {
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal("JSON rejection transaction failed")
		}
		_, callErr := tx.Exec(ctx, `SELECT raw.safety_create_rollout($1,$2,$3,$4,$5::json)`, prefix+"_bad", string(scope), 43, security, payload)
		rollbackErr := tx.Rollback(ctx)
		if callErr == nil || rollbackErr != nil {
			t.Fatal("ambiguous target JSON accepted or rollback failed")
		}
	}
	// Successful writes followed by callback failure must leave neither row CAS
	// nor target CAS visible. The adapter never commits its own capabilities.
	abort := errors.New("intentional callback abort")
	err = transactor.WithinRolloutTransaction(ctx, func(tx port.RolloutTx) error {
		if _, err := tx.LockScope(ctx, scope); err != nil {
			return err
		}
		old, err := tx.LockRollout(ctx, scope, rid)
		if err != nil {
			return err
		}
		next := cloneRollout(old)
		next.LastActivationEpoch++
		if err := tx.CompareAndSwapRollout(ctx, old, next); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal("CAS abort did not propagate")
	}
	var last uint64
	var finalRollouts, terminalRollouts int
	if err := migrator.QueryRow(ctx, `SELECT last_activation_epoch,
 (SELECT count(*) FROM raw.policy_rollouts WHERE scope_id=$2),
 (SELECT count(*) FROM raw.policy_rollouts WHERE scope_id=$2 AND state='ROLLED_BACK')
 FROM raw.policy_rollouts WHERE rollout_id=$1`, string(rid), string(scope)).Scan(&last, &finalRollouts, &terminalRollouts); err != nil || last != 43 || finalRollouts != 1 || terminalRollouts != 1 {
		t.Fatalf("final Rollback state/aborted CAS: last=%d rollouts=%d rolled_back=%d err=%v", last, finalRollouts, terminalRollouts, err)
	}
	current, err := readSafetyScope(ctx, safety, scope)
	if err != nil {
		t.Fatalf("read app-only authority after Rollback: %v", err)
	}
	wantRoots := map[domain.RootID]domain.RootAuthority{
		rootA: {Policy: baselinePolicy, AuthorizationEpoch: 5},
		rootB: {Policy: baselinePolicy, AuthorizationEpoch: 7},
	}
	if current.Mode != domain.ScopeActive || current.ActivationEpoch != 43 || current.SecurityEpoch != security || current.LiveRolloutID != nil || !reflect.DeepEqual(current.Roots, wantRoots) {
		t.Fatalf("Rollback authority differs: %+v", current)
	}
	// Rollback audit remains the existing RolloutRolledBack Event/Outbox above.
	// No mass revoke, Security Epoch increment, denial ledger, or external action.
	for _, stale := range []domain.Grant{grantA, grantB} {
		if err := gate.CheckHighRiskAction(ctx, scope, authorization(stale)); !errors.Is(err, domain.ErrStaleGrant) {
			t.Fatalf("pre-Rollback grant accepted: %v", err)
		}
	}
	grantA.AuthorizationEpoch, grantB.AuthorizationEpoch = 5, 7
	for _, grant := range []domain.Grant{grantA, grantB} {
		if err := gate.CheckHighRiskAction(ctx, scope, authorization(grant)); err != nil {
			t.Fatalf("current baseline/v1 grant for Root %q after Rollback: %v", grant.Root, err)
		}
	}
	for name, mutate := range map[string]func(*domain.HighRiskAuthorization){
		"other Root WorkOrder":    func(a *domain.HighRiskAuthorization) { a.Lease = bindings[rootA] },
		"missing WorkOrder/lease": func(a *domain.HighRiskAuthorization) { a.Lease.WorkOrderID = domain.WorkOrderID(prefix + "_missing") },
		"wrong attempt":           func(a *domain.HighRiskAuthorization) { a.Lease.AttemptID = domain.AttemptID(prefix + "_wrong_attempt") },
		"wrong worker":            func(a *domain.HighRiskAuthorization) { a.Lease.WorkerID = domain.WorkerID(prefix + "_wrong_worker") },
		"wrong session":           func(a *domain.HighRiskAuthorization) { a.Lease.SessionID = domain.SessionID(prefix + "_wrong_session") },
		"stale lease epoch":       func(a *domain.HighRiskAuthorization) { a.Lease.LeaseEpoch++ },
		"missing binding":         func(a *domain.HighRiskAuthorization) { a.Lease = domain.AttemptLeaseBinding{} },
		"expired lease":           func(a *domain.HighRiskAuthorization) { a.Lease = expiredBinding },
	} {
		invalid := authorization(grantB)
		mutate(&invalid)
		if err := gate.CheckHighRiskAction(ctx, scope, invalid); !errors.Is(err, domain.ErrInvalidLease) {
			t.Fatalf("%s: got %v, want lease denial", name, err)
		}
	}
	if err := gate.CheckHighRiskAction(ctx, domain.ScopeID(prefix+"_missing_scope"), authorization(grantB)); err == nil {
		t.Fatal("wrong Scope accepted")
	}
	// Denials must not consume/revoke the active matching lease.
	if err := gate.CheckHighRiskAction(ctx, scope, authorization(grantB)); err != nil {
		t.Fatalf("denials altered current lease: %v", err)
	}
	keys, signers, quorum := newM04SafetyQuorum(t)
	const stopNonce = "rollout-safety-stop-nonce"
	stopSignatures, err := makeM04SafetySignatures(keys, signers, domain.SafetyActionStop, current, commands[6], stopNonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	safetyService := application.NewSafetyService(safety, quorum)
	stopped, err := safetyService.Stop(ctx, scope, security, commands[6], stopNonce, stopSignatures)
	if err != nil || stopped.State.Mode != domain.ScopeSafeStop || stopped.State.SecurityEpoch != security+1 || stopped.State.ScopeActivationEpoch != 43 || !reflect.DeepEqual(stopped.State.Roots, wantRoots) {
		t.Fatalf("2-of-3 Safety Stop: %+v err=%v", stopped, err)
	}
	afterStop, err := readSafetyScope(ctx, safety, scope)
	if err != nil || afterStop.Mode != domain.ScopeSafeStop || afterStop.SecurityEpoch != security+1 || afterStop.ActivationEpoch != current.ActivationEpoch || afterStop.LiveRolloutID != nil || !reflect.DeepEqual(afterStop.Roots, current.Roots) {
		t.Fatalf("persisted Safety Stop changed Scope/Root epochs or failed to advance Security Epoch: %+v err=%v", afterStop, err)
	}
	for _, grant := range []domain.Grant{grantA, grantB} {
		if err := gate.CheckHighRiskAction(ctx, scope, authorization(grant)); !errors.Is(err, domain.ErrSafeStopped) {
			t.Fatalf("high-risk grant for Root %q after Stop: got %v, want ErrSafeStopped", grant.Root, err)
		}
	}
	var stopReceipts, stopEvents, stopOutbox int
	if err := migrator.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM raw.command_receipts WHERE command_id=$1 AND status='SUCCEEDED'),
 (SELECT count(*) FROM raw.domain_events WHERE event_id=$2 AND event_type='SafetyStopped'),
 (SELECT count(*) FROM raw.event_outbox WHERE event_id=$2)`, commands[6], events[6]).Scan(&stopReceipts, &stopEvents, &stopOutbox); err != nil || stopReceipts != 1 || stopEvents != 1 || stopOutbox != 1 {
		t.Fatalf("Safety Stop receipt/Event/Outbox: receipts=%d events=%d outbox=%d err=%v", stopReceipts, stopEvents, stopOutbox, err)
	}
}
