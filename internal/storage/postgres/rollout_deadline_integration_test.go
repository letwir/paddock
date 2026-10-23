//go:build integration && paddock_test

package postgres

// SOURCE ONLY: compile with -run '^$'; executing any body requires separate
// approval and a dedicated paddock_test with the additive migration installed.
// No migration is applied here; connection configuration is read only in bodies.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type deadlineIntegrationEnv struct {
	ctx           context.Context
	migrator, app *pgxpool.Pool
	tx            *RolloutTransactor
	store         *RolloutDeadlineStore
	now           time.Time
}

func newDeadlineIntegrationEnv(t *testing.T) *deadlineIntegrationEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	migratorURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if migratorURL == "" || appURL == "" {
		t.Fatal("isolated migrator and app configuration required")
	}
	m, err := openPullPool(ctx, migratorURL, false)
	if err != nil {
		t.Fatal("cannot open fixture pool")
	}
	t.Cleanup(m.Close)
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("cannot open app pool")
	}
	t.Cleanup(app.Close)
	for _, entry := range []struct {
		pool *pgxpool.Pool
		role string
	}{{m, "paddock_migrator"}, {app, "paddock_app"}} {
		var db, user, session string
		if err := entry.pool.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(&db, &user, &session); err != nil || db != "paddock_test" || user != entry.role || session != entry.role {
			t.Fatal("refusing unexpected database/session identity")
		}
	}
	var ready, empty bool
	var now time.Time
	if err := m.QueryRow(ctx, `SELECT to_regprocedure('raw.safety_cas_rollout(jsonb,jsonb)') IS NOT NULL AND to_regprocedure('raw.safety_list_rollout_deadlines(integer)') IS NOT NULL, NOT EXISTS(SELECT 1 FROM raw.policy_rollouts WHERE state='MONITORING'), clock_timestamp()`).Scan(&ready, &empty, &now); err != nil || !ready || !empty {
		t.Fatal("requires migrated isolated database without pre-existing monitoring rows")
	}
	tx, err := NewRolloutTransactor(app)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRolloutDeadlineStore(app)
	if err != nil {
		t.Fatal(err)
	}
	return &deadlineIntegrationEnv{ctx: ctx, migrator: m, app: app, tx: tx, store: store, now: now.UTC()}
}
func deadlineWindowAt(start time.Time) domain.MonitoringWindow {
	return domain.MonitoringWindow{StartedAt: start, LastObservedAt: start, ObservationDeadline: start.Add(domain.MonitoringActivePeriod), HoldBudget: domain.MonitoringHoldBudget}
}
func (e *deadlineIntegrationEnv) seed(t *testing.T, m domain.MonitoringWindow) port.RolloutSnapshot {
	t.Helper()
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "it_m07_" + hex.EncodeToString(token[:])
	root := domain.RootID(prefix + "_root")
	digest := func(s string) domain.Digest {
		d := sha256.Sum256([]byte(s))
		return domain.Digest(hex.EncodeToString(d[:]))
	}
	baseline, candidate := digest(prefix+"baseline"), digest(prefix+"candidate")
	s := port.RolloutSnapshot{ID: domain.RolloutID(prefix + "_rollout"), Scope: domain.ScopeID(prefix + "_scope"), State: domain.RolloutMonitoring, TargetRoot: &root, BaseActivationEpoch: 40, LastActivationEpoch: 42, Targets: map[domain.RootID]port.RolloutTargetSnapshot{root: {Baseline: domain.PolicyBinding{Digest: baseline}, Candidate: domain.PolicyBinding{Digest: candidate}, BaseRootEpoch: 3}}, Monitoring: m}
	if m == (domain.MonitoringWindow{}) {
		s.State = domain.RolloutCanary
		s.LastActivationEpoch = 41
	}
	if err := e.migrator.QueryRow(e.ctx, `SELECT security_epoch FROM raw.security_generation WHERE singleton_id=true`).Scan(&s.BaseSecurityEpoch); err != nil {
		t.Fatal(err)
	}
	payload, err := persistentRolloutJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := strconv.Itoa(len(s.Scope)) + ":" + string(s.Scope) + string(s.ID)
	// Cleanup is registered before the first insert and uses only exact fixture IDs.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := e.migrator.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup begin: %v", err)
			return
		}
		defer tx.Rollback(ctx)
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM raw.event_outbox WHERE event_id IN (SELECT event_id FROM raw.domain_events WHERE aggregate_id=$1 AND aggregate_kind IN ('rollout-decision','rollout-monitoring-terminal'))`, []any{aggregate}},
			{`DELETE FROM raw.domain_events WHERE aggregate_id=$1 AND aggregate_kind IN ('rollout-decision','rollout-monitoring-terminal')`, []any{aggregate}},
			{`UPDATE raw.policy_scopes SET live_rollout_id=NULL WHERE scope_id=$1`, []any{string(s.Scope)}},
			{`DELETE FROM raw.rollout_targets WHERE rollout_id=$1 AND scope_id=$2`, []any{string(s.ID), string(s.Scope)}},
			{`DELETE FROM raw.policy_rollouts WHERE rollout_id=$1 AND scope_id=$2`, []any{string(s.ID), string(s.Scope)}},
			{`DELETE FROM raw.roots WHERE root_id=$1 AND scope_id=$2`, []any{string(root), string(s.Scope)}},
			{`DELETE FROM raw.policy_scopes WHERE scope_id=$1`, []any{string(s.Scope)}},
			{`DELETE FROM raw.policy_bundles WHERE bundle_digest IN ($1,$2)`, []any{string(baseline), string(candidate)}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				t.Errorf("fixture cleanup: %v", err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("fixture cleanup commit: %v", err)
		}
	})
	tx, err := e.migrator.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(e.ctx)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO raw.policy_bundles(bundle_digest,canonical_bytes,schema_version,signer_key_id,signature) VALUES($1,$2,'integration','m07-test',$3),($4,$5,'integration','m07-test',$3)`, []any{string(baseline), []byte(prefix + "baseline"), []byte{1}, string(candidate), []byte(prefix + "candidate")}},
		{`INSERT INTO raw.policy_scopes(scope_id,activation_epoch,baseline_bundle_digest,mode) VALUES($1,$2,$3,'ACTIVE')`, []any{string(s.Scope), s.LastActivationEpoch, string(baseline)}},
		{`INSERT INTO raw.roots(root_id,scope_id,authorization_epoch,effective_bundle_digest,safe_baseline) VALUES($1,$2,4,$3,false)`, []any{string(root), string(s.Scope), string(candidate)}},
		{`INSERT INTO raw.policy_rollouts(rollout_id,scope_id,state,target_root_id,base_activation_epoch,last_activation_epoch,base_security_epoch,rollback_from,monitoring_started_at,monitoring_last_observed_at,observation_deadline,hold_since,hold_deadline,hold_used,hold_budget,extension_used,extension_command_id,extension_nonce,monitoring_decision,decision_at,evidence_digest,decision_revision)
SELECT r.rollout_id,r.scope_id,r.state,r.target_root_id,r.base_activation_epoch,r.last_activation_epoch,r.base_security_epoch,r.rollback_from,r.monitoring_started_at,r.monitoring_last_observed_at,r.observation_deadline,r.hold_since,r.hold_deadline,r.hold_used,r.hold_budget,r.extension_used,r.extension_command_id,r.extension_nonce,r.monitoring_decision,r.decision_at,r.evidence_digest,r.decision_revision FROM jsonb_populate_record(NULL::raw.policy_rollouts,$1::jsonb) r`, []any{payload}},
		{`INSERT INTO raw.rollout_targets(rollout_id,scope_id,root_id,baseline_bundle_digest,candidate_bundle_digest,base_root_epoch) VALUES($1,$2,$3,$4,$5,3)`, []any{string(s.ID), string(s.Scope), string(root), string(baseline), string(candidate)}},
		{`UPDATE raw.policy_scopes SET live_rollout_id=$2 WHERE scope_id=$1`, []any{string(s.Scope), string(s.ID)}},
	} {
		if _, err := tx.Exec(e.ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(e.ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
func (e *deadlineIntegrationEnv) locked(t *testing.T, s port.RolloutSnapshot) port.RolloutSnapshot {
	t.Helper()
	var out port.RolloutSnapshot
	err := e.tx.WithinTransaction(e.ctx, func(tx port.GovernanceTx) error {
		if _, err := tx.LockScope(e.ctx, s.Scope); err != nil {
			return err
		}
		var err error
		out, err = tx.LockRollout(e.ctx, s.Scope, s.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestRolloutMonitoringRoundtripIntegration(t *testing.T) {
	e := newDeadlineIntegrationEnv(t)
	hold := deadlineHoldWindow()
	hold.DecisionRevision = 1234567890123456788
	for _, m := range []domain.MonitoringWindow{{}, deadlineWindowAt(e.now), hold, deadlineHoldWindow()} {
		s := e.seed(t, m)
		got := e.locked(t, s)
		if !reflect.DeepEqual(got, s) {
			t.Fatalf("snapshot mismatch: %+v / %+v", got, s)
		}
		if m == (domain.MonitoringWindow{}) || m.DecisionRevision == math.MaxInt64 {
			continue
		}
		// Persist new decision/evidence and clear HOLD times without losing extension
		// metadata, elapsed budget, or the full int64 DecisionRevision.
		next := cloneRollout(s)
		next.Monitoring.Decision = domain.DecisionPass
		next.Monitoring.HoldSince = time.Time{}
		next.Monitoring.HoldDeadline = time.Time{}
		next.Monitoring.DecisionAt = next.Monitoring.LastObservedAt
		next.Monitoring.EvidenceDigest = domain.Digest(strings.Repeat("d", 64))
		next.Monitoring.DecisionRevision++
		err := e.tx.WithinTransaction(e.ctx, func(tx port.GovernanceTx) error {
			if _, err := tx.LockScope(e.ctx, s.Scope); err != nil {
				return err
			}
			locked, err := tx.LockRollout(e.ctx, s.Scope, s.ID)
			if err != nil {
				return err
			}
			return tx.CompareAndSwapRollout(e.ctx, locked, next)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.locked(t, next); !reflect.DeepEqual(got, next) {
			t.Fatalf("CAS roundtrip: %+v / %+v", got, next)
		}
	}
}
func TestRolloutFullFieldStaleCASIntegration(t *testing.T) {
	e := newDeadlineIntegrationEnv(t)
	m := deadlineHoldWindow()
	m.DecisionRevision = 100
	s := e.seed(t, m)
	payload, err := persistentRolloutJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &fields); err != nil {
		t.Fatal(err)
	}
	// Exercise every physical base/window field in the SQL overload, independently
	// of the in-memory cache fence. Reflection also catches newly added Go fields.
	if reflect.TypeOf(m).NumField() != 14 || len(fields) != 23 {
		t.Fatal("update stale-CAS field coverage")
	}
	for name, raw := range fields {
		if name == "targets" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			bad := make(map[string]json.RawMessage, len(fields))
			for k, v := range fields {
				bad[k] = v
			}
			switch {
			case string(raw) == "null":
				bad[name] = json.RawMessage(`"2026-01-01T00:00:00Z"`)
			case string(raw) == "true":
				bad[name] = json.RawMessage(`false`)
			case string(raw) == "false":
				bad[name] = json.RawMessage(`true`)
			case raw[0] == '"':
				var value string
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				if stamp, err := time.Parse(time.RFC3339Nano, value); err == nil {
					value = stamp.Add(time.Microsecond).Format(time.RFC3339Nano)
				} else if strings.Contains(value, " microseconds") {
					value = "1 microseconds"
				} else {
					value += "x"
				}
				bad[name], err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			default:
				var value int64
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				bad[name] = json.RawMessage(strconv.FormatInt(value+1, 10))
			}
			encoded, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			var updated bool
			if err := e.app.QueryRow(e.ctx, `SELECT raw.safety_cas_rollout($1::jsonb,$2::jsonb)`, string(encoded), payload).Scan(&updated); err != nil || updated {
				t.Fatalf("SQL accepted stale %s: %v", name, err)
			}
		})
	}
	for _, field := range []string{"root_id", "baseline_bundle_digest", "candidate_bundle_digest", "base_root_epoch", "cardinality"} {
		t.Run("targets/"+field, func(t *testing.T) {
			var bad map[string]json.RawMessage
			if err := json.Unmarshal([]byte(payload), &bad); err != nil {
				t.Fatal(err)
			}
			var targets []map[string]any
			if err := json.Unmarshal(bad["targets"], &targets); err != nil {
				t.Fatal(err)
			}
			if field == "cardinality" {
				targets = append(targets, targets[0])
			} else if field == "base_root_epoch" {
				targets[0][field] = 99
			} else {
				targets[0][field] = "stale"
			}
			bad["targets"], err = json.Marshal(targets)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			var updated bool
			if err := e.app.QueryRow(e.ctx, `SELECT raw.safety_cas_rollout($1::jsonb,$2::jsonb)`, string(encoded), payload).Scan(&updated); err != nil || updated {
				t.Fatalf("SQL accepted stale target %s: %v", field, err)
			}
		})
	}
	if got := e.locked(t, s); !reflect.DeepEqual(got, s) {
		t.Fatal("stale CAS mutated a field")
	}
	var legacyUpdated bool
	if err := e.app.QueryRow(e.ctx, `SELECT raw.safety_cas_rollout($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, string(s.State), string(*s.TargetRoot), s.LastActivationEpoch, nil, string(s.ID), string(s.Scope), string(s.State), s.BaseActivationEpoch, s.LastActivationEpoch, s.BaseSecurityEpoch, string(*s.TargetRoot), nil).Scan(&legacyUpdated); err != nil || legacyUpdated {
		t.Fatalf("legacy base CAS bypassed full fence: %v", err)
	}
}
func effectiveDeadline(c port.RolloutDeadlineCandidate) time.Time {
	if c.Monitoring.Decision == domain.DecisionFail || c.Monitoring.Decision == domain.DecisionAbort {
		return c.Monitoring.DecisionAt
	}
	if c.Monitoring.Decision == domain.DecisionHold {
		return c.Monitoring.HoldDeadline
	}
	return c.Monitoring.ObservationDeadline
}
func TestRolloutDeadlineOrderingAndBoundsIntegration(t *testing.T) {
	e := newDeadlineIntegrationEnv(t)
	normal := deadlineWindowAt(e.now.Add(-domain.MonitoringActivePeriod - 20*time.Second))
	hold := deadlineWindowAt(e.now.Add(-8 * 24 * time.Hour))
	hold.Decision = domain.DecisionHold
	hold.DecisionRevision = 1
	hold.HoldDeadline = e.now.Add(-20 * time.Second)
	hold.HoldSince = hold.HoldDeadline.Add(-hold.HoldBudget)
	hold.DecisionAt = hold.HoldSince
	hold.LastObservedAt = hold.HoldSince
	hold.EvidenceDigest = domain.Digest(strings.Repeat("a", 64))
	failed := deadlineWindowAt(e.now)
	failed.Decision = domain.DecisionFail
	failed.DecisionRevision = 1
	failed.DecisionAt = e.now
	failed.EvidenceDigest = domain.Digest(strings.Repeat("b", 64))
	expected := []port.RolloutDeadlineCandidate{}
	for _, m := range []domain.MonitoringWindow{normal, normal, hold, failed} {
		s := e.seed(t, m)
		expected = append(expected, port.RolloutDeadlineCandidate{Scope: s.Scope, Rollout: s.ID, Monitoring: m})
	}
	e.seed(t, deadlineWindowAt(e.now.Add(time.Hour))) // not due
	sort.Slice(expected, func(i, j int) bool {
		a, b := expected[i], expected[j]
		da, db := effectiveDeadline(a), effectiveDeadline(b)
		if !da.Equal(db) {
			return da.Before(db)
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Rollout < b.Rollout
	})
	for _, limit := range []int{1, 2, port.MaxRolloutDeadlineBatch} {
		got, err := e.store.ListRolloutDeadlines(e.ctx, limit)
		if err != nil {
			t.Fatal(err)
		}
		n := limit
		if n > len(expected) {
			n = len(expected)
		}
		if !reflect.DeepEqual(got, expected[:n]) {
			t.Fatalf("order/bound %d: %+v / %+v", limit, got, expected[:n])
		}
	}
	for _, limit := range []int{0, -1, port.MaxRolloutDeadlineBatch + 1} {
		if _, err := e.store.ListRolloutDeadlines(e.ctx, limit); !errors.Is(err, port.ErrInvalidDeadlineBatch) {
			t.Fatal(err)
		}
		rows, err := e.app.Query(e.ctx, `SELECT * FROM raw.safety_list_rollout_deadlines($1)`, limit)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
		if err == nil {
			t.Fatalf("SQL accepted limit %d", limit)
		}
	}
	// A held Scope lock must not block listing: listing has no authority/row locks.
	owner, err := e.app.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Rollback(e.ctx)
	if _, err := owner.Exec(e.ctx, `SELECT * FROM raw.safety_lock_scope($1)`, string(expected[0].Scope)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
	defer cancel()
	if _, err := e.store.ListRolloutDeadlines(ctx, 1); err != nil {
		t.Fatalf("listing took locks: %v", err)
	}
}

type deadlineBarrierStore struct {
	store   port.RolloutDeadlineStore
	ready   chan struct{}
	release chan struct{}
}

func (s deadlineBarrierStore) ListRolloutDeadlines(ctx context.Context, n int) ([]port.RolloutDeadlineCandidate, error) {
	hints, err := s.store.ListRolloutDeadlines(ctx, n)
	if err != nil {
		return nil, err
	}
	select {
	case s.ready <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-s.release:
		return hints, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type deadlineFixedHints []port.RolloutDeadlineCandidate

func (s deadlineFixedHints) ListRolloutDeadlines(context.Context, int) ([]port.RolloutDeadlineCandidate, error) {
	return s, nil
}
func TestRolloutConcurrentReaperCleanupIntegration(t *testing.T) {
	e := newDeadlineIntegrationEnv(t)
	s := e.seed(t, deadlineWindowAt(e.now.Add(-8*24*time.Hour)))
	hints, err := e.store.ListRolloutDeadlines(e.ctx, 1)
	if err != nil || len(hints) != 1 {
		t.Fatalf("hints: %v", err)
	}
	barrier := deadlineBarrierStore{store: e.store, ready: make(chan struct{}, 2), release: make(chan struct{})}
	type result struct {
		n   int
		err error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		reaper, err := application.NewRolloutDeadlineReaper(e.tx, barrier, nil, time.Second, 10*time.Second, 10)
		if err != nil {
			t.Fatal(err)
		}
		workers.Add(1)
		go func() { defer workers.Done(); n, err := reaper.Sweep(e.ctx); results <- result{n, err} }()
	}
	// Both hints are acquired before allowing either transaction to start.
	for i := 0; i < 2; i++ {
		select {
		case <-barrier.ready:
		case <-e.ctx.Done():
			close(barrier.release)
			workers.Wait()
			t.Fatal("reaper listing stalled")
		}
	}
	close(barrier.release)
	workers.Wait()
	close(results)
	total := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		total += r.n
	}
	if total != 1 {
		t.Fatalf("concurrent terminal count: %d", total)
	}
	got := e.locked(t, s)
	if got.State != domain.RolloutSafeStopped || got.Monitoring.Decision != domain.DecisionAbort || got.Monitoring.DecisionRevision != 1 || got.LastActivationEpoch != 43 {
		t.Fatalf("safe-only exit: %+v", got)
	}
	var mode string
	var live *string
	var epoch domain.Epoch
	if err := e.migrator.QueryRow(e.ctx, `SELECT mode,live_rollout_id,activation_epoch FROM raw.policy_scopes WHERE scope_id=$1`, string(s.Scope)).Scan(&mode, &live, &epoch); err != nil || mode != "SAFE_STOPPED" || live != nil || epoch != 43 {
		t.Fatalf("slot not released: %s %v %d %v", mode, live, epoch, err)
	}
	aggregate := fmt.Sprintf("%d:%s%s", len(s.Scope), s.Scope, s.ID)
	var events, outbox int
	if err := e.migrator.QueryRow(e.ctx, `SELECT count(*),(SELECT count(*) FROM raw.event_outbox o JOIN raw.domain_events d USING(event_id) WHERE d.aggregate_id=$1) FROM raw.domain_events WHERE aggregate_id=$1`, aggregate).Scan(&events, &outbox); err != nil || events != 2 || outbox != 2 {
		t.Fatalf("atomic events/outbox: %d/%d %v", events, outbox, err)
	}
	replay, err := application.NewRolloutDeadlineReaper(e.tx, deadlineFixedHints(hints), nil, time.Second, 10*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := replay.Sweep(e.ctx); err != nil || n != 0 {
		t.Fatalf("replayed hints changed terminal row: %d %v", n, err)
	}
	if remaining, err := e.store.ListRolloutDeadlines(e.ctx, 10); err != nil || len(remaining) != 0 {
		t.Fatalf("terminal row still due: %v", err)
	}
}
