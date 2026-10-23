package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

type rolloutCall struct {
	sql  string
	args []any
}
type rolloutRecordingTx struct {
	fakeTransaction
	calls    []rolloutCall
	results  []bool
	rowErrAt int
	execErr  error
}

func (f *rolloutRecordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, rolloutCall{sql, args})
	return pgconn.NewCommandTag("UPDATE 1"), f.execErr
}
func (f *rolloutRecordingTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.calls = append(f.calls, rolloutCall{sql, args})
	index := len(f.calls) - 1
	if f.rowErrAt == index+1 {
		return rolloutBoolRow{err: errors.New("row failure")}
	}
	result := true
	if index < len(f.results) {
		result = f.results[index]
	}
	return rolloutBoolRow{updated: result}
}

type rolloutBoolRow struct {
	updated bool
	err     error
}

func (r rolloutBoolRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.updated
	return nil
}

func rolloutAdapterFixture() (*rolloutGovernanceTx, *rolloutRecordingTx, port.ScopeSnapshot, port.RolloutSnapshot) {
	baseline := domain.PolicyBinding{Digest: domain.Digest(strings.Repeat("a", 64))}
	candidate := domain.PolicyBinding{Digest: domain.Digest(strings.Repeat("b", 64))}
	rootID := domain.RootID("root-b")
	scope := port.ScopeSnapshot{ScopeID: "scope", Mode: domain.ScopeActive, ActivationEpoch: 40, SecurityEpoch: 7,
		Roots: map[domain.RootID]domain.RootAuthority{
			"root-a": {Policy: baseline, AuthorizationEpoch: 3}, "root-b": {Policy: baseline, AuthorizationEpoch: 9}}}
	snap := port.RolloutSnapshot{ID: "rollout", Scope: "scope", State: domain.RolloutCanary, TargetRoot: &rootID,
		BaseActivationEpoch: 40, LastActivationEpoch: 41, BaseSecurityEpoch: 7,
		Targets: map[domain.RootID]port.RolloutTargetSnapshot{
			"root-a": {Baseline: baseline, Candidate: candidate, BaseRootEpoch: 3},
			"root-b": {Baseline: baseline, Candidate: candidate, BaseRootEpoch: 9}}}
	tx := &rolloutRecordingTx{}
	g := &rolloutGovernanceTx{safetyGovernanceTx: newSafetyGovernanceTx(tx)}
	g.lockedScopes[scope.ScopeID] = cloneScope(scope)
	g.validatedScopes[scope.ScopeID] = true
	return g, tx, scope, snap
}

func TestRolloutCreateCallsOnlyJSONCapabilityAndCachesClone(t *testing.T) {
	g, tx, _, snap := rolloutAdapterFixture()
	if err := g.CreateRollout(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 1 || tx.calls[0].sql != `SELECT raw.safety_create_rollout($1, $2, $3, $4, $5::json)` {
		t.Fatalf("calls: %+v", tx.calls)
	}
	want := []any{"rollout", "scope", domain.Epoch(40), domain.Epoch(7)}
	if !reflect.DeepEqual(tx.calls[0].args[:4], want) {
		t.Fatalf("arguments: %#v", tx.calls[0].args)
	}
	var targets []map[string]any
	if err := json.Unmarshal([]byte(tx.calls[0].args[4].(string)), &targets); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0]["root_id"] != "root-a" || targets[1]["root_id"] != "root-b" || targets[0]["target"] != false || targets[1]["target"] != true {
		t.Fatalf("targets: %#v", targets)
	}
	for _, target := range targets {
		if len(target) != 5 || target["baseline_digest"] != strings.Repeat("a", 64) || target["candidate_digest"] != strings.Repeat("b", 64) {
			t.Fatalf("shape: %#v", target)
		}
	}
	snap.Targets["root-a"] = port.RolloutTargetSnapshot{}
	*snap.TargetRoot = "mutated"
	cached := g.lockedRollouts[rolloutKey{scope: "scope", rollout: "rollout"}]
	if *cached.TargetRoot != "root-b" || cached.Targets["root-a"].BaseRootEpoch != 3 {
		t.Fatal("created snapshot aliases caller")
	}
}

func TestRolloutCreateRejectsBeforeSQL(t *testing.T) {
	tests := map[string]func(*rolloutGovernanceTx, *port.RolloutSnapshot){
		"unlocked":       func(g *rolloutGovernanceTx, s *port.RolloutSnapshot) { delete(g.lockedScopes, s.Scope) },
		"unvalidated":    func(g *rolloutGovernanceTx, s *port.RolloutSnapshot) { delete(g.validatedScopes, s.Scope) },
		"wrong state":    func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) { s.State = domain.RolloutMonitoring },
		"missing target": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) { s.TargetRoot = nil },
		"foreign target": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			id := domain.RootID("foreign")
			s.TargetRoot = &id
		},
		"last epoch": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) { s.LastActivationEpoch++ },
		"scope epoch": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			s.BaseActivationEpoch++
			s.LastActivationEpoch++
		},
		"security epoch": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) { s.BaseSecurityEpoch++ },
		"missing root":   func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) { delete(s.Targets, "root-a") },
		"foreign root": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			s.Targets["foreign"] = s.Targets["root-a"]
			delete(s.Targets, "root-a")
		},
		"baseline": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			r := s.Targets["root-a"]
			r.Baseline = r.Candidate
			s.Targets["root-a"] = r
		},
		"root epoch": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			r := s.Targets["root-a"]
			r.BaseRootEpoch++
			s.Targets["root-a"] = r
		},
		"candidate": func(_ *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			r := s.Targets["root-a"]
			r.Candidate = domain.PolicyBinding{SafeBaseline: true}
			s.Targets["root-a"] = r
		},
		"frozen": func(g *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			r := g.lockedScopes[s.Scope]
			r.Mode = domain.ScopeFrozen
			g.lockedScopes[s.Scope] = r
		},
		"live rollout": func(g *rolloutGovernanceTx, s *port.RolloutSnapshot) {
			r := g.lockedScopes[s.Scope]
			r.LiveRolloutID = &s.ID
			g.lockedScopes[s.Scope] = r
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			g, tx, _, s := rolloutAdapterFixture()
			mutate(g, &s)
			if err := g.CreateRollout(context.Background(), s); err == nil {
				t.Fatal("accepted invalid create")
			}
			if len(tx.calls) != 0 {
				t.Fatal("wrote invalid create")
			}
		})
	}
}

func TestRolloutCreateFailureDoesNotCache(t *testing.T) {
	g, tx, _, s := rolloutAdapterFixture()
	tx.execErr = errors.New("insert failed")
	if err := g.CreateRollout(context.Background(), s); !errors.Is(err, tx.execErr) {
		t.Fatalf("error: %v", err)
	}
	if len(g.lockedRollouts) != 0 {
		t.Fatal("cached failed creation")
	}
}

func TestRolloutCASMirrorsGenericArgumentsAndSortedTargets(t *testing.T) {
	g, tx, _, s := rolloutAdapterFixture()
	key := rolloutKey{scope: s.Scope, rollout: s.ID}
	g.lockedRollouts[key] = cloneRollout(s)
	next := cloneRollout(s)
	next.State = domain.RolloutMonitoring
	next.Monitoring = deadlineTestWindow()
	next.LastActivationEpoch++
	target := next.Targets["root-a"]
	target.Baseline = domain.PolicyBinding{SafeBaseline: true}
	target.BaseRootEpoch++
	next.Targets["root-a"] = target
	if err := g.CompareAndSwapRollout(context.Background(), s, next); err != nil {
		t.Fatal(err)
	}
	direct := &rolloutRecordingTx{}
	generic := newGovernanceTx(direct)
	generic.lockedRollouts[key] = cloneRollout(s)
	if err := generic.CompareAndSwapRollout(context.Background(), s, next); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 3 || len(direct.calls) != 3 {
		t.Fatalf("calls: %d/%d", len(tx.calls), len(direct.calls))
	}
	for i, call := range tx.calls {
		if i == 0 {
			if len(call.args) != 2 || !strings.Contains(call.sql, "$1::jsonb, $2::jsonb") {
				t.Fatalf("full-snapshot CAS: %+v", call)
			}
			for j, snapshot := range []port.RolloutSnapshot{s, next} {
				want, err := persistentRolloutJSON(snapshot)
				if err != nil || call.args[j] != want {
					t.Fatalf("full-snapshot CAS payload %d: %v", j, err)
				}
			}
		} else if !reflect.DeepEqual(call.args, direct.calls[i].args) {
			t.Fatalf("CAS %d differs from generic: %#v vs %#v", i, call.args, direct.calls[i].args)
		}
		if !strings.HasPrefix(call.sql, "SELECT raw.safety_cas_rollout(") && !strings.HasPrefix(call.sql, "SELECT raw.safety_cas_rollout_target(") {
			t.Fatalf("direct DML: %s", call.sql)
		}
	}
	if tx.calls[1].args[5] != "root-a" || tx.calls[2].args[5] != "root-b" {
		t.Fatal("nondeterministic target order")
	}
	if !reflect.DeepEqual(g.lockedRollouts[key], next) {
		t.Fatal("cache not advanced")
	}
	next.Targets["root-a"] = port.RolloutTargetSnapshot{}
	if g.lockedRollouts[key].Targets["root-a"].BaseRootEpoch != 4 {
		t.Fatal("CAS cache aliases caller")
	}
}

func TestRolloutCASEveryExpectedFieldIsCheckedBeforeSQL(t *testing.T) {
	mutations := map[string]func(*port.RolloutSnapshot){
		"id": func(s *port.RolloutSnapshot) { s.ID = "other" }, "scope": func(s *port.RolloutSnapshot) { s.Scope = "other" },
		"state":           func(s *port.RolloutSnapshot) { s.State = domain.RolloutMonitoring },
		"target":          func(s *port.RolloutSnapshot) { s.TargetRoot = nil },
		"base activation": func(s *port.RolloutSnapshot) { s.BaseActivationEpoch++ },
		"last activation": func(s *port.RolloutSnapshot) { s.LastActivationEpoch++ },
		"security":        func(s *port.RolloutSnapshot) { s.BaseSecurityEpoch++ },
		"rollback origin": func(s *port.RolloutSnapshot) { state := domain.RolloutCanary; s.RollbackFrom = &state },
		"root ids":        func(s *port.RolloutSnapshot) { delete(s.Targets, "root-a") },
		"baseline": func(s *port.RolloutSnapshot) {
			v := s.Targets["root-a"]
			v.Baseline = v.Candidate
			s.Targets["root-a"] = v
		},
		"candidate": func(s *port.RolloutSnapshot) {
			v := s.Targets["root-a"]
			v.Candidate = v.Baseline
			s.Targets["root-a"] = v
		},
		"base root epoch": func(s *port.RolloutSnapshot) { v := s.Targets["root-a"]; v.BaseRootEpoch++; s.Targets["root-a"] = v },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			g, tx, _, s := rolloutAdapterFixture()
			g.lockedRollouts[rolloutKey{scope: s.Scope, rollout: s.ID}] = cloneRollout(s)
			next := cloneRollout(s)
			mutate(&s)
			if err := g.CompareAndSwapRollout(context.Background(), s, next); !errors.Is(err, port.ErrStaleWrite) {
				t.Fatalf("error %v", err)
			}
			if len(tx.calls) != 0 {
				t.Fatal("SQL before expected check")
			}
		})
	}
}

func TestRolloutCASRejectsInvalidNextBeforeSQL(t *testing.T) {
	for _, mutate := range []func(*port.RolloutSnapshot){
		func(s *port.RolloutSnapshot) { s.ID = "other" }, func(s *port.RolloutSnapshot) { s.Scope = "other" },
		func(s *port.RolloutSnapshot) { s.BaseActivationEpoch++ }, func(s *port.RolloutSnapshot) { s.BaseSecurityEpoch++ },
		func(s *port.RolloutSnapshot) { delete(s.Targets, "root-a") }, func(s *port.RolloutSnapshot) { s.LastActivationEpoch-- },
		func(s *port.RolloutSnapshot) { s.State = domain.RolloutRollingBack },
	} {
		g, tx, _, s := rolloutAdapterFixture()
		g.lockedRollouts[rolloutKey{scope: s.Scope, rollout: s.ID}] = cloneRollout(s)
		next := cloneRollout(s)
		mutate(&next)
		if err := g.CompareAndSwapRollout(context.Background(), s, next); err == nil {
			t.Fatal("accepted invalid next")
		}
		if len(tx.calls) != 0 {
			t.Fatal("wrote invalid next")
		}
	}
}

func TestRolloutCASStaleAndErrorsRollBackEntireTransaction(t *testing.T) {
	for _, failureAt := range []int{1, 2, 3} {
		for _, dbError := range []bool{false, true} {
			g, tx, _, s := rolloutAdapterFixture()
			key := rolloutKey{scope: s.Scope, rollout: s.ID}
			g.lockedRollouts[key] = cloneRollout(s)
			tx.results = []bool{true, true, true}
			tx.results[failureAt-1] = false
			if dbError {
				tx.rowErrAt = failureAt
			}
			transactor := &RolloutTransactor{transactor: &Transactor{pool: fakeBeginner{tx: tx}, safetyAPI: true}}
			err := transactor.WithinRolloutTransaction(context.Background(), func(port.RolloutTx) error {
				next := cloneRollout(s)
				next.LastActivationEpoch++
				return g.CompareAndSwapRollout(context.Background(), s, next)
			})
			if err == nil || (!dbError && !errors.Is(err, port.ErrStaleWrite)) {
				t.Fatalf("failure %d: %v", failureAt, err)
			}
			if tx.commits != 0 || tx.rollbacks != 1 || len(tx.calls) != failureAt {
				t.Fatalf("partial CAS not aborted: %+v", tx)
			}
			if !reflect.DeepEqual(g.lockedRollouts[key], s) {
				t.Fatal("advanced cache after failed target CAS")
			}
		}
	}
}

func TestRolloutTransactorLifecycleAndAdapterSelection(t *testing.T) {
	if _, err := NewRolloutTransactor(nil); err == nil {
		t.Fatal("accepted nil pool")
	}
	for _, scenario := range []string{"success", "callback", "cancel", "commit", "panic", "rollback", "begin"} {
		t.Run(scenario, func(t *testing.T) {
			tx := &rolloutRecordingTx{}
			begin := fakeBeginner{tx: tx}
			want := errors.New("sentinel")
			if scenario == "commit" {
				tx.commitErr = want
			}
			if scenario == "rollback" {
				tx.rollbackErr = want
			}
			if scenario == "begin" {
				begin.err = want
			}
			transactor := &RolloutTransactor{transactor: &Transactor{pool: begin, safetyAPI: true}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			callback := func(g port.RolloutTx) error {
				adapter, ok := g.(*rolloutGovernanceTx)
				if !ok || adapter.tx != tx {
					t.Fatalf("wrong adapter/transaction %T", g)
				}
				// Existing Scope/Root/Receipt APIs remain promoted from Safety, not generic.
				if scenario == "cancel" {
					cancel()
				}
				if scenario == "panic" {
					panic(want)
				}
				if scenario == "callback" || scenario == "rollback" {
					return want
				}
				return nil
			}
			if scenario == "panic" {
				defer func() {
					if recover() != want || tx.rollbacks != 1 || tx.commits != 0 {
						t.Fatal("panic not rolled back")
					}
				}()
			}
			err := transactor.WithinRolloutTransaction(ctx, callback)
			if scenario == "success" {
				if err != nil || tx.commits != 1 || tx.rollbacks != 0 {
					t.Fatalf("success %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("lost lifecycle failure")
			}
			if scenario == "commit" {
				if !strings.Contains(err.Error(), "outcome may be unknown") || tx.rollbacks != 0 {
					t.Fatal("unknown commit treated as rollback")
				}
				return
			}
			if scenario == "begin" {
				if tx.commits != 0 || tx.rollbacks != 0 {
					t.Fatal("rollback without begin")
				}
				return
			}
			if tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatal("failed callback committed")
			}
		})
	}
	var nilTx *RolloutTransactor
	if err := nilTx.WithinRolloutTransaction(context.Background(), func(port.RolloutTx) error { return nil }); err == nil {
		t.Fatal("accepted nil transactor")
	}
	transactor := &RolloutTransactor{transactor: &Transactor{pool: fakeBeginner{tx: &rolloutRecordingTx{}}, safetyAPI: true}}
	if err := transactor.WithinRolloutTransaction(context.Background(), nil); err == nil {
		t.Fatal("accepted nil callback")
	}
	if err := transactor.WithinRolloutTransaction(nil, func(port.RolloutTx) error { return nil }); err == nil {
		t.Fatal("accepted nil context")
	}
}
