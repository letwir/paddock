package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

func deadlineTestWindow() domain.MonitoringWindow {
	now := time.Date(2026, 10, 22, 1, 2, 3, 456000, time.UTC)
	return domain.MonitoringWindow{StartedAt: now, LastObservedAt: now, ObservationDeadline: now.Add(domain.MonitoringActivePeriod), HoldBudget: domain.MonitoringHoldBudget}
}
func deadlineHoldWindow() domain.MonitoringWindow {
	m := deadlineTestWindow()
	m.HoldUsed = time.Hour
	m.HoldBudget = domain.MonitoringExtendedCap
	m.ObservationDeadline = m.StartedAt.Add(domain.MonitoringActivePeriod + m.HoldUsed)
	m.ExtensionUsed = true
	m.ExtensionCommandID = "extension"
	m.ExtensionNonce = "nonce"
	m.HoldSince = m.StartedAt.Add(2 * time.Hour)
	m.HoldDeadline = m.HoldSince.Add(m.HoldBudget - m.HoldUsed)
	m.LastObservedAt = m.HoldSince
	m.Decision = domain.DecisionHold
	m.DecisionAt = m.HoldSince
	m.EvidenceDigest = domain.Digest(strings.Repeat("c", 64))
	m.DecisionRevision = math.MaxInt64
	return m
}
func deadlineRow(m domain.MonitoringWindow) monitoringRow {
	ts := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()} }
	return monitoringRow{started: ts(m.StartedAt), observed: ts(m.LastObservedAt), observation: ts(m.ObservationDeadline), since: ts(m.HoldSince), deadline: ts(m.HoldDeadline), used: pgtype.Interval{Microseconds: int64(m.HoldUsed / time.Microsecond), Valid: true}, budget: pgtype.Interval{Microseconds: int64(m.HoldBudget / time.Microsecond), Valid: true}, extension: m.ExtensionUsed, command: m.ExtensionCommandID, nonce: m.ExtensionNonce, decision: string(m.Decision), decisionAt: ts(m.DecisionAt), evidence: string(m.EvidenceDigest), revision: m.DecisionRevision}
}
func deadlineValues(m domain.MonitoringWindow) []any {
	r := deadlineRow(m)
	out := []any{}
	for _, p := range r.dest() {
		out = append(out, reflect.ValueOf(p).Elem().Interface())
	}
	return out
}

// Embed unused methods, but implement every operation exercised by the adapter.
type deadlineRows struct {
	pgx.Rows
	values          [][]any
	index           int
	closed          bool
	scanErr, rowErr error
}

func (r *deadlineRows) Close() { r.closed = true }
func (r *deadlineRows) Next() bool {
	if r.index == len(r.values) {
		return false
	}
	r.index++
	return true
}
func (r *deadlineRows) Err() error { return r.rowErr }
func (r *deadlineRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	return deadlineAssign(dest, r.values[r.index-1])
}
func deadlineAssign(dest, values []any) error {
	if len(dest) != len(values) {
		return errors.New("wrong column count")
	}
	for n, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(values[n]))
	}
	return nil
}

type deadlineQuery struct {
	rows  *deadlineRows
	err   error
	calls int
	sql   string
	args  []any
}

func (q *deadlineQuery) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.calls++
	q.sql = sql
	q.args = args
	return q.rows, q.err
}

func TestMonitoringIntervalLosslessBoundaries(t *testing.T) {
	for _, d := range []time.Duration{0, time.Microsecond, time.Hour, 48 * time.Hour, time.Duration(math.MaxInt64 / 1000 * 1000)} {
		i, err := durationInterval(d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := intervalDuration(i)
		if err != nil || got != d {
			t.Fatalf("%v: %v %v", d, got, err)
		}
	}
	for _, d := range []time.Duration{-time.Microsecond, time.Nanosecond, time.Duration(math.MaxInt64)} {
		if _, err := durationInterval(d); err == nil {
			t.Fatalf("accepted %v", d)
		}
	}
	for _, i := range []pgtype.Interval{{}, {Valid: true, Months: 1}, {Valid: true, Days: 1}, {Valid: true, Months: 1, Days: -30}, {Valid: true, Microseconds: -1}, {Valid: true, Microseconds: math.MaxInt64/1000 + 1}} {
		if _, err := intervalDuration(i); err == nil {
			t.Fatalf("accepted %#v", i)
		}
	}
}
func TestMonitoringRowAndJSONRoundtrip(t *testing.T) {
	for _, m := range []domain.MonitoringWindow{{}, deadlineTestWindow(), deadlineHoldWindow()} {
		r := deadlineRow(m)
		got, err := r.window()
		if err != nil || got != m {
			t.Fatalf("window: %#v %v", got, err)
		}
		_, _, _, s := rolloutAdapterFixture()
		s.Monitoring = m
		if m != (domain.MonitoringWindow{}) {
			s.State = domain.RolloutMonitoring
		}
		payload, err := persistentRolloutJSON(s)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &wire); err != nil {
			t.Fatal(err)
		}
		if len(wire) != 23 {
			t.Fatalf("incomplete JSON: %d fields", len(wire))
		}
		var revision int64
		if err := json.Unmarshal(wire["decision_revision"], &revision); err != nil || revision != m.DecisionRevision {
			t.Fatalf("revision lost: %s", wire["decision_revision"])
		}
		if m == (domain.MonitoringWindow{}) && string(wire["monitoring_started_at"]) != "null" {
			t.Fatal("fabricated time")
		}
		if !strings.Contains(string(wire["hold_budget"]), "microseconds") {
			t.Fatal("interval transport is not explicit")
		}
	}
	for _, mutate := range []func(*monitoringRow){
		func(r *monitoringRow) { r.used.Months = 1 }, func(r *monitoringRow) { r.budget.Valid = false }, func(r *monitoringRow) { r.revision = -1 }, func(r *monitoringRow) { r.started.InfinityModifier = pgtype.Infinity }, func(r *monitoringRow) { r.started.Time = r.started.Time.Add(time.Nanosecond) }, func(r *monitoringRow) { r.started.Valid = false }, func(r *monitoringRow) { r.decision = "unknown" },
	} {
		r := deadlineRow(deadlineHoldWindow())
		mutate(&r)
		if _, err := r.window(); err == nil {
			t.Fatal("invalid stored monitoring accepted")
		}
	}
}
func TestMonitoringSnapshotPostgresValidation(t *testing.T) {
	for _, mutate := range []func(*port.RolloutSnapshot){
		func(s *port.RolloutSnapshot) { s.Monitoring.StartedAt = s.Monitoring.StartedAt.Add(time.Nanosecond) },
		func(s *port.RolloutSnapshot) { s.Monitoring.HoldUsed = time.Nanosecond },
		func(s *port.RolloutSnapshot) { s.Monitoring.DecisionRevision = -1 },
		func(s *port.RolloutSnapshot) { s.Monitoring = domain.MonitoringWindow{} },
		func(s *port.RolloutSnapshot) { s.BaseActivationEpoch = domain.Epoch(math.MaxInt64) + 1 },
		func(s *port.RolloutSnapshot) { s.BaseSecurityEpoch = domain.Epoch(math.MaxInt64) + 1 },
		func(s *port.RolloutSnapshot) { s.LastActivationEpoch = domain.Epoch(math.MaxInt64) + 1 },
		func(s *port.RolloutSnapshot) { s.State = domain.RolloutCompleted },
	} {
		_, _, _, s := rolloutAdapterFixture()
		s.State = domain.RolloutMonitoring
		s.Monitoring = deadlineTestWindow()
		mutate(&s)
		if err := validatePersistentRollout(s); err == nil {
			t.Fatalf("invalid snapshot accepted: %+v", s)
		}
	}
}
func TestRolloutDeadlineStoreBoundsCancellationAndRows(t *testing.T) {
	m := deadlineHoldWindow()
	row := append([]any{domain.ScopeID("scope"), domain.RolloutID("rollout")}, deadlineValues(m)...)
	q := &deadlineQuery{rows: &deadlineRows{values: [][]any{row}}}
	s := &RolloutDeadlineStore{pool: q}
	for _, limit := range []int{-1, 0, port.MaxRolloutDeadlineBatch + 1} {
		if _, err := s.ListRolloutDeadlines(context.Background(), limit); !errors.Is(err, port.ErrInvalidDeadlineBatch) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListRolloutDeadlines(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.ListRolloutDeadlines(nil, 1); err == nil {
		t.Fatal("nil context")
	}
	if q.calls != 0 {
		t.Fatal("queried invalid input")
	}
	got, err := s.ListRolloutDeadlines(context.Background(), 1)
	if err != nil || len(got) != 1 || got[0].Monitoring != m || !q.rows.closed {
		t.Fatalf("%+v %v", got, err)
	}
	if q.sql != `SELECT * FROM raw.safety_list_rollout_deadlines($1)` || !reflect.DeepEqual(q.args, []any{1}) {
		t.Fatal("caller clock or direct query")
	}
	for _, kind := range []string{"query", "scan", "iterate", "overflow", "invalid", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			rows := &deadlineRows{values: [][]any{row}}
			q := &deadlineQuery{rows: rows}
			s := &RolloutDeadlineStore{pool: q}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "query":
				q.err = errors.New("query")
			case "scan":
				rows.scanErr = errors.New("scan")
			case "iterate":
				rows.rowErr = errors.New("iterate")
			case "overflow":
				rows.values = append(rows.values, row)
			case "invalid":
				bad := append([]any(nil), row...)
				bad[0] = domain.ScopeID("")
				rows.values = [][]any{bad}
			case "cancel":
				cancel()
			}
			if got, err := s.ListRolloutDeadlines(ctx, 1); err == nil || got != nil {
				t.Fatalf("partial success: %+v %v", got, err)
			}
			if q.calls != 0 && q.err == nil && !rows.closed {
				t.Fatal("rows leaked")
			}
		})
	}
	if _, err := NewRolloutDeadlineStore(nil); err == nil {
		t.Fatal("nil pool")
	}
	var empty *RolloutDeadlineStore
	if _, err := empty.ListRolloutDeadlines(context.Background(), 1); err == nil {
		t.Fatal("nil store")
	}
}

type monitoringScanRow struct {
	values []any
	err    error
}

func (r monitoringScanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return deadlineAssign(dest, r.values)
}

type monitoringReadTx struct {
	rolloutRecordingTx
	base       *deadlineRows
	monitoring pgx.Row
	reads      int
}

func (f *monitoringReadTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "safety_lock_rollout") {
		return nil, errors.New("unexpected query")
	}
	f.reads++
	return f.base, nil
}
func (f *monitoringReadTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if !strings.Contains(sql, "safety_rollout_monitoring") {
		return monitoringScanRow{err: errors.New("unexpected row query")}
	}
	f.reads++
	return f.monitoring
}
func TestRolloutLockCompleteValidatedSnapshotAndFailedReadNotCached(t *testing.T) {
	for _, failure := range []string{"", "scan", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			_, _, scope, s := rolloutAdapterFixture()
			s.State = domain.RolloutMonitoring
			m := deadlineHoldWindow()
			root := *s.TargetRoot
			target := s.Targets[root]
			base := []any{s.ID, s.Scope, string(s.State), pgtype.Text{String: string(root), Valid: true}, s.BaseActivationEpoch, s.LastActivationEpoch, s.BaseSecurityEpoch, pgtype.Text{}, pgtype.Text{String: string(root), Valid: true}, pgtype.Text{String: string(target.Baseline.Digest), Valid: true}, pgtype.Text{String: string(target.Candidate.Digest), Valid: true}, pgtype.Int8{Int64: int64(target.BaseRootEpoch), Valid: true}}
			wire := deadlineValues(m)
			row := monitoringScanRow{values: wire}
			if failure == "scan" {
				row.err = errors.New("scan")
			}
			if failure == "invalid" {
				wire[len(wire)-1] = int64(-1)
			}
			tx := &monitoringReadTx{base: &deadlineRows{values: [][]any{base}}, monitoring: row}
			g := &rolloutGovernanceTx{safetyGovernanceTx: newSafetyGovernanceTx(tx)}
			if _, err := g.LockRollout(context.Background(), s.Scope, s.ID); !errors.Is(err, ErrScopeNotLocked) {
				t.Fatal(err)
			}
			g.lockedScopes[s.Scope] = scope
			got, err := g.LockRollout(context.Background(), s.Scope, s.ID)
			if failure != "" {
				if err == nil || len(g.lockedRollouts) != 0 {
					t.Fatal("cached partial read")
				}
				return
			}
			if err != nil || got.Monitoring != m {
				t.Fatalf("%+v %v", got, err)
			}
			got.Targets[root] = port.RolloutTargetSnapshot{}
			again, err := g.LockRollout(context.Background(), s.Scope, s.ID)
			if err != nil || again.Targets[root] != target || tx.reads != 2 {
				t.Fatal("cache aliases or repeated query")
			}
		})
	}
}

func TestRolloutCASChecksEveryMonitoringFieldBeforeSQL(t *testing.T) {
	m := deadlineHoldWindow()
	typ := reflect.TypeOf(m)
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			g, tx, _, s := rolloutAdapterFixture()
			s.State = domain.RolloutMonitoring
			s.Monitoring = m
			g.lockedRollouts[rolloutKey{scope: s.Scope, rollout: s.ID}] = cloneRollout(s)
			expected := cloneRollout(s)
			v := reflect.ValueOf(&expected.Monitoring).Elem().Field(i)
			switch v.Kind() {
			case reflect.Struct:
				v.Set(reflect.ValueOf(v.Interface().(time.Time).Add(time.Microsecond)))
			case reflect.Int64:
				v.SetInt(v.Int() + 1)
			case reflect.Bool:
				v.SetBool(!v.Bool())
			case reflect.String:
				v.SetString(v.String() + "x")
			default:
				t.Fatal("uncovered field")
			}
			if err := g.CompareAndSwapRollout(context.Background(), expected, s); !errors.Is(err, port.ErrStaleWrite) || len(tx.calls) != 0 {
				t.Fatalf("unfenced %s: %v", typ.Field(i).Name, err)
			}
		})
	}
}
func TestRolloutTransactorGovernanceAdapter(t *testing.T) {
	tx := &fakeTransaction{}
	transactor := &RolloutTransactor{transactor: &Transactor{pool: fakeBeginner{tx: tx}, safetyAPI: true}}
	err := transactor.WithinTransaction(context.Background(), func(g port.GovernanceTx) error {
		if _, ok := g.(*rolloutGovernanceTx); !ok {
			t.Fatal("base-only adapter")
		}
		return nil
	})
	if err != nil || tx.commits != 1 {
		t.Fatal(err)
	}
	if err := transactor.WithinTransaction(context.Background(), nil); err == nil {
		t.Fatal("nil callback")
	}
}
