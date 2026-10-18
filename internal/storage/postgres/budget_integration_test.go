//go:build paddock_test

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/domain"
)

// This test intentionally retains its uniquely-named fixtures: the budget journal is append-only.
func TestBudgetLedgerAcceptance(t *testing.T) {
	setupURL, appURL := os.Getenv("PADDOCK_DB_URL"), os.Getenv("PADDOCK_APP_DB_URL")
	if setupURL == "" || appURL == "" {
		t.Fatal("PADDOCK_DB_URL and PADDOCK_APP_DB_URL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	migrator, err := openPullPool(ctx, setupURL, false)
	if err != nil {
		t.Fatal("cannot connect migrator fixture database")
	}
	t.Cleanup(migrator.Close)
	var db, migratorUser string
	if err := migrator.QueryRow(ctx, `SELECT current_database(), current_user`).Scan(&db, &migratorUser); err != nil || db != "paddock_test" || migratorUser != "paddock_migrator" {
		t.Fatal("migrator connection must target paddock_test as paddock_migrator")
	}
	app, err := openPullPool(ctx, appURL, true)
	if err != nil {
		t.Fatal("app connection must target paddock_test as paddock_app")
	}
	t.Cleanup(app.Close)
	var dbApp, appUser string
	if err := app.QueryRow(ctx, `SELECT current_database(), current_user`).Scan(&dbApp, &appUser); err != nil || dbApp != "paddock_test" || appUser != "paddock_app" {
		t.Fatal("app connection must use paddock_test as paddock_app")
	}

	suffixBytes := make([]byte, 12)
	if _, err := rand.Read(suffixBytes); err != nil {
		t.Fatal("cannot generate fixture identifier")
	}
	suffix := hex.EncodeToString(suffixBytes)
	scopeID := "m09_it_scope_" + suffix
	rootID := "m09_it_root_" + suffix
	parent := "m09_it_account_" + suffix
	childA, childB := "m09_it_account_a_"+suffix, "m09_it_account_b_"+suffix
	childLimit, childCross := "m09_it_account_limit_"+suffix, "m09_it_account_cross_"+suffix
	storageParent, storageChild, storageBadUnitChild := "m09_it_account_storage_"+suffix, "m09_it_account_storage_child_"+suffix, "m09_it_account_storage_bad_unit_"+suffix
	unit := "m09_it_unit_" + suffix
	crossUnit := "m09_it_other_unit_" + suffix
	storageIDs := []string{"storage_grant_" + suffix, "storage_delegate_" + suffix, "storage_reserve_" + suffix, "storage_settle_reserve_" + suffix, "storage_close_" + suffix, "storage_settle_child_" + suffix, "storage_bad_unit_" + suffix}
	ids := []string{"grant_" + suffix, "deny_grant_" + suffix, "delegate_a_" + suffix, "delegate_b_" + suffix, "close_a_" + suffix, "settle_child_" + suffix, "reserve_" + suffix, "settle_reserve_" + suffix, "release_" + suffix, "replay_" + suffix, "conflict_" + suffix, "over_limit_" + suffix, "cross_unit_" + suffix}
	for i := range ids {
		ids[i] = "m09_it_" + ids[i]
	}
	for i := range storageIDs {
		storageIDs[i] = "m09_it_" + storageIDs[i]
	}
	// Refuse any generated-namespace collision before writing; never overwrite retained fixtures.
	var collision bool
	if err := migrator.QueryRow(ctx, `SELECT
		 EXISTS(SELECT 1 FROM raw.policy_scopes WHERE scope_id=$4) OR
		 EXISTS(SELECT 1 FROM raw.roots WHERE root_id=$5) OR
		 EXISTS(SELECT 1 FROM raw.budget_accounts WHERE account_id = ANY($1::text[])) OR
		 EXISTS(SELECT 1 FROM raw.budget_operations WHERE operation_id = ANY($2::text[])) OR
		 EXISTS(SELECT 1 FROM raw.budget_accounts WHERE unit_code = ANY($3::text[])) OR
		 EXISTS(SELECT 1 FROM raw.budget_accounts WHERE account_id = ANY($6::text[])) OR
		 EXISTS(SELECT 1 FROM raw.budget_operations WHERE operation_id = ANY($7::text[]))`, []string{parent, childA, childB, childLimit, childCross}, ids, []string{unit, crossUnit}, scopeID, rootID, []string{storageParent, storageChild, storageBadUnitChild}, storageIDs).Scan(&collision); err != nil || collision {
		t.Fatal("m09_it_ fixture namespace preflight failed or collided; refusing to continue")
	}
	// Fixtures are intentionally retained (like the append-only budget journal). Log both IDs
	// before the first write so setup failures still identify any partially retained fixture.
	t.Logf("retained M09 scope/root/accounts/operation IDs: scope=%s root=%s accounts=%s,%s,%s,%s,%s,%s,%s,%s operations=%s", scopeID, rootID, parent, childA, childB, childLimit, childCross, storageParent, storageChild, storageBadUnitChild, strings.Join(append(ids, storageIDs...), ","))
	if _, err := migrator.Exec(ctx, `INSERT INTO raw.policy_scopes(scope_id,mode) VALUES ($1,'SAFE_STOPPED')`, scopeID); err != nil {
		t.Fatalf("cannot create retained M09 scope fixture %s (root=%s): %v", scopeID, rootID, err)
	}
	if _, err := migrator.Exec(ctx, `INSERT INTO raw.roots(root_id,scope_id,safe_baseline) VALUES ($1,$2,true)`, rootID, scopeID); err != nil {
		t.Fatalf("cannot create retained M09 root fixture %s (scope=%s); scope may remain retained: %v", rootID, scopeID, err)
	}
	store, err := NewBudgetStore(app)
	if err != nil {
		t.Fatal("cannot initialize app BudgetStore")
	}
	key := domain.BudgetKey{RootID: rootID, ResourceKind: string(domain.ResourceTokens), UnitCode: unit}
	grantOp := domain.BudgetOperation{OperationID: ids[0], Amount: 100}
	if _, err := store.InitializeRootGrant(ctx, grantOp, parent, key); err == nil {
		t.Fatal("app BudgetStore.InitializeRootGrant unexpectedly granted authority")
	}
	// The migrator-only ledger entry point seeds the modest parent grant; no migration is run here.
	var grantResult []byte
	if err := migrator.QueryRow(ctx, `SELECT raw.budget_apply($1,'GRANT',$2::jsonb)`, ids[0], jsonGrant(parent, rootID, unit, int64(grantOp.Amount))).Scan(&grantResult); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.Fatalf("migrator-only root grant failed (SQLSTATE %s)", pgErr.Code)
		}
		t.Fatal("migrator-only root grant failed (SQLSTATE unavailable)")
	}
	storageKey := domain.BudgetKey{RootID: rootID, ResourceKind: string(domain.ResourceStorageBytes), UnitCode: "byte"}
	if _, err := store.InitializeRootGrant(ctx, domain.BudgetOperation{OperationID: storageIDs[0], Amount: 1000}, storageParent, storageKey); err == nil {
		t.Fatal("app BudgetStore.InitializeRootGrant unexpectedly granted STORAGE_BYTES authority")
	}
	var storageGrantResult []byte
	if err := migrator.QueryRow(ctx, `SELECT raw.budget_apply($1,'GRANT',$2::jsonb)`, storageIDs[0], jsonResourceGrant(storageParent, rootID, storageKey.ResourceKind, storageKey.UnitCode, 1000)).Scan(&storageGrantResult); err != nil {
		t.Fatal("migrator-only STORAGE_BYTES root grant failed")
	}

	// Concurrent attempts each request more than half the remaining balance; exactly one can win.
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, child := range []string{childA, childB} {
		wg.Add(1)
		go func(i int, child string) {
			defer wg.Done()
			<-start
			_, e := store.Delegate(ctx, domain.BudgetOperation{OperationID: ids[2+i], Amount: 60}, parent, child, key)
			results <- e
		}(i, child)
	}
	close(start)
	wg.Wait()
	close(results)
	winnerCount := 0
	for e := range results {
		if e == nil {
			winnerCount++
		}
	}
	if winnerCount != 1 {
		t.Fatalf("concurrent delegation expected exactly one success, got %d", winnerCount)
	}

	var winningChild, allocationID string
	if err := migrator.QueryRow(ctx, `SELECT child_account_id, allocation_id::text FROM raw.budget_allocations WHERE parent_account_id=$1 AND state='OPEN'`, parent).Scan(&winningChild, &allocationID); err != nil {
		t.Fatal("cannot read winning allocation")
	}
	var delegateOp string
	if winningChild == childA {
		delegateOp = ids[2]
	} else if winningChild == childB {
		delegateOp = ids[3]
	} else {
		t.Fatal("unexpected child account in winning allocation")
	}
	var originalDelegationJSON []byte
	if err := migrator.QueryRow(ctx, `SELECT result FROM raw.budget_operations WHERE operation_id=$1`, delegateOp).Scan(&originalDelegationJSON); err != nil {
		t.Fatal("cannot read original delegation result")
	}
	delegationJSON, err := store.Delegate(ctx, domain.BudgetOperation{OperationID: delegateOp, Amount: 60}, parent, winningChild, key)
	if err != nil {
		t.Fatal("same-operation delegation replay failed")
	}
	var replay struct {
		AllocationID string `json:"allocation_id"`
	}
	if !jsonEqual(originalDelegationJSON, delegationJSON) || json.Unmarshal(delegationJSON, &replay) != nil || replay.AllocationID != allocationID {
		t.Fatal("delegation replay returned a different allocation ID")
	}
	t.Logf("retained token allocation: allocation=%s parent=%s child=%s", allocationID, parent, winningChild)
	var childAccount string
	if err := migrator.QueryRow(ctx, `SELECT account_id FROM raw.budget_accounts WHERE account_id=$1`, winningChild).Scan(&childAccount); err != nil {
		t.Fatal("winning child missing")
	}
	if _, err := store.Reserve(ctx, domain.BudgetOperation{OperationID: ids[6], Amount: 20}, winningChild); err != nil {
		t.Fatal("child reservation failed")
	}
	if _, err := store.SettleReservation(ctx, domain.BudgetOperation{OperationID: ids[7]}, winningChild, 20, 12); err != nil {
		t.Fatal("child reservation settlement failed")
	}
	if _, err := store.Reserve(ctx, domain.BudgetOperation{OperationID: ids[9], Amount: 8}, winningChild); err != nil {
		t.Fatal("unused reservation setup failed")
	}
	if _, err := store.ReleaseReservation(ctx, domain.BudgetOperation{OperationID: ids[8]}, winningChild, 8); err != nil {
		t.Fatal("unused reservation release failed")
	}
	if _, err := store.CloseChild(ctx, domain.BudgetOperation{OperationID: ids[4]}, winningChild); err != nil {
		t.Fatal("child close failed")
	}
	settleOp := domain.BudgetOperation{OperationID: ids[5]}
	settleResult, err := store.SettleChild(ctx, settleOp, parent, winningChild, allocationID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.Fatalf("child allocation settlement failed (SQLSTATE %s)", pgErr.Code)
		}
		t.Fatalf("child allocation settlement failed (error type %T)", err)
	}
	settleReplay, err := store.SettleChild(ctx, settleOp, parent, winningChild, allocationID)
	if err != nil || !jsonEqual(settleResult, settleReplay) {
		t.Fatal("settlement replay did not return the identical JSON result")
	}
	_, conflictError := store.Reserve(ctx, domain.BudgetOperation{OperationID: ids[5], Amount: 1}, parent)
	if conflictError == nil {
		t.Fatal("conflicting operation ID/request was accepted")
	}
	if _, err := store.Delegate(ctx, domain.BudgetOperation{OperationID: ids[11], Amount: 101}, parent, childLimit, key); err == nil {
		t.Fatal("over-limit delegation was accepted")
	}
	crossKey := key
	crossKey.UnitCode = crossUnit
	if _, err := store.Delegate(ctx, domain.BudgetOperation{OperationID: ids[12], Amount: 1}, parent, childCross, crossKey); err == nil {
		t.Fatal("cross-unit delegation was accepted")
	}
	if _, err := store.Delegate(ctx, domain.BudgetOperation{OperationID: storageIDs[6], Amount: 1}, storageParent, storageBadUnitChild, domain.BudgetKey{RootID: rootID, ResourceKind: string(domain.ResourceStorageBytes), UnitCode: "KiB"}); err == nil {
		t.Fatal("STORAGE_BYTES delegation with wrong unit was accepted")
	}
	storageAllocationJSON, err := store.Delegate(ctx, domain.BudgetOperation{OperationID: storageIDs[1], Amount: 400}, storageParent, storageChild, storageKey)
	if err != nil {
		t.Fatalf("STORAGE_BYTES delegation failed: %v", err)
	}
	var storageAllocation struct {
		AllocationID string `json:"allocation_id"`
	}
	if json.Unmarshal(storageAllocationJSON, &storageAllocation) != nil || storageAllocation.AllocationID == "" {
		t.Fatal("STORAGE_BYTES delegation returned invalid allocation ID")
	}
	t.Logf("retained STORAGE_BYTES allocation: allocation=%s parent=%s child=%s", storageAllocation.AllocationID, storageParent, storageChild)
	if _, err := store.Reserve(ctx, domain.BudgetOperation{OperationID: storageIDs[2], Amount: 300}, storageChild); err != nil {
		t.Fatalf("STORAGE_BYTES reservation failed: %v", err)
	}
	if _, err := store.SettleReservation(ctx, domain.BudgetOperation{OperationID: storageIDs[3]}, storageChild, 300, 237); err != nil {
		t.Fatalf("STORAGE_BYTES reservation settlement failed: %v", err)
	}
	if _, err := store.CloseChild(ctx, domain.BudgetOperation{OperationID: storageIDs[4]}, storageChild); err != nil {
		t.Fatalf("STORAGE_BYTES child close failed: %v", err)
	}
	if _, err := store.SettleChild(ctx, domain.BudgetOperation{OperationID: storageIDs[5]}, storageParent, storageChild, storageAllocation.AllocationID); err != nil {
		t.Fatalf("STORAGE_BYTES allocation settlement failed: %v", err)
	}

	// Independent migrator readback: balances, operation/event_seq rows, and exact account deltas.
	var granted, spent, reserved, delegated int64
	if err := migrator.QueryRow(ctx, `SELECT granted,spent,reserved,delegated FROM raw.budget_accounts WHERE account_id=$1`, parent).Scan(&granted, &spent, &reserved, &delegated); err != nil {
		t.Fatal("parent counter readback failed")
	}
	if granted != 100 || spent != 12 || reserved != 0 || delegated != 0 || spent+reserved+delegated > granted {
		t.Fatalf("parent invariant/balance mismatch: granted=%d spent=%d reserved=%d delegated=%d", granted, spent, reserved, delegated)
	}
	var deltaGranted, deltaSpent, deltaReserved, deltaDelegated int64
	if err := migrator.QueryRow(ctx, `SELECT COALESCE(sum(granted_delta),0), COALESCE(sum(spent_delta),0), COALESCE(sum(reserved_delta),0), COALESCE(sum(delegated_delta),0) FROM raw.budget_journal WHERE account_id=$1`, parent).Scan(&deltaGranted, &deltaSpent, &deltaReserved, &deltaDelegated); err != nil || deltaGranted != granted || deltaSpent != spent || deltaReserved != reserved || deltaDelegated != delegated {
		t.Fatal("parent journal deltas do not reconcile with counters")
	}
	var childGranted, childSpent, childReserved, childDelegated int64
	if err := migrator.QueryRow(ctx, `SELECT granted,spent,reserved,delegated FROM raw.budget_accounts WHERE account_id=$1`, winningChild).Scan(&childGranted, &childSpent, &childReserved, &childDelegated); err != nil || childGranted != 60 || childSpent != 12 || childReserved != 0 || childDelegated != 0 {
		t.Fatal("child counter readback/invariant failed")
	}
	if err := migrator.QueryRow(ctx, `SELECT COALESCE(sum(granted_delta),0), COALESCE(sum(spent_delta),0), COALESCE(sum(reserved_delta),0), COALESCE(sum(delegated_delta),0) FROM raw.budget_journal WHERE account_id=$1`, winningChild).Scan(&deltaGranted, &deltaSpent, &deltaReserved, &deltaDelegated); err != nil || deltaGranted != childGranted || deltaSpent != childSpent || deltaReserved != childReserved || deltaDelegated != childDelegated {
		t.Fatal("child journal deltas do not reconcile with counters")
	}
	var storageResourceKind, storageUnitCode string
	var storageGranted, storageSpent, storageReserved, storageDelegated int64
	if err := migrator.QueryRow(ctx, `SELECT resource_kind,unit_code,granted,spent,reserved,delegated FROM raw.budget_accounts WHERE account_id=$1`, storageChild).Scan(&storageResourceKind, &storageUnitCode, &storageGranted, &storageSpent, &storageReserved, &storageDelegated); err != nil || storageResourceKind != string(domain.ResourceStorageBytes) || storageUnitCode != "byte" || storageGranted != 400 || storageSpent != 237 || storageReserved != 0 || storageDelegated != 0 {
		t.Fatalf("STORAGE_BYTES child counter readback failed: granted=%d spent=%d reserved=%d delegated=%d", storageGranted, storageSpent, storageReserved, storageDelegated)
	}
	if err := migrator.QueryRow(ctx, `SELECT COALESCE(sum(j.granted_delta),0), COALESCE(sum(j.spent_delta),0), COALESCE(sum(j.reserved_delta),0), COALESCE(sum(j.delegated_delta),0) FROM raw.budget_journal j JOIN raw.budget_accounts a ON a.account_id=j.account_id WHERE j.account_id=$1 AND a.resource_kind=$2 AND a.unit_code=$3`, storageChild, string(domain.ResourceStorageBytes), "byte").Scan(&deltaGranted, &deltaSpent, &deltaReserved, &deltaDelegated); err != nil || deltaGranted != storageGranted || deltaSpent != storageSpent || deltaReserved != storageReserved || deltaDelegated != storageDelegated {
		t.Fatal("STORAGE_BYTES child journal deltas do not reconcile with counters")
	}
	if err := migrator.QueryRow(ctx, `SELECT resource_kind,unit_code,granted,spent,reserved,delegated FROM raw.budget_accounts WHERE account_id=$1`, storageParent).Scan(&storageResourceKind, &storageUnitCode, &storageGranted, &storageSpent, &storageReserved, &storageDelegated); err != nil || storageResourceKind != string(domain.ResourceStorageBytes) || storageUnitCode != "byte" || storageGranted != 1000 || storageSpent != 237 || storageReserved != 0 || storageDelegated != 0 {
		t.Fatalf("STORAGE_BYTES parent counter readback failed: granted=%d spent=%d reserved=%d delegated=%d", storageGranted, storageSpent, storageReserved, storageDelegated)
	}
	if err := migrator.QueryRow(ctx, `SELECT COALESCE(sum(j.granted_delta),0), COALESCE(sum(j.spent_delta),0), COALESCE(sum(j.reserved_delta),0), COALESCE(sum(j.delegated_delta),0) FROM raw.budget_journal j JOIN raw.budget_accounts a ON a.account_id=j.account_id WHERE j.account_id=$1 AND a.resource_kind=$2 AND a.unit_code=$3`, storageParent, string(domain.ResourceStorageBytes), "byte").Scan(&deltaGranted, &deltaSpent, &deltaReserved, &deltaDelegated); err != nil || deltaGranted != storageGranted || deltaSpent != storageSpent || deltaReserved != storageReserved || deltaDelegated != storageDelegated {
		t.Fatal("STORAGE_BYTES parent journal deltas do not reconcile with counters")
	}
	var ops, events int
	if err := migrator.QueryRow(ctx, `SELECT count(DISTINCT operation_id), count(*) FROM raw.budget_journal WHERE operation_id IN (SELECT operation_id FROM raw.budget_operations WHERE operation_id LIKE 'm09_it_%' AND (request->>'account_id'=$1 OR request->>'child_id'=$2 OR operation_id=ANY($3::text[])))`, parent, winningChild, ids).Scan(&ops, &events); err != nil {
		t.Fatal("journal count readback failed")
	}
	if ops < 6 || events < 8 {
		t.Fatalf("expected retained operations/events, got operations=%d events=%d", ops, events)
	}
	var journalOK bool
	if err := migrator.QueryRow(ctx, `SELECT bool_and(event_seq>0) FROM raw.budget_journal WHERE operation_id=ANY($1::text[])`, ids).Scan(&journalOK); err != nil || !journalOK {
		t.Fatal("journal event_seq verification failed")
	}
	t.Logf("retained M09 fixture: scope=%s; root=%s; accounts=%s,%s,%s,%s; units=%s,byte; allocations=%s,%s; operations=%s; operation_count=%d event_count=%d", scopeID, rootID, parent, winningChild, storageParent, storageChild, unit, allocationID, storageAllocation.AllocationID, strings.Join(append(ids, storageIDs...), ","), ops, events)
}

func jsonGrant(account, root, unit string, amount int64) string {
	b, _ := json.Marshal(map[string]any{"account_id": account, "root_id": root, "resource_kind": string(domain.ResourceTokens), "unit_code": unit, "amount": amount})
	return string(b)
}
func jsonResourceGrant(account, root, resourceKind, unit string, amount int64) string {
	b, _ := json.Marshal(map[string]any{"account_id": account, "root_id": root, "resource_kind": resourceKind, "unit_code": unit, "amount": amount})
	return string(b)
}
func jsonEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
