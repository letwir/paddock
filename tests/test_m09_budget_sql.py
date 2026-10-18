from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "sql/governance_budget.sql").read_text(encoding="utf-8").lower()
STORE = (ROOT / "internal/storage/postgres/budget_store.go").read_text(encoding="utf-8")

class BudgetSQLContractTests(unittest.TestCase):
    def test_guard_and_no_destructive_ddl(self):
        self.assertIn("current_database()<>'paddock_test'", SQL)
        self.assertIn("current_user<>'paddock_migrator'", SQL)
        self.assertNotRegex(SQL, r"\b(drop|create extension|alter database)\b")

    def test_root_grant_is_session_migrator_only(self):
        guard = SQL.index("if kind='grant' then if session_user<>'paddock_migrator'")
        replay = SQL.index("select bo.request,bo.result into oldreq,oldresult")
        self.assertLess(guard, replay)
        self.assertIn("insert into raw.budget_operations(operation_id,operation_kind,request,result)", SQL)
        self.assertIn("grant execute on function raw.budget_apply", SQL)
        self.assertIn('"GRANT"', STORE)
        self.assertIn('session_user', SQL)

    def test_function_replay_is_replaceable_and_qualified(self):
        self.assertIn("create or replace function raw.budget_apply(text,text,jsonb)", SQL)
        self.assertIn("select bo.request,bo.result into oldreq,oldresult from raw.budget_operations as bo where bo.operation_id=opid", SQL)
        replay = SQL.split("-- serialize globally by operation id", 1)[1].split("aid:=req->>'account_id'", 1)[0]
        self.assertNotRegex(replay, r"\bselect\s+(?:request|result|operation_kind)\b")

    def test_allocation_identity_and_exact_settlement(self):
        declaration = SQL.split("create or replace function raw.budget_apply(text,text,jsonb)", 1)[1].split("begin", 1)[0]
        self.assertRegex(declaration, r"\bp\s+raw\.budget_allocations%rowtype\b")
        self.assertNotRegex(declaration, r"\bp\s+raw\.budget_accounts%rowtype\b")
        for token in ("create table raw.budget_allocations", "allocation_id uuid primary key default gen_random_uuid()",
                      "parent_account_id text not null", "child_account_id text not null unique", "state in ('open','settled')",
                      "insert into raw.budget_allocations(parent_account_id,child_account_id,amount,state)",
                      "returning allocation_id into allocid", "set allocation_id=allocid where account_id=childid",
                      "'allocation_id',allocid", "req->>'allocation_id'",
                      "p.parent_account_id<>aid", "p.child_account_id<>childid", "p.amount<>c.granted", "c.allocation_id<>allocid",
                      "set state='settled'"):
            self.assertIn(token, SQL)
        self.assertIn('json:"allocation_id,omitempty"', STORE)
        self.assertIn('allocationID string', STORE)
        self.assertIn('AllocationID string', STORE)
        self.assertIn("'allocation_id',allocid", SQL)

    def test_unit_nfc_whitespace_controls_and_go_validation(self):
        self.assertIn("convert_to(v,'utf8')<>convert_to(normalize(v,nfc),'utf8')", SQL)
        self.assertNotIn("v<>normalize(v,nfc)", SQL)
        self.assertIn('unit_code text collate "c" not null', SQL)
        self.assertIn("ascii(substr(v,1,1))", SQL)
        self.assertIn("ascii(substr(v,char_length(v),1))", SQL)
        self.assertNotRegex(SQL, r"\bunicode\s*\(")
        self.assertIn("cp between 0 and 31", SQL)
        self.assertIn("cp between 127 and 159", SQL)
        self.assertIn("server_encoding')<>'utf8'", SQL)
        self.assertIn("gen_random_uuid()", SQL)
        self.assertIn("norm.NFC.IsNormalString", STORE)
        self.assertIn("utf8.ValidString", STORE)
        self.assertIn("unicode.IsControl", STORE)
        self.assertIn("unicode.IsSpace", STORE)

    def test_invariant_replay_lock_journal_privileges(self):
        self.assertIn("spent<=granted and reserved<=granted-spent and delegated<=granted-spent-reserved", SQL)
        self.assertIn("oldreq<>req", SQL)
        self.assertIn("operation id replay conflict", SQL)
        self.assertIn("pg_advisory_xact_lock(hashtextextended(opid,0))", SQL)
        self.assertIn("for update", SQL)
        self.assertIn("budget_journal_immutable before update or delete", SQL)
        self.assertIn("revoke all on raw.budget_accounts,raw.budget_allocations,raw.budget_operations,raw.budget_journal from public,paddock_app", SQL)
        self.assertIn("revoke all on function raw.budget_unit_valid(text) from public,paddock_app", SQL)
        self.assertIn("revoke all on function raw.budget_apply(text,text,jsonb) from public,paddock_app", SQL)
        self.assertIn("security definer set search_path=pg_catalog", SQL)

    def test_journal_explicit_deltas_per_account_and_operation_sequence(self):
        for token in ("granted_delta bigint not null", "spent_delta bigint not null",
                      "reserved_delta bigint not null", "delegated_delta bigint not null",
                      "unique(operation_id,event_seq)", "event_seq integer not null",
                      "operation_id text not null references raw.budget_operations(operation_id)",
                      "allocation_id uuid references raw.budget_allocations(allocation_id)"):
            self.assertIn(token, SQL)
        self.assertNotIn("operation_id text not null unique references raw.budget_operations", SQL)
        self.assertIn("budget_journal_immutable before update or delete", SQL)
        self.assertIn("values(opid,1,aid,'grant',amount,0,0,0)", SQL)
        delegate = SQL.split("if kind='delegate' then", 1)[1].split("elsif kind='reserve' then", 1)[0]
        # Both account movements are explicit and share allocation identity.
        self.assertIn("values(opid,1,aid,allocid,kind,0,0,0,amount,childid),(opid,2,childid,allocid,kind,amount,0,0,0,aid)", SQL)
        settle_child = SQL.split("elsif kind='settle_child' then", 1)[1].split("else\n  insert into raw.budget_journal", 1)[0]
        self.assertIn("-p.amount", settle_child)
        self.assertIn("c.spent", settle_child)
        self.assertIn("opid,2,childid,allocid,kind,0,0,0,0,aid", settle_child)
        self.assertRegex(SQL, r"when kind='reserve' then amount")
        self.assertRegex(SQL, r"when kind='settle_reservation' then actual else 0 end")
        self.assertRegex(SQL, r"when kind in \('settle_reservation','release'\) then -reserve_amount")
        self.assertRegex(SQL, r"when kind='settle_reservation' then actual else 0 end,case")

    def test_delegate_compares_and_validates_unit_bytes(self):
        delegate = SQL.split("if kind='delegate' then", 1)[1].split("elsif kind='reserve' then", 1)[0]
        self.assertIn("not raw.budget_unit_valid(req->>'unit_code')", delegate)
        self.assertIn("convert_to(req->>'unit_code','utf8') is distinct from convert_to(a.unit_code,'utf8')", delegate)
        self.assertNotIn("(req->>'unit_code') is distinct from a.unit_code", delegate)

    def test_go_adapter_uses_exact_allocation_and_validates_units(self):
        self.assertIn('raw.budget_apply($1,$2,$3::jsonb)', STORE)
        self.assertIn("func (s *BudgetStore) SettleChild(ctx context.Context, op domain.BudgetOperation, parentID, childID, allocationID string)", STORE)
        self.assertIn("validBudgetUnit", STORE)
        self.assertIn("SettleReservation", STORE)
        self.assertIn("ReleaseReservation", STORE)

if __name__ == "__main__":
    unittest.main()
