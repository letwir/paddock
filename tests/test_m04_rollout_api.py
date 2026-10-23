"""Offline M04-S01 source contracts. Never connects to or executes PostgreSQL."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = {
    "safety_create_rollout": "text,text,bigint,bigint,json",
    "safety_cas_rollout": "text,text,bigint,text,text,text,text,bigint,bigint,bigint,text,text",
    "safety_cas_rollout_target": "text,text,bigint,text,text,text,text,text,bigint",
}


class RolloutAPIStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = (ROOT / "sql/governance_rollout_api.sql").read_text().lower()
        cls.adapter = (ROOT / "internal/storage/postgres/rollout_governance_tx.go").read_text()
        cls.transactor = (ROOT / "internal/storage/postgres/rollout_transactor.go").read_text()

    def body(self, name):
        match = re.search(rf"create or replace function raw\.{name}\s*\(.*?\${name}\$;", self.sql, re.S)
        self.assertIsNotNone(match, name)
        return match.group()

    def test_guarded_migrator_owned_fixed_path_app_only_capabilities(self):
        self.assertRegex(self.sql, r"current_database\(\) <> 'paddock_test'")
        self.assertIn("current_user <> 'paddock_migrator'", self.sql)
        self.assertIn("session_user <> 'paddock_migrator'", self.sql)
        self.assertIn("pg_catalog.pg_auth_members", self.sql)
        self.assertIn("not rolsuper", self.sql)
        compact = re.sub(r"\s+", "", self.sql)
        for name, signature in FUNCTIONS.items():
            with self.subTest(name=name):
                body = self.body(name)
                self.assertIn("security definer set search_path = pg_catalog", body)
                self.assertIn("if session_user <> 'paddock_app' then", body)
                self.assertIn(f"alterfunctionraw.{name}({signature})ownertopaddock_migrator;", compact)
                self.assertRegex(self.sql, rf"revoke all on function[^;]*raw\.{name}\([^;]*from public, paddock_app;")
                self.assertRegex(self.sql, rf"grant execute on function[^;]*raw\.{name}\([^;]*to paddock_app;")
                self.assertIn(f"pg_catalog.to_regprocedure('raw.{name}({signature})')", self.sql)
        # Existing non-owner ACLs must also be removed on CREATE OR REPLACE.
        self.assertIn("pg_catalog.aclexplode", self.sql)
        self.assertIn("acl.grantee <> p.proowner", self.sql)
        self.assertIn("acl.grantee <> 0", self.sql)
        self.assertIn("revoke all on function %s from %i", self.sql)
        self.assertEqual(len(re.findall(r"\bgrant\s+", self.sql)), 1)
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+(?:table\s+)?raw\.")
        self.assertNotRegex(self.sql, r"\bgrant\s+(?:select|insert|update|delete|all)\b")
        self.assertNotRegex(self.sql, r"\balter\s+table\b")

    def test_json_unique_keys_before_processing_and_exact_five_keys(self):
        body = self.body("safety_create_rollout")
        self.assertRegex(body, r"\(text, text, bigint, bigint, json\)\s*returns void")
        validation = body.index("$5 is json array with unique keys")
        # Ignore explanatory comments while checking actual executable ordering.
        code = re.sub(r"--[^\n]*", "", body)
        self.assertLess(code.index("$5 is json array with unique keys"), code.index("pg_catalog.json_array_elements($5)"))
        self.assertGreater(validation, 0)
        self.assertNotIn("::jsonb", code)
        self.assertIn("pg_catalog.json_object_keys(v_target)", body)
        self.assertIn("v_key_count <> 5 or v_unknown_key", body)
        self.assertIn("('root_id', 'target', 'baseline_digest', 'candidate_digest', 'base_root_epoch')", body)
        for field in ("root_id", "target", "baseline_digest", "candidate_digest", "base_root_epoch"):
            self.assertIn(f"json_typeof(v_target->'{field}')", body)
        for check in ("v_root_id = any(v_root_ids)", "v_target_root is null", "v_target_root is not null", "json_array_length($5) = 0"):
            self.assertIn(check, body)

    def test_creation_locks_scope_and_same_scope_roots_before_insert(self):
        body = self.body("safety_create_rollout")
        for check in ("s.scope_id = $2 for update", "v_scope.activation_epoch <> $3", "v_security_epoch <> $4", "v_scope.mode <> 'active'", "v_scope.live_rollout_id is not null", "where r.scope_id = $2 order by r.root_id for update", "r.scope_id = $2", "v_root.authorization_epoch", "v_root.effective_bundle_digest is distinct from", "v_root.safe_baseline is distinct from"):
            self.assertIn(check, body)
        self.assertLess(body.index("for update"), body.index("insert into raw.policy_rollouts"))
        self.assertIn("insert into raw.rollout_targets", body)
        self.assertIn("values ($1, $2, 'canary', v_target_root, $3, $3 + 1, $4)", body)

    def test_creation_serializes_security_epoch_check_before_any_insert(self):
        code = re.sub(r"--[^\n]*", "", self.body("safety_create_rollout"))
        # KEY SHARE does not conflict with a non-key security_epoch UPDATE.
        lock = re.search(
            r"select sg\.security_epoch into v_security_epoch from raw\.security_generation sg\s+"
            r"where sg\.singleton_id = true for share;", code)
        self.assertIsNotNone(lock, "Security Epoch must be protected by FOR SHARE")
        check = re.search(
            r"if not found or v_security_epoch <> \$4 or v_scope\.activation_epoch <> \$3\s+"
            r"or v_scope\.mode <> 'active' or v_scope\.live_rollout_id is not null then\s+"
            r"raise exception 'stale scope or security epoch';\s+end if;", code)
        self.assertIsNotNone(check, "expected epochs must reject stale creation")
        self.assertLess(lock.end(), check.start())
        inserts = list(re.finditer(r"\binsert\s+into\b", code))
        self.assertGreaterEqual(len(inserts), 2)
        for insert in inserts:
            self.assertLess(check.end(), insert.start())

    def test_cas_predicates_match_existing_generic_contract_exactly(self):
        generic = (ROOT / "internal/storage/postgres/governance_tx.go").read_text().lower()
        generic = generic[generic.index("func (g *governancetx) compareandswaprollout"):]
        for name, relation in (("safety_cas_rollout", "policy_rollouts"), ("safety_cas_rollout_target", "rollout_targets")):
            with self.subTest(name=name):
                # SQL whitespace is immaterial. Compare SET and every WHERE predicate,
                # not just a token list which could miss a weakened predicate.
                existing = re.search(rf"update raw\.{relation}\s+set.*?`", generic, re.S).group()[:-1]
                capability = re.search(rf"update raw\.{relation}\s+set.*?;", self.body(name), re.S).group()[:-1]
                normalize = lambda s: re.sub(r"\s+", " ", s).strip()
                self.assertEqual(normalize(existing), normalize(capability))
                self.assertIn("returns boolean", self.body(name))
                self.assertIn("return found;", self.body(name))

    def test_adapter_routes_only_create_and_cas_and_reuses_safety_lifecycle(self):
        self.assertIn("NewSafetyTransactor(pool)", self.transactor)
        self.assertIn("t.transactor.WithinTransaction(ctx", self.transactor)
        self.assertIn("*safetyGovernanceTx", self.adapter)
        self.assertIn("func (g *rolloutGovernanceTx) CompareAndSwapRollout", self.adapter)
        for name in FUNCTIONS:
            self.assertIn(f"SELECT raw.{name}(", self.adapter)
        self.assertIn("$5::json", self.adapter)
        self.assertIn("reflect.DeepEqual(locked, expected)", self.adapter)
        self.assertIn("sameTargetIDs(expected.Targets, next.Targets)", self.adapter)
        self.assertIn("sortedTargetIDs(expected.Targets)", self.adapter)
        self.assertIn("if !updated", self.adapter)
        self.assertIn("return port.ErrStaleWrite", self.adapter)
        self.assertNotRegex(self.adapter, r"(?i)\b(?:insert into|update|delete from)\s+raw\.")
        self.assertNotIn(".Begin(", self.adapter)
        self.assertNotIn(".Commit(", self.adapter)

    def test_integration_source_is_opt_in(self):
        source = (ROOT / "internal/storage/postgres/rollout_application_integration_test.go").read_text()
        self.assertTrue(source.startswith("//go:build integration && paddock_test\n"))
        for token in ("NewRolloutTransactor", ".StartCanary(", ".Promote(", ".Rollback("):
            self.assertIn(token, source)
        self.assertIn("SELECT live_rollout_id IS NOT DISTINCT FROM $2 FROM raw.policy_scopes WHERE scope_id=$1", source)
        self.assertIn("string(scope), string(rid)).Scan(&liveCanary)", source)
        self.assertIn("err != nil || !liveCanary", source)
        for token in ("creation blocks concurrent Security Epoch advance", "SET LOCAL lock_timeout", "SELECT raw.safety_cas_security_epoch($1,$2)", 'pgErr.Code != "55P03"'):
            self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
