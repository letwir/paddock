import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SQL = (ROOT / "sql/governance_offline_policy.sql").read_text(encoding="utf-8").lower()
GO = (ROOT / "internal/storage/postgres/offline_policy.go").read_text(encoding="utf-8")


class OfflinePolicySQLContract(unittest.TestCase):
    def test_migration_is_guarded_and_additive(self):
        self.assertIn("current_database()<>'paddock_test'", SQL)
        self.assertIn("current_user<>'paddock_migrator'", SQL)
        self.assertIn("not rolsuper", SQL)
        self.assertIn("pg_auth_members", SQL)
        self.assertIn("raw.work_orders", SQL)
        self.assertIn("raw.work_order_attempts", SQL)
        self.assertIn("raw.work_order_leases", SQL)
        self.assertNotRegex(SQL, r"\bdrop\s+(database|schema|table)\b")
        self.assertNotIn("create extension", SQL)

    def test_policy_configuration_is_queued_and_one_time(self):
        self.assertIn("pull_state,offline_policy_mode into st,configured", SQL)
        self.assertIn("st<>'queued' or configured is not null", SQL)
        self.assertIn("where work_order_id=p_order and root_id=p_root and pull_state='queued' and offline_policy_mode is null", SQL)
        self.assertIn("'online_required','offline_compute'", SQL)
        self.assertIn("'checkpointable','not_checkpointable'", SQL)
        self.assertIn("external_action_allowlist", SQL)
        self.assertIn("not ('*'=any(external_action_allowlist))", SQL)

    def test_authorizer_checks_all_fencing_and_allowlist_fields(self):
        for text in (
            "w.root_id=p_root", "w.work_order_id=p_order", "a.attempt_id=p_attempt",
            "l.worker_id=p_worker", "l.session_id=p_session", "w.lease_epoch=p_epoch",
            "l.lease_epoch=p_epoch", "l.expires_at>op_time", "clock_timestamp()",
            "w.policy_digest=p_digest", "w.offline_policy_mode='online_required'",
            "convert_to(p_action,'utf8')=any(",
            "select convert_to(allowed_action,'utf8')",
            "from unnest(w.external_action_allowlist) as actions(allowed_action)",
        ):
            self.assertIn(text, SQL)
        self.assertNotIn("p_action=any(w.external_action_allowlist)", SQL)

    def test_action_validation_uses_byte_exact_comparisons(self):
        configure = SQL.split("create function raw.configure_work_order_offline_policy", 1)[1].split(
            "create function raw.authorize_work_order_external_action", 1
        )[0]
        self.assertIn("convert_to(x,'utf8')<>convert_to(btrim(x),'utf8')", configure)
        self.assertIn("count(distinct convert_to(x,'utf8'))", configure)
        self.assertIn("convert_to(x,'utf8') in (convert_to('*','utf8'),convert_to('%','utf8'))", configure)

    def test_app_has_only_narrow_function_execution(self):
        self.assertIn("grant execute on function raw.configure_work_order_offline_policy", SQL)
        self.assertIn("grant execute on function raw.configure_work_order_offline_policy(text,text,text,text,bytea,text),raw.authorize_work_order_external_action", SQL)
        self.assertIn("revoke all on table raw.work_orders,raw.work_order_attempts,raw.work_order_leases from public,paddock_app", SQL)
        self.assertNotRegex(SQL, r"grant\s+(select|insert|update|delete|all)\s+on\s+table[^;]*paddock_app")
        self.assertIn("policy.CanonicalBytes()", GO)
        self.assertIn("policy.Digest()", GO)
        self.assertIn("read_work_order_authorization", GO)
        self.assertIn("func (a *OfflinePolicyAuthorizer) ReadAuthorization", GO)
        self.assertIn("ErrAuthorizationUnavailable", GO)
        self.assertIn("time.Duration(remainingUS) * time.Microsecond", GO)

    def test_configuration_reconstructs_jcs_and_binds_exact_sha256(self):
        configure = SQL.split("create function raw.configure_work_order_offline_policy", 1)[1].split(
            "create function raw.authorize_work_order_external_action", 1
        )[0]
        for text in (
            "jsonb_object_keys(supplied)",
            "jsonb_array_elements(supplied->'external_actions')",
            "jsonb_array_elements(supplied->'low_risk_actions')",
            "count(*) from jsonb_object_keys(supplied))<>4",
            "raw.jcs_utf16_sort_key(v)",
            "raw.jcs_quote(v)",
            "expected_low_actions",
            "low_risk_actions=low_action_list",
            "not exists\n    (select 1 from unnest(action_list)",
            "expected_bytes:=convert_to('",
            "if p_canonical<>expected_bytes then return null",
            "actual_digest:=encode(pg_catalog.sha256(expected_bytes),'hex')",
            "if actual_digest<>p_digest then return null",
            "policy_canonical=expected_bytes",
            "policy_digest=actual_digest",
        ):
            self.assertIn(text, configure)
        self.assertNotIn("ascii", configure)

    def test_unicode_jcs_helpers_and_builtin_sha256_guard(self):
        self.assertIn("pg_catalog.to_regprocedure('pg_catalog.sha256(bytea)')", SQL)
        self.assertIn("current_setting('server_encoding')<>'utf8'", SQL)
        self.assertIn("create function raw.jcs_quote(p_value text)", SQL)
        self.assertIn("create function raw.jcs_utf16_sort_key(p_value text)", SQL)
        self.assertIn("backslash text:=chr(92)", SQL)
        self.assertIn("result:=result||backslash||'\"'", SQL)
        self.assertIn("result:=result||backslash||backslash", SQL)
        self.assertIn("result:=result||backslash||'u00'", SQL)
        quote = SQL.split("create function raw.jcs_quote(p_value text)", 1)[1].split("create function raw.jcs_utf16_sort_key", 1)[0]
        # Escape bytes come from chr(92), never backslashes in ordinary SQL constants;
        # this makes the RFC 8785 output independent of standard_conforming_strings.
        self.assertNotRegex(quote, r"'[^']*\\")
        self.assertIn("else result:=result||ch", SQL)
        self.assertNotIn("create extension", SQL)

    def test_go_canonical_policy_uses_utf16_order(self):
        domain = (ROOT / "internal/governance/domain/work_order_policy.go").read_text(encoding="utf-8")
        tests = (ROOT / "internal/governance/domain/work_order_policy_test.go").read_text(encoding="utf-8")
        self.assertIn("utf16.Encode", domain)
        self.assertIn("\\U00010000", tests)
        self.assertIn("\\ue000", tests)
        self.assertIn(r"\u0001", tests)
        self.assertIn("雪", tests)
        self.assertIn('"low_risk_actions":[]', tests)
        self.assertIn("LowRiskActions: []string{\"read\"}", tests)
        self.assertIn("changing low-risk classification did not change digest", tests)
        self.assertIn('"low_risk_actions":["𐀀",""]', tests)

    def test_snapshot_reader_is_one_clock_read_and_fail_closed_tuple(self):
        snapshot = SQL.split("create function raw.read_work_order_authorization", 1)[1].split(
            "alter function raw.jcs_quote", 1
        )[0]
        self.assertEqual(snapshot.count("clock_timestamp()"), 1)
        for text in (
            "returns table(allowed boolean,risk_tier text,lease_remaining_us bigint)",
            "w.root_id=p_root", "w.work_order_id=p_order", "a.attempt_id=p_attempt",
            "a.work_order_id=w.work_order_id", "l.attempt_id=a.attempt_id",
            "w.pull_state='running'", "w.lease_epoch=p_epoch", "l.lease_epoch=p_epoch",
            "l.worker_id=p_worker", "l.session_id=p_session", "l.expires_at>op_time",
            "w.policy_digest=p_digest", "w.offline_policy_mode='online_required'",
            "external_action_allowlist", "low_risk_actions", "floor(extract(epoch",
            "allowed:=coalesce(matched and action_allowed,false)",
            "case when allowed and is_low then 'low' else 'high' end",
            "if not allowed then lease_remaining_us:=0",
        ):
            self.assertIn(text, snapshot)
        self.assertIn("grant execute on function raw.configure_work_order_offline_policy(text,text,text,text,bytea,text),raw.authorize_work_order_external_action(text,text,text,text,text,bigint,text,text),raw.read_work_order_authorization", SQL)
        self.assertIn("low_risk_actions) on table raw.work_orders from public,paddock_app", SQL)


if __name__ == "__main__":
    unittest.main()
