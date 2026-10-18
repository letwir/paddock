"""Offline source contracts for M05-S03 Outbox lease/dispatch implementation."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "sql" / "governance_outbox_dispatch.sql"
INIT = ROOT / "sql" / "init.sql"
STORE = ROOT / "internal" / "storage" / "postgres" / "outbox_store.go"
APP = ROOT / "internal" / "governance" / "application" / "outbox_dispatcher.go"


def function_body(source, name, receiver):
    match = re.search(rf"^func \({receiver}\) {name}\b.*?(?=^func |\Z)", source, re.M | re.S)
    if not match:
        raise AssertionError(f"Go method {name} with receiver {receiver!r} not found")
    return match.group(0)


class OutboxDispatchStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()
        cls.init = INIT.read_text(encoding="utf-8").lower()
        cls.store = STORE.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")

    def test_migration_is_guarded_and_never_grants_direct_outbox_acl(self):
        self.assertEqual(len(re.findall(r"\bbegin\s*;", self.sql)), 1)
        self.assertEqual(len(re.findall(r"\bcommit\s*;", self.sql)), 1)
        self.assertRegex(self.sql, r"current_database\(\)\s*<>\s*'paddock_test'")
        self.assertRegex(self.sql, r"current_user\s*<>\s*'paddock_migrator'")
        self.assertRegex(self.sql, r"session_user\s*<>\s*'paddock_migrator'")
        self.assertIn("pg_catalog.pg_auth_members", self.sql)
        self.assertIn("raw.event_outbox.event_id must reference raw.domain_events.event_id", self.sql)
        self.assertIn("c.confrelid=domain_events_oid", self.sql)
        self.assertIn("c.contype='f'", self.sql)
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+table\b")
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+(?:table\s+)?raw\.event_outbox")
        self.assertIn("must not have direct event_outbox table privileges", self.sql)

    def test_lease_schema_and_initial_schema_have_the_same_contract(self):
        columns = (
            "claim_token uuid",
            "lease_expires_at timestamptz",
            "dead_lettered_at timestamptz",
            "redrive_count integer not null default 0",
        )
        for fragment in columns:
            with self.subTest(fragment=fragment):
                column, pgtype = fragment.split()[:2]
                self.assertRegex(self.init, rf"\b{column}\s+{pgtype}\b")
                self.assertIn(fragment, self.sql)
        for name in (
            "event_outbox_claim_pair_ck",
            "event_outbox_dead_letter_unclaimed_ck",
            "event_outbox_published_not_dead_lettered_ck",
            "event_outbox_redrive_count_ck",
            "event_outbox_claimable_idx",
            "event_outbox_redrive_idx",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.init)
                self.assertIn(name, self.sql)
        self.assertIn("$outbox_index_readback$", self.sql)
        self.assertIn("Outbox claim/redrive indexes are missing or incompatible".lower(), self.sql)

    def test_index_readback_predicates_match_created_indexes(self):
        claim_index = re.search(r"create index if not exists event_outbox_claimable_idx\b.*?;", self.sql, re.S).group(0)
        redrive_index = re.search(r"create index if not exists event_outbox_redrive_idx\b.*?;", self.sql, re.S).group(0)
        self.assertIn("where published_at is null and dead_lettered_at is null", claim_index)
        self.assertIn("where published_at is null and dead_lettered_at is not null and redrive_count=0", redrive_index)
        self.assertIn("='published_atisnullanddead_lettered_atisnull'", self.sql)
        self.assertIn("='published_atisnullanddead_lettered_atisnotnullandredrive_count=0'", self.sql)

    def test_all_new_function_bodies_are_app_only_fixed_path_definers(self):
        names = ("claim_event_outbox", "ack_event_outbox", "retry_event_outbox", "append_domain_event_and_outbox")
        for name in names:
            with self.subTest(function=name):
                definition = re.search(
                    rf"create\s+or\s+replace\s+function\s+raw\.{name}\s*\(.*?\$[a-z0-9_]+\$;",
                    self.sql,
                    re.S,
                )
                self.assertIsNotNone(definition)
                body = definition.group(0)
                self.assertIn("security definer", body)
                self.assertIn("set search_path=pg_catalog", body)
                self.assertIn("session_user<>'paddock_app'", body)
                self.assertRegex(self.sql, rf"alter\s+function\s+raw\.{name}\s*\(.*?owner\s+to\s+paddock_migrator", msg=name)
                self.assertRegex(self.sql, rf"grant\s+execute\s+on\s+function[^;]*raw\.{name}\s*\(", msg=name)
                self.assertRegex(self.sql, rf"revoke\s+all\s+on\s+function[^;]*raw\.{name}\s*\(", msg=name)
        self.assertIn("from public,paddock_app", self.sql)
        self.assertIn("to paddock_app", self.sql)

    def test_claim_fencing_retry_redrive_and_notify_contract(self):
        claim = re.search(r"create\s+or\s+replace\s+function\s+raw\.claim_event_outbox\b.*?\$claim_event_outbox\$;", self.sql, re.S).group(0)
        for required in ("for update of o skip locked", "$1>100", "v_remaining:=$1", "get diagnostics v_changed=row_count", "lease_expires_at=v_now+interval '5 minutes'", "gen_random_uuid", "attempt_count=o.attempt_count+1", "dead_lettered_at<=v_now-interval '24 hours'", "redrive_count=1"):
            self.assertIn(required, claim)
        self.assertIn("last_error='lease_expired_max_attempts'", claim)
        self.assertIn("claim_event_outbox found an outbox row without its durable event", claim)
        retry = re.search(r"create\s+or\s+replace\s+function\s+raw.retry_event_outbox\b.*?\$retry_event_outbox\$;", self.sql, re.S).group(0)
        for required in ("attempt_count >= 20*(v_redrive_count+1)", "v_backoff_seconds := least(3600", "'dead_lettered'", "'retry_scheduled'", "'stale_claim'"):
            self.assertIn(required, retry)
        ack = re.search(r"create\s+or\s+replace\s+function\s+raw.ack_event_outbox\b.*?\$ack_event_outbox\$;", self.sql, re.S).group(0)
        self.assertIn("claim_token=$2::uuid", ack)
        self.assertIn("lease_expires_at>pg_catalog.clock_timestamp()", ack)
        self.assertIn("lease_expires_at>v_now", retry)
        self.assertIn("lease_expires_at>pg_catalog.clock_timestamp()", ack)
        self.assertIn("lease_expires_at>v_now", retry)
        append = re.search(r"create\s+or\s+replace\s+function\s+raw.append_domain_event_and_outbox\b.*?\$append_domain_event_and_outbox\$;", self.sql, re.S).group(0)
        self.assertLess(append.index("insert into raw.event_outbox"), append.index("pg_catalog.pg_notify('paddock_event_outbox','')"))

    def test_postgres_store_routes_through_functions_and_dedicated_listener(self):
        for method, function in (("Claim", "raw.claim_event_outbox($1)"), ("Ack", "raw.ack_event_outbox($1,$2)"), ("Retry", "raw.retry_event_outbox($1,$2,$3)")):
            body = function_body(self.store, method, r"s \*PostgresOutboxStore")
            self.assertIn(function, body)
            self.assertNotIn("raw.event_outbox", body)
        self.assertIn("pgx.ConnectConfig", self.store)
        self.assertIn("LISTEN `+outboxWakeupChannel", self.store)
        self.assertIn("WaitForNotification(ctx)", self.store)
        self.assertIn("currentUser != \"paddock_app\" || sessionUser != \"paddock_app\"", self.store)

    def test_application_dispatches_outside_claim_and_polls_after_notify(self):
        dispatch = function_body(self.app, "DispatchOnce", r"d \*OutboxDispatcher")
        self.assertLess(dispatch.index("d.store.Claim"), dispatch.index("d.publisher.Publish"))
        self.assertLess(dispatch.index("d.publisher.Publish"), dispatch.index("d.store.Ack"))
        self.assertIn("outboxDeliveryFailureCode", dispatch)
        run = function_body(self.app, "Run", r"d \*OutboxDispatcher")
        self.assertLess(run.index("d.notifier.Listen(ctx)"), run.index("d.DispatchOnce(ctx)"))
        self.assertIn("waitForOutboxPoll", run)
        self.assertIn("context.DeadlineExceeded", run)
        self.assertIn("close listener after dispatch failure", run)
        self.assertIn("close listener after notification wait", run)


if __name__ == "__main__":
    unittest.main()
