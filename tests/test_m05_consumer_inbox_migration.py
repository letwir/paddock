"""Offline source contracts for the M05-S04 Consumer Inbox migration."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "sql" / "governance_consumer_inbox.sql"
STORE = ROOT / "internal" / "storage" / "postgres" / "consumer_inbox_store.go"


class ConsumerInboxMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()
        cls.store = STORE.read_text(encoding="utf-8").lower()

    def test_migration_is_guarded_transactional_and_additive(self):
        self.assertEqual(len(re.findall(r"\bbegin\s*;", self.sql)), 1)
        self.assertEqual(len(re.findall(r"\bcommit\s*;", self.sql)), 1)
        self.assertIn("current_database() <> 'paddock_test'", self.sql)
        self.assertIn("current_user <> 'paddock_migrator'", self.sql)
        self.assertIn("session_user <> 'paddock_migrator'", self.sql)
        self.assertIn("create table raw.event_consumer_projection", self.sql)
        self.assertNotRegex(self.sql, r"\bdrop\s+(?:table|schema|database)\b")

    def test_inbox_insert_and_projection_effect_share_one_transaction(self):
        store = re.sub(r"\s+", "", self.store)
        self.assertIn("withconsumerinboxtransaction(ctx,s.pool", store)
        self.assertIn("selectexists(select1fromraw.domain_eventswhereevent_id=$1)", store)
        self.assertIn("insertintoraw.event_inbox(consumer_id,event_id,processed_at)", store)
        self.assertIn("onconflictdonothing", store)
        self.assertNotIn("onconflict(consumer_id,event_id)", store)
        self.assertIn("insertintoraw.event_consumer_projection", store)
        self.assertIn("onconflict(consumer_id)doupdate", store)
        self.assertIn("rollback(tx)", store)

    def test_application_grants_are_narrow_and_outbox_remains_ungranted(self):
        self.assertRegex(self.sql, r"grant\s+insert\s*\(consumer_id,event_id,processed_at\)\s+on\s+table\s+raw\.event_inbox\s+to\s+paddock_app")
        self.assertIn("grant select (consumer_id,processed_event_count), insert (consumer_id,processed_event_count), update (processed_event_count)", self.sql)
        self.assertIn("paddock_app must not have direct raw.event_outbox privileges", self.sql)
        self.assertNotRegex(self.sql, r"\bgrant\b[^;]*\bon\s+(?:table\s+)?raw\.event_outbox")

    def test_inbox_primary_key_is_checked_and_privileges_fail_closed(self):
        self.assertIn("raw.event_inbox primary key must be (consumer_id,event_id)", self.sql)
        self.assertIn("raw.event_inbox must have exactly one valid unique index", self.sql)
        self.assertIn("paddock_app must not have pre-existing direct raw.event_inbox privileges", self.sql)
        self.assertIn("consumer_inbox_readback", self.sql)
        self.assertIn("has_column_privilege", self.sql)


if __name__ == "__main__":
    unittest.main()
