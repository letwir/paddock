import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SQL=(ROOT/'sql/governance_checkpoints.sql').read_text()
class CheckpointSQLTests(unittest.TestCase):
 def test_restore_rehashes_payload_and_checks_both_stored_digests_before_exposure(self):
  import re
  match=re.search(r'CREATE FUNCTION raw\.restore_work_order_checkpoint\(text\)(.*?)\$\$;',SQL,re.S)
  self.assertIsNotNone(match,'restore function source must be present')
  restore=match.group(1)
  digest_check=re.search(r'pg_catalog\.sha256\s*\(\s*c\.payload\s*\)',restore,re.I)
  self.assertIsNotNone(digest_check,'restore must recompute SHA-256 from stored payload bytes')
  column_check=re.search(r'c\.payload_sha256\s*=\s*encode\s*\(\s*pg_catalog\.sha256\s*\(\s*c\.payload\s*\)\s*,\s*\'hex\'\s*\)',restore,re.I)
  self.assertIsNotNone(column_check,'recomputed digest must match the stored digest column')
  manifest_check=re.search(r'c\.payload_sha256\s*=\s*\(\s*convert_from\s*\(\s*c\.manifest\s*,\s*\'UTF8\'\s*\)\s*::jsonb\s*->>\s*\'payload_sha256\'\s*\)',restore,re.I)
  self.assertIsNotNone(manifest_check,'stored digest column must match manifest payload_sha256')
  promotion=re.search(r'current_state\s*:=\s*CASE\s+WHEN([\s\S]*?)THEN\s+\'L2\'',restore)
  self.assertIsNotNone(promotion,'restore must have an explicit L2 promotion predicate')
  predicate=promotion.group(1)
  self.assertRegex(predicate,r"c\.state\s*=\s*'L2'")
  self.assertIn(column_check.group(0),predicate,'stored-column integrity must gate L2 promotion')
  self.assertIn(manifest_check.group(0),predicate,'manifest integrity must gate L2 promotion')
  self.assertLess(digest_check.start(),restore.lower().index('return query'),'integrity checks must precede any return')
  self.assertIn("CASE WHEN current_state='L2' THEN c.payload ELSE NULL::bytea END",restore)
  # A malformed manifest must fail closed (the JSON/hex conversion occurs in the
  # integrity predicate, before RETURN QUERY), while digest mismatches cannot
  # produce L2 or a non-NULL payload.
  self.assertRegex(restore,r'current_state\s*:=\s*CASE\s+WHEN[\s\S]*?payload_sha256[\s\S]*?THEN\s+\'L2\'\s+ELSE\s+\'QUARANTINED\'')
  self.assertNotRegex(restore,r'RETURN\s+QUERY\s+SELECT\s+c\.checkpoint_id\s*,\s*c\.manifest\s*,\s*c\.payload\s*,')

 def test_guarded_additive_and_role_boundaries(self):
  for token in ('current_database()<>\'paddock_test\'','current_user<>\'paddock_migrator\'','paddock_app','paddock_migrator','raw.roots','raw.work_orders','raw.work_order_attempts','raw.work_order_leases','raw.budget_accounts','BEGIN;','COMMIT;'):
   self.assertIn(token,SQL)
  self.assertNotIn('DROP ',SQL.upper()); self.assertNotIn('CREATE EXTENSION',SQL.upper())
 def test_policy_is_finite_immutable_and_budget_bounded(self):
  self.assertIn('max_bytes_per_checkpoint bigint NOT NULL CHECK(max_bytes_per_checkpoint>0)',SQL)
  self.assertIn('max_total_checkpoint_bytes bigint NOT NULL CHECK(max_total_checkpoint_bytes>0',SQL)
  self.assertIn('BEFORE UPDATE OR DELETE ON raw.checkpoint_policies',SQL)
  self.assertIn('total_limit>granted',SQL)
 def test_single_append_only_bytea_row_with_quarantine(self):
  for token in ('manifest bytea NOT NULL','payload bytea NOT NULL',"state IN ('L2','QUARANTINED')",'stored_bytes=octet_length(manifest)+octet_length(payload)','BEFORE UPDATE OR DELETE ON raw.work_order_checkpoints','clock_timestamp()','raw.work_order_leases','raw.store_work_order_checkpoint','GRANT EXECUTE ON FUNCTION raw.checkpoint_storage_account(text),raw.store_work_order_checkpoint'):
   self.assertIn(token,SQL)
  self.assertNotIn('GRANT SELECT',SQL)
 def test_replay_conflict_and_stale_never_promotes(self):
  self.assertIn('checkpoint operation replay conflict',SQL)
  self.assertIn("CASE WHEN live THEN 'L2' ELSE 'QUARANTINED' END",SQL)
  self.assertIn('l.expires_at>now_at',SQL)
  self.assertIn('now_at:=clock_timestamp()',SQL)
  self.assertNotIn('UPDATE raw.work_order_checkpoints',SQL)
 def test_server_integrity_and_canonical_bytes(self):
  self.assertIn('pg_catalog.sha256(p)',SQL)
  self.assertIn('IF canonical IS DISTINCT FROM m THEN',SQL)
  self.assertIn('jsonb_object_keys(manifest_json)',SQL)
  self.assertIn("getdatabaseencoding()<>'UTF8'",SQL)
  self.assertNotIn('paddock_coordinator',SQL)
 def test_manifest_has_exact_typed_required_members_and_attempt_binding(self):
  members=('schema_version','root_id','work_order_id','attempt_id','lease_epoch','definition_digest','policy_digest','payload_sha256','payload_size')
  self.assertIn("manifest_json ?& ARRAY["+','.join("'"+name+"'" for name in members)+"]",SQL)
  self.assertIn("(SELECT count(*) FROM jsonb_object_keys(manifest_json))<>9",SQL)
  types={'schema_version':'string','root_id':'string','work_order_id':'string','attempt_id':'string','lease_epoch':'number','definition_digest':'string','policy_digest':'string','payload_sha256':'string','payload_size':'number'}
  for name,kind in types.items():
   self.assertIn("jsonb_typeof(manifest_json->'"+name+"') IS DISTINCT FROM '"+kind+"'",SQL)
  self.assertIn("manifest_json->>'attempt_id' IS DISTINCT FROM aid",SQL)
 def test_restore_is_current_authority_gated_and_payload_null_when_stale(self):
  self.assertIn('raw.restore_work_order_checkpoint(text)',SQL)
  self.assertIn("CASE WHEN current_state='L2' THEN c.payload ELSE NULL::bytea END",SQL)
  self.assertIn('GRANT EXECUTE ON FUNCTION raw.restore_work_order_checkpoint(text) TO paddock_app',SQL)
 def test_narrow_privileges_and_root_attempt_binding(self):
  self.assertIn('REVOKE ALL ON TABLE raw.checkpoint_policies,raw.work_order_checkpoints FROM PUBLIC,paddock_app',SQL)
  self.assertIn('w.root_id=rid',SQL)
  self.assertIn('a.work_order_id=w.work_order_id AND a.attempt_id=aid',SQL)

 def test_store_requires_exact_reserve_receipt_before_checkpoint_insert(self):
  import re
  match=re.search(r'CREATE FUNCTION raw\.store_work_order_checkpoint\(text,text,text,text,bigint,bytea,bytea,bigint\)(.*?)\$\$;',SQL,re.S)
  self.assertIsNotNone(match,'store function source must be present')
  store=match.group(1)
  insert=store.lower().find('insert into raw.work_order_checkpoints')
  self.assertGreaterEqual(insert,0,'store function must insert the checkpoint')
  before_insert=store[:insert]

  self.assertRegex(before_insert,r"(?:bo\.)?operation_id\s*=\s*op\s*\|\|\s*':reserve'",
                   'reserve receipt must be for this exact operation’s :reserve id')
  self.assertRegex(before_insert,r"(?:bo\.)?operation_kind\s*=\s*'RESERVE'",
                   'receipt must record the RESERVE operation kind')
  self.assertRegex(before_insert,r"(?:bo\.)?request\s*->>\s*'account_id'\s*=\s*pol\.storage_account_id",
                   'receipt request must use the configured storage account')
  self.assertRegex(before_insert,r"(?:bo\.)?request\s*->>\s*'amount'\s*=\s*n\s*(?:::\s*(?:text|bigint))?",
                   'receipt request amount must exactly match n')
  self.assertRegex(before_insert,r"(?:bo\.)?result\s*=\s*jsonb_build_object\s*\(\s*'account_id'\s*,\s*pol\.storage_account_id\s*,\s*'reserved'\s*,\s*n\s*\)",
                   'receipt result must exactly match the configured account and reserved amount')

  # The app role must not be able to sidestep the checked SECURITY DEFINER path.
  self.assertIn('SECURITY DEFINER',store.upper())
  self.assertRegex(SQL,r'REVOKE\s+ALL\s+ON\s+TABLE\s+raw\.checkpoint_policies\s*,\s*raw\.work_order_checkpoints\s+FROM\s+PUBLIC\s*,\s*paddock_app',
                   'direct table insertion must be revoked from the app role')
  self.assertNotRegex(SQL,r'GRANT\s+(?:INSERT|ALL(?:\s+PRIVILEGES)?)\s+ON\s+(?:TABLE\s+)?raw\.work_order_checkpoints\s+TO\s+(?:PUBLIC\s*,\s*)?paddock_app',
                      'app role must not receive direct checkpoint insert privileges')
  self.assertRegex(SQL,r'GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+[^;]*,\s*raw\.store_work_order_checkpoint\([^;]+\)\s+TO\s+paddock_app',
                    'app role should use the reserve-checking store function')

 def test_total_checkpoint_bytes_aggregate_qualifies_stored_bytes(self):
  import re
  match=re.search(r'SELECT\s+COALESCE\s*\(\s*sum\s*\((.*?)\)\s*,\s*0\s*\)\s+INTO\s+used\s+FROM\s+raw\.work_order_checkpoints\s+(?:AS\s+)?([a-z_][a-z0-9_]*)\s+WHERE\s+(.*?)\s*;',SQL,re.I|re.S)
  self.assertIsNotNone(match,'total checkpoint bytes must use an explicitly aliased table and root filter')
  alias=match.group(2)
  self.assertRegex(match.group(1),rf'\b{re.escape(alias)}\.stored_bytes\b',
                   'stored_bytes in the total-byte aggregate must be qualified by the table alias')
  self.assertRegex(match.group(3),rf'\b{re.escape(alias)}\.root_id\s*=\s*rid\b',
                   'the total-byte aggregate must filter by the requested root through that alias')
  self.assertNotRegex(SQL,r'sum\s*\(\s*stored_bytes\s*\)',
                      'unqualified sum(stored_bytes) is ambiguous with the OUT parameter')

 if __name__=='__main__': unittest.main()
