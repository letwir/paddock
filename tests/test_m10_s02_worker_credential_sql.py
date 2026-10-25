"""Offline source checks only; this suite never opens a database or applies SQL."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
UP = (ROOT / "sql/governance_worker_credential.sql").read_text()
DOWN = (ROOT / "sql/governance_worker_credential_down.sql").read_text()
STORE = (ROOT / "internal/storage/postgres/worker_credential_store.go").read_text()
GATE = (ROOT / "internal/governance/application/safety_gate.go").read_text()
PORT = (ROOT / "internal/governance/port/safety_gate_transaction.go").read_text()
DOMAIN = (ROOT / "internal/governance/domain/worker_credential.go").read_text()
INTEGRATION = (ROOT / "internal/storage/postgres/worker_credential_integration_test.go").read_text()


class WorkerCredentialSQLTests(unittest.TestCase):
    def test_transaction_and_migrator_preflight(self):
        self.assertRegex(UP, r"BEGIN;[\s\S]+COMMIT;")
        for text in (UP, DOWN):
            self.assertIn("\\set ON_ERROR_STOP on", text)
            self.assertIn("current_database()<>'paddock_test'", text)
            self.assertIn("current_user<>'paddock_migrator'", text)
            self.assertIn("session_user<>'paddock_migrator'", text)
        for check in ("NOT rolsuper", "NOT rolcreaterole", "NOT rolcreatedb", "NOT rolreplication", "NOT rolbypassrls", "pg_catalog.pg_auth_members", "migrator must own raw schema"):
            self.assertIn(check, UP)

    def test_only_additive_credential_table(self):
        self.assertEqual(re.findall(r"CREATE TABLE (\w+\.\w+)", UP), ["raw.worker_issuer_context", "raw.worker_credentials"])
        self.assertNotRegex(UP, r"(?i)ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+EXTENSION")
        self.assertIn("REFERENCES raw.worker_enrollment_workers(worker_id)", UP)

    def test_opaque_and_positive_epoch_shapes(self):
        for text in ("credential_id ~ '^[0-9a-f]{64}$'", "octet_length(credential_id)=64", "lease_epoch bigint NOT NULL CHECK(lease_epoch>0)", "issuer_revision numeric(20,0) NOT NULL", "18446744073709551615", "ceiling_digest ~ '^[0-9a-f]{64}$'", "revoked boolean NOT NULL DEFAULT false"):
            self.assertIn(text, UP)

    def test_fixed_path_definer_app_only_for_every_capability(self):
        functions = re.findall(r"CREATE FUNCTION raw\.(\w+)\([\s\S]+?END \$\$;", UP)
        self.assertEqual(functions, ["issue_worker_credential", "lock_worker_credential", "lock_current_worker_issuer_context", "revoke_worker_credential"])
        self.assertEqual(UP.count("SECURITY DEFINER SET search_path=pg_catalog"), 4)
        self.assertEqual(UP.count("IF session_user<>'paddock_app'"), 4)
        self.assertNotIn("EXECUTE format", UP)

    def test_execute_only_and_fail_closed_default_acl(self):
        self.assertIn("REVOKE ALL ON TABLE raw.worker_credentials FROM PUBLIC,paddock_app", UP)
        self.assertIn("REVOKE ALL ON TABLE raw.worker_issuer_context FROM PUBLIC,paddock_app", UP)
        self.assertNotRegex(UP, r"(?i)GRANT\s+(SELECT|INSERT|UPDATE|DELETE|ALL|USAGE)")
        grant = re.search(r"GRANT EXECUTE ON FUNCTION ([^;]+);", UP).group(1)
        for function in ("issue_worker_credential", "lock_worker_credential", "lock_current_worker_issuer_context", "revoke_worker_credential"):
            self.assertIn("raw." + function + "(", grant)
        self.assertTrue(grant.endswith("TO paddock_app"))
        self.assertIn("FROM PUBLIC,paddock_app;\nGRANT EXECUTE", UP)
        self.assertIn("acl.grantee NOT IN (p.proowner", UP)
        self.assertIn("acl.grantee<>c.relowner", UP)
        self.assertIn("unexpected credential ACL", UP)
        self.assertIn("pg_catalog.aclexplode(a.attacl)", UP)
        self.assertIn("a.attrelid IN ('raw.worker_credentials'::regclass,'raw.worker_issuer_context'::regclass)", UP)

    def test_enrollment_checked_under_lock_before_issue(self):
        self.assertLess(UP.index("w.fingerprint=p_fingerprint"), UP.index("INSERT INTO raw.worker_credentials"))
        self.assertIn("FOR SHARE;", UP)
        self.assertIn("enrolled key binding unavailable", UP)

    def test_gate_lock_serializes_revoke_and_loads_key(self):
        self.assertIn("FOR UPDATE OF c FOR SHARE OF w", UP)
        self.assertIn("w.worker_id=c.worker_id AND w.fingerprint=c.fingerprint", UP)
        self.assertIn("c.ceiling_digest,c.revoked,w.public_key", UP)
        self.assertIn("SET revoked=true", UP)
        self.assertNotIn("SET revoked=false", UP)

    def test_no_authority_or_second_replay_ledger(self):
        table = UP.split("CREATE TABLE raw.worker_credentials (", 1)[1].split("\n);", 1)[0]
        for field in ("scope_id", "capabilities", "trust", "authority", "root_epoch", "security_epoch", "policy_digest", "nonce", "request_digest", "command_id"):
            self.assertNotIn(field, table)
        self.assertNotIn("raw.command_receipts", UP)

    def test_down_is_owned_restrict_only(self):
        self.assertNotIn("CASCADE", DOWN)
        self.assertEqual(DOWN.count(" RESTRICT;"), 6)
        self.assertIn("unexpected credential object owner", DOWN)
        self.assertEqual(re.findall(r"DROP TABLE (\w+\.\w+) RESTRICT;", DOWN), ["raw.worker_credentials", "raw.worker_issuer_context"])
        for signature in ("raw.worker_issuer_context", "raw.lock_current_worker_issuer_context(text)"):
            self.assertIn(signature, DOWN.split("END $$;", 1)[0])

    def test_adapter_only_calls_parameterized_capabilities(self):
        self.assertIn("raw.issue_worker_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", STORE)
        self.assertIn("raw.revoke_worker_credential($1)", STORE)
        self.assertIn("FROM raw.lock_worker_credential($1)", STORE)
        self.assertIn("FROM raw.lock_current_worker_issuer_context($1)", STORE)
        self.assertNotIn("FROM raw.worker_credentials", STORE)
        self.assertNotIn("INSERT INTO", STORE)
        self.assertNotIn("FROM raw.worker_issuer_context", STORE)

    def test_gate_has_no_optional_high_risk_path(self):
        high_risk = GATE.split("func (g *SafetyGate) CheckHighRiskAction", 1)[1].split("func (g *SafetyGate) check(", 1)[0]
        for call in ("domain.Authorize", "ValidateCurrentLease", "LockWorkerCredential", "tx.LockCurrentCredentialIssuer", "domain.VerifyWorkerCredential"):
            self.assertIn(call, high_risk)
        self.assertIn("LockWorkerCredential(context.Context, string)", PORT)
        self.assertIn("request domain.CredentialRequest", high_risk)
        self.assertNotIn("CredentialIssuerProvider", GATE)
        self.assertNotIn("g.issuers", GATE)
        self.assertIn("LockCurrentCredentialIssuer(context.Context, string)", PORT)
        self.assertLess(high_risk.index("tx.LockWorkerCredential"), high_risk.index("tx.LockCurrentCredentialIssuer"))
        self.assertIn("g.transactor.WithinSafetyGateTransaction", GATE)

    def test_registry_is_current_state_without_app_update_api(self):
        registry = UP.split("CREATE TABLE raw.worker_issuer_context (", 1)[1].split("\n);", 1)[0]
        for field in ("issuer_id", "issuer_revision", "ceiling_digest"):
            self.assertIn(field, registry)
        self.assertIn('PRIMARY KEY CHECK(issuer_id', registry)
        self.assertIn("issuer_revision>0", registry)
        # Inspect every SECURITY DEFINER capability, not only the read API.
        bodies = re.findall(r"CREATE FUNCTION raw\.\w+[\s\S]*?AS \$\$([\s\S]*?)END \$\$;", UP)
        self.assertEqual(len(bodies), 4)
        for body in bodies:
            self.assertNotRegex(body, r"(?i)(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE)\s+raw\.worker_issuer_context")
        lock = UP.split("CREATE FUNCTION raw.lock_current_worker_issuer_context", 1)[1].split("END $$;", 1)[0]
        self.assertIn('i.issuer_id=p_issuer COLLATE "C" FOR SHARE OF i', lock)
        self.assertIn("i.issuer_revision::text,i.ceiling_digest", lock)
        self.assertNotIn("FOR KEY SHARE", lock)

    def test_issue_compares_current_registry_under_lock_before_insert(self):
        issue = UP.split("CREATE FUNCTION raw.issue_worker_credential", 1)[1].split("END $$;", 1)[0]
        for check in ('i.issuer_id=p_issuer COLLATE "C"', "i.issuer_revision=p_revision::numeric", 'i.ceiling_digest=p_ceiling COLLATE "C" FOR SHARE;', "current issuer context unavailable"):
            self.assertIn(check, issue)
        self.assertLess(issue.index("FROM raw.worker_issuer_context"), issue.index("INSERT INTO raw.worker_credentials"))
        self.assertIn("IF NOT FOUND THEN RAISE EXCEPTION", issue.split("FROM raw.worker_issuer_context", 1)[1].split("INSERT INTO", 1)[0])

    def test_proof_binds_all_inputs_via_jcs_and_ed25519(self):
        for field in ("credential_id", "fingerprint", "worker_id", "session_id", "attempt_id", "work_order_id", "lease_epoch", "issuer_id", "issuer_revision", "ceiling_digest", "scope_id", "root_id", "policy_digest", "authorization_epoch", "security_epoch", "request_digest"):
            self.assertIn('json:"' + field + '"', DOMAIN)
        for call in ("canonical.Envelope", "ed25519.Verify", "Audience: c.Audience", "RequestID: request.CommandID", "Nonce: request.Nonce", "c.Lease != authorization.Lease", "c.Issuer != issuer", "c.Revoked"):
            self.assertIn(call, DOMAIN)

    def test_integration_opt_in_before_db_configuration_and_no_migration(self):
        body = INTEGRATION.split("func TestWorkerCredentialGateIntegration", 1)[1]
        self.assertLess(body.index('os.Getenv("PADDOCK_WORKER_CREDENTIAL_INTEGRATION")'), body.index('os.Getenv("PADDOCK_DB_URL")'))
        self.assertIn('db != "paddock_test"', body)
        self.assertNotIn("os.ReadFile", INTEGRATION)
        self.assertNotIn("governance_worker_credential.sql", body)
        for evidence in ("bad signature accepted", "wrong key accepted", "stale issuer revision accepted", "stale issuer ceiling accepted", "stale credential epoch accepted", "revoked credential accepted", "expired lease accepted", "LookupCommandReceipt", "InsertCommandReceipt", "cleanup readback"):
            self.assertIn(evidence, INTEGRATION)

    def test_m07_sources_require_current_hash_revalidation(self):
        self.assertIn("current-hash M06 rollback-only + M07 shared body", INTEGRATION)
        for path in ("integration_test.go", "rollout_application_integration_test.go"):
            source = (ROOT / "internal/storage/postgres" / path).read_text()
            self.assertIn("credentialIntegrationAuthorization", source)
            self.assertIn("credentialIntegrationRequest()", source)
            self.assertIn("issueCredentialIntegration", source)
            self.assertIn("seedCredentialIntegrationIssuer", source)
            self.assertNotIn("credentialIntegrationIssuer()", source)

    def test_registry_fixture_is_migrator_only_exact_and_readback_zero(self):
        fixture = INTEGRATION.split("func seedCredentialIntegrationIssuer", 1)[1].split("func credentialIntegrationRequest", 1)[0]
        self.assertIn('user != "paddock_migrator"', fixture)
        self.assertIn('session != "paddock_migrator"', fixture)
        self.assertIn("migrator.Exec(ctx, `INSERT INTO raw.worker_issuer_context", fixture)
        self.assertIn("DELETE FROM raw.worker_issuer_context WHERE issuer_id=$1", fixture)
        self.assertIn("SELECT count(*) FROM raw.worker_issuer_context WHERE issuer_id=$1", fixture)
        self.assertIn("remaining != 0", fixture)
        self.assertNotIn("ON CONFLICT", fixture)
        self.assertNotRegex(INTEGRATION, r"app\.(?:Exec|QueryRow)\([^\n]*`(?:UPDATE|INSERT INTO|DELETE FROM) raw\.worker_issuer_context")
        for evidence in ("stale issuance context accepted", "stale issuance digest accepted", "missing issuance issuer accepted"):
            self.assertIn(evidence, INTEGRATION)


if __name__ == "__main__":
    unittest.main()
