"""Offline M04-S03 source contracts; never runs a helper, Go test, or database."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "internal/storage/postgres/rollout_concurrency_integration_test.go"


class RolloutConcurrencyStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.helper = cls.source.split("func TestRolloutScopeConflictProcessHelper(", 1)[1].split(
            "type rolloutConcurrencyChild", 1)[0]
        cls.launch = cls.source.split("func startRolloutConcurrencyChild(", 1)[1].split(
            "func TestRolloutScopeConflictTwoProcessesIntegration(", 1)[0]
        cls.parent = cls.source.split("func TestRolloutScopeConflictTwoProcessesIntegration(", 1)[1]

    def test_explicit_triple_opt_in_and_test_only_surface(self):
        self.assertEqual(SOURCE.suffix, ".go")
        self.assertTrue(SOURCE.name.endswith("_test.go"))
        self.assertTrue(self.source.startswith(
            "//go:build integration && paddock_test && rollout_concurrency\n\npackage postgres\n"))
        self.assertIn("Compile offline with -run '^$'", self.source)
        self.assertIn("requires separate exact", self.source)
        self.assertNotRegex(self.source, r"func (?:init|main)\(")
        exported = re.findall(r"^func ([A-Z]\w*)\(", self.source, re.M)
        self.assertEqual(exported, ["TestRolloutScopeConflictProcessHelper",
                                   "TestRolloutScopeConflictTwoProcessesIntegration"])
        self.assertIn('os.Getenv(rolloutConcurrencyHelperEnv) != "1"', self.helper)
        self.assertIn('t.Skip("parent-controlled helper only")', self.helper)

    def test_two_os_processes_and_independent_app_pools(self):
        self.assertIn("os.Executable()", self.launch)
        self.assertIn("exec.CommandContext(childCtx, binary,", self.launch)
        self.assertIn('"-test.run=^TestRolloutScopeConflictProcessHelper$"', self.launch)
        self.assertIn('"-test.count=1"', self.launch)
        self.assertIn("cmd.Start()", self.launch)
        self.assertIn("make([]*rolloutConcurrencyChild, 2)", self.parent)
        self.assertIn("children[i] = startRolloutConcurrencyChild(", self.parent)
        self.assertIn("app := rolloutConcurrencyPool(t, ctx, true)", self.helper)
        self.assertIn("rolloutConcurrencyService(t, app, q.Prefix)", self.helper)
        self.assertIn("r.PID != child.cmd.Process.Pid || r.PID == os.Getpid()", self.parent)
        self.assertIn("results[0].PID == results[1].PID", self.parent)
        self.assertIn('!strings.HasPrefix(entry, "PADDOCK_DB_URL=")', self.launch)
        self.assertIn('db != "paddock_test" || user != role || session != role', self.source)
        self.assertIn('name, role = "PADDOCK_APP_DB_URL", "paddock_app"', self.source)
        self.assertNotRegex(self.source, r"(?m)^\s*go\s+(?:func|\w+\()")

    def test_parent_controlled_ready_go_pipe_barrier_order(self):
        self.assertIn("cmd.StdinPipe()", self.launch)
        self.assertIn("cmd.StdoutPipe()", self.launch)
        self.assertIn("json.NewEncoder(stdin).Encode(q)", self.launch)
        launch = self.parent.index("children[i] = startRolloutConcurrencyChild(")
        ready = self.parent.index('child.stdout.Text() != "READY"')
        go = self.parent.index('io.WriteString(child.stdin, "GO\\n")')
        results = self.parent.index("results := make([]rolloutConcurrencyResult, 2)")
        self.assertLess(launch, ready)
        self.assertLess(ready, go)
        self.assertLess(go, results)
        # READY and GO are separate whole-slice loops, not a per-child exchange.
        barrier = self.parent[launch:results]
        self.assertEqual(barrier.count("for _, child := range children {"), 2)
        self.assertIn("bufio.NewReader(os.Stdin)", self.helper)
        pool = self.helper.index("app := rolloutConcurrencyPool(")
        request = self.helper.index("request := application.StartCanaryRequest{")
        ready = self.helper.index('fmt.Fprintln(os.Stdout, "READY")')
        go = self.helper.index('line != "GO\\n"')
        call = self.helper.index("service.StartCanary(ctx, request,")
        self.assertLess(pool, request)
        self.assertLess(request, ready)
        self.assertLess(ready, go)
        self.assertLess(go, call)
        self.assertNotIn("time.Sleep(", self.source)
        self.assertNotIn("sync.WaitGroup", self.source)

    def test_distinct_command_and_rollout_ids_same_expected_snapshot(self):
        self.assertIn('fmt.Sprintf("%s_canary_%d", q.Prefix, q.Index)', self.source)
        self.assertIn('fmt.Sprintf("%s_rollout_%d", q.Prefix, q.Index)', self.source)
        self.assertIn("rolloutConcurrencyInput{Prefix: prefix, Security: security, Index: i}", self.parent)
        self.assertIn("commands[1] == commands[2]", self.parent)
        self.assertIn("r.CommandID != commands[i+1]", self.parent)
        for field in ("CommandID: q.commandID()", "Rollout: q.rolloutID()",
                      'Scope: domain.ScopeID(q.Prefix + "_scope")',
                      'Root: domain.RootID(q.Prefix + "_b")',
                      "ExpectedScopeEpoch: 40", "ExpectedRootEpoch: 5",
                      "ExpectedSecurityEpoch: q.Security"):
            self.assertIn(field, self.helper)
        self.assertIn("domain.DomainApprovalSigningBytes(candidate, pin, \"candidate-author\")", self.source)
        self.assertIn("rolloutIntegrationKey{public}", self.source)
        self.assertIn("rolloutIntegrationLKG{}", self.source)

    def test_exact_commit_and_occupied_slot_not_arbitrary_failure(self):
        self.assertIn("service.StartCanary(ctx, request,", self.helper)
        self.assertIn('Outcome: "COMMITTED"', self.helper)
        self.assertIn("!errors.As(err, &failure)", self.helper)
        self.assertIn("failure.Kind != application.FailureBusy", self.helper)
        self.assertIn('failure.Cause.Error() != "scope active rollout slot is occupied"', self.helper)
        self.assertIn('out.Outcome = "BUSY"', self.helper)
        self.assertIn("committed != 1 || busy != 1", self.parent)
        self.assertIn("r.Result.State != domain.RolloutCanary", self.parent)
        self.assertIn("r.Result.ScopeEpoch != 41 || r.Result.RootEpoch != 6", self.parent)
        # Check the reused product contract, without modifying or expanding it.
        service = (ROOT / "internal/governance/application/rollout_service.go").read_text()
        start = service.split("func (s *RolloutService) startCanary(", 1)[1]
        lock = start.index("tx.LockScope(ctx, q.Scope)")
        busy = start.index("if snap.LiveRolloutID != nil")
        stale = start.index("snap.ActivationEpoch != q.ExpectedScopeEpoch")
        self.assertLess(lock, busy)
        self.assertLess(busy, stale)
        self.assertIn('commandFailure(FailureBusy, errors.New("scope active rollout slot is occupied"))', start)

    def test_app_and_persisted_state_match_successful_process(self):
        for token in ("winningRollout := domain.RolloutID(rollouts[winner])",
                      "transactor.WithinRolloutTransaction(ctx", "tx.LockScope(ctx, scope)",
                      "*snap.LiveRolloutID != winningRollout", "snap.ActivationEpoch != 41",
                      "snap.SecurityEpoch != security", "snap.Roots[rootB].AuthorizationEpoch != 6",
                      "tx.LockRollout(ctx, scope, winningRollout)", "r.State != domain.RolloutCanary",
                      "*r.TargetRoot != rootB", "live != string(winningRollout)"):
            self.assertIn(token, self.parent)
        self.assertIn("state IN ('CANARY','MONITORING','ROLLING_BACK')", self.parent)
        self.assertIn("scope_id=$1 AND live_rollout_id IS NOT NULL", self.parent)
        self.assertIn("active != 1 || slots != 1 || total != 1 || receipts != 1 || outbox != 1", self.parent)
        self.assertIn("commands[1:], events[1:]", self.parent)

    def test_bounded_process_lifetime_wait_and_cleanup(self):
        self.assertIn("context.WithTimeout(context.Background(), 60*time.Second)", self.parent)
        self.assertIn('"-test.timeout=45s"', self.launch)
        self.assertIn("context.WithTimeout(context.Background(), 40*time.Second)", self.helper)
        self.assertIn("childCtx, cancel := context.WithCancel(ctx)", self.launch)
        self.assertIn("t.Cleanup(func()", self.launch)
        self.assertIn("cancel()", self.launch)
        self.assertIn("cmd.Process != nil && !child.waited", self.launch)
        self.assertIn("cmd.Wait()", self.launch)
        self.assertIn("stdin.Close()", self.launch)
        self.assertIn("stdout.Close()", self.launch)
        self.assertLess(self.parent.index("child.stdout.Err()"), self.parent.index("child.cmd.Wait()"))
        self.assertIn("child.waited = true", self.parent)
        self.assertIn("cmd.Stderr = io.Discard", self.launch)

    def test_cleanup_exact_named_rows_and_never_global_security_epoch(self):
        cleanup = self.parent.split("t.Cleanup(func()", 1)[1].split("if err := seed.Commit(ctx)", 1)[0]
        sql = re.findall(r"`([^`]+)`", cleanup)
        self.assertEqual(sql, [
            "DELETE FROM raw.event_outbox WHERE event_id=ANY($1::text[])",
            "DELETE FROM raw.domain_events WHERE event_id=ANY($1::text[])",
            "DELETE FROM raw.command_receipts WHERE command_id=ANY($1::text[])",
            "UPDATE raw.policy_scopes SET live_rollout_id=NULL WHERE scope_id=$1",
            "DELETE FROM raw.rollout_targets WHERE rollout_id=ANY($1::text[])",
            "DELETE FROM raw.policy_rollouts WHERE rollout_id=ANY($1::text[])",
            "DELETE FROM raw.roots WHERE root_id=ANY($1::text[]) AND scope_id=$2",
            "DELETE FROM raw.policy_scopes WHERE scope_id=$1",
            "DELETE FROM raw.policy_bundles WHERE bundle_digest=$1 OR bundle_digest=$2",
        ])
        self.assertIn("context.WithTimeout(context.Background(), 15*time.Second)", cleanup)
        self.assertIn("rand.Read(suffix)", self.parent)
        self.assertIn('prefix := "it_rollout_race_" + hex.EncodeToString(suffix)', self.parent)
        all_sql = "\n".join(re.findall(r"`([^`]+)`", self.source))
        self.assertNotRegex(all_sql.lower(), r"\b(?:update|insert into|delete from)\s+raw\.security_generation")
        self.assertNotIn("safety_cas_security_epoch", self.source)
        self.assertNotIn("TRUNCATE", all_sql.upper())

    def test_no_product_api_schema_dependency_or_http_expansion(self):
        sql = "\n".join(re.findall(r"`([^`]+)`", self.source)).lower()
        self.assertNotRegex(sql, r"\b(?:create|alter|drop|grant|revoke|truncate)\b")
        self.assertNotRegex(self.source, r'"(?:net/http|net|database/sql)"')
        self.assertNotRegex(self.source, r"(?:http\.|ListenAndServe|HandleFunc|exec\.Command\()")
        self.assertNotIn("/pull", self.source)
        self.assertNotRegex(self.source, r"(?m)^type [A-Z]\w*")
        imports = re.findall(r'^\s*"([^"\n]+)"', self.source.split("import (", 1)[1].split(")", 1)[0], re.M)
        self.assertEqual([p for p in imports if "." in p.split("/")[0]], [
            "github.com/jackc/pgx/v5/pgxpool",
            "github.com/letwir/paddock/internal/governance/application",
            "github.com/letwir/paddock/internal/governance/domain",
            "github.com/letwir/paddock/internal/governance/port",
        ])


if __name__ == "__main__":
    unittest.main()
