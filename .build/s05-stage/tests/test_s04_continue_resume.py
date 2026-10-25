"""Deterministic CONTINUE/1 planner restart and fail-closed regressions."""
from pathlib import Path
import importlib.util
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("paddock_continue", SOURCE / "scripts" / "continue_plan.py")
PLANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLANNER)


class S04ContinueResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ("README.md", "decisions.md", "Issues.md", "method.md", "THREAT_MODEL.md"):
            shutil.copy2(SOURCE / name, self.root / name)
        shutil.copytree(SOURCE / "docs", self.root / "docs")
        shutil.copy2(SOURCE / "AGENTS.md", self.root / "AGENTS.md")
        shutil.copytree(SOURCE / "rules", self.root / "rules")
        (self.root / "scripts").mkdir()
        shutil.copy2(SOURCE / "scripts" / "lint_design.py", self.root / "scripts" / "lint_design.py")
        # Model the pre-interruption durable state in the disposable fixture,
        # independent of the live Cursor's current review status.
        issue_text = (self.root / "Issues.md").read_text(encoding="utf-8")
        issue_text, active_count = re.subn(r"^active_issue: PDK-M\d{2}-S\d{2}$", "active_issue: PDK-M00-S04", issue_text, count=1, flags=re.M)
        issue_text, state_count = re.subn(r"^issue_state: [A-Z_]+$", "issue_state: WIP", issue_text, count=1, flags=re.M)
        issue_text, marker_count = re.subn(r"^- \[[ x~*\-]\] `PDK-M00-S04`", "- [-] `PDK-M00-S04`", issue_text, count=1, flags=re.M)
        if (active_count, state_count, marker_count) != (1, 1, 1):
            raise AssertionError("could not construct pre-interruption S04 Cursor fixture")
        (self.root / "Issues.md").write_text(issue_text, encoding="utf-8")
        shutil.copy2(SOURCE / "scripts" / "continue_plan.py", self.root / "scripts" / "continue_plan.py")

    def tearDown(self):
        self.temp.cleanup()

    def issues(self):
        return self.root / "Issues.md"

    def mutate(self, old, new):
        text = self.issues().read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.issues().write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_restart_without_conversation_resumes_same_wip_issue(self):
        expected = {"issue_id": "PDK-M00-S04", "reason": "resume_cursor_wip"}
        self.assertEqual(PLANNER.plan(self.root), expected)

    def test_clean_restart_preserves_wip_and_records_local_evidence(self):
        """Exercise a process restart using only temporary, test-owned evidence."""
        evidence_dir = self.root / "test-evidence"
        evidence_dir.mkdir()
        issues_path = self.issues()
        before = issues_path.read_text(encoding="utf-8")
        self.assertEqual(PLANNER.plan(self.root)["issue_id"], "PDK-M00-S04")
        (evidence_dir / "cursor-before.txt").write_text(before, encoding="utf-8")

        # Simulate interrupted, unverified work without changing the Issue state.
        wip_path = self.root / "controlled-wip.txt"
        wip_path.write_text("unverified local work\n", encoding="utf-8")
        diff = "".join(difflib.unified_diff(
            [], wip_path.read_text(encoding="utf-8").splitlines(keepends=True),
            fromfile="a/controlled-wip.txt", tofile="b/controlled-wip.txt"))
        (evidence_dir / "wip.diff").write_text(diff, encoding="utf-8")

        after = issues_path.read_text(encoding="utf-8")
        (evidence_dir / "cursor-after.txt").write_text(after, encoding="utf-8")
        self.assertEqual(before, after)
        self.assertIn("[-] `PDK-M00-S04`", after)

        command = [sys.executable, str(self.root / "scripts" / "continue_plan.py"),
                   "--root", str(self.root)]
        result = subprocess.run(command, cwd=self.root, text=True,
                                capture_output=True, check=False)
        verification = {
            "command": command,
            "result": result.stdout.strip(),
            "exit_code": result.returncode,
        }
        (evidence_dir / "verification.json").write_text(
            json.dumps(verification, sort_keys=True) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "issue_id": "PDK-M00-S04", "reason": "resume_cursor_wip"})
        self.assertIn("controlled-wip.txt", diff)
        # These are temporary local test artifacts, not a CI receipt.
        self.assertEqual(set(path.name for path in evidence_dir.iterdir()), {
            "cursor-before.txt", "cursor-after.txt", "wip.diff", "verification.json"})
    def test_dependencies_and_explicitly_blocked_items_are_skipped(self):
        # Reset Cursor to an already complete issue. S07 is explicitly blocked;
        # the first genuinely ready TODO is M01-S01.
        self.mutate("active_issue: PDK-M00-S04", "active_issue: PDK-M00-S01")
        self.mutate("issue_state: WIP", "issue_state: DONE")
        self.assertEqual(PLANNER.plan(self.root), {
            "issue_id": "PDK-M01-S01", "reason": "first_ready_incomplete"})

    def test_done_issue_without_current_evidence_is_rejected(self):
        self.mutate("- [-] `PDK-M00-S04`", "- [x] `PDK-M00-S04`")
        self.mutate("issue_state: WIP", "issue_state: DONE")
        text = self.issues().read_text(encoding="utf-8")
        match = re.search(r"^- \[x\] `PDK-M00-S04`[\s\S]*?(?=^- \[|\Z)", text, re.M)
        self.assertIsNotNone(match)
        chunk = match.group(0)
        chunk, count = re.subn(r"^  - `current_evidence`:.*\n", "", chunk, count=1, flags=re.M)
        self.assertEqual(count, 1)
        self.issues().write_text(text[:match.start()] + chunk + text[match.end():], encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "lacks current_evidence: PDK-M00-S04"):
            PLANNER.plan(self.root)

    def test_cursor_issue_state_mismatch_fails_closed(self):
        self.mutate("issue_state: WIP", "issue_state: TODO")
        with self.assertRaisesRegex(ValueError, "CURSOR_STATUS_MISMATCH|Cursor mismatch"):
            PLANNER.plan(self.root)


if __name__ == "__main__":
    unittest.main()
