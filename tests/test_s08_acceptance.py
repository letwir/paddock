"""Focused S08 acceptance tests for the design-document linter."""
from pathlib import Path
import importlib.util
import re
import shutil
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "paddock_lint_s08", SOURCE / "scripts" / "lint_design.py"
)
LINTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINTER)


class S08AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in LINTER.NAME_FILES:
            shutil.copy2(SOURCE / name, self.root / name)
        shutil.copy2(SOURCE / "AGENTS.md", self.root / "AGENTS.md")
        (self.root / "docs").mkdir()
        shutil.copy2(
            SOURCE / "docs" / "issue-dependencies.generated.md",
            self.root / "docs" / "issue-dependencies.generated.md",
        )
        shutil.copy2(SOURCE / "docs" / "bootstrap-safety.md", self.root / "docs" / "bootstrap-safety.md")
        shutil.copytree(SOURCE / "rules", self.root / "rules")
        (self.root / "scripts").mkdir()
        shutil.copy2(SOURCE / "scripts" / "lint_design.py", self.root / "scripts" / "lint_design.py")

    def tearDown(self):
        self.tmp.cleanup()

    def validate(self):
        return LINTER.validate(self.root, check_generated=False)[0]

    def change_once(self, path, old, new):
        file = self.root / path
        text = file.read_text(encoding="utf-8")
        self.assertIn(old, text, f"fixture anchor missing in {path}: {old!r}")
        file.write_text(text.replace(old, new, 1), encoding="utf-8")

    def assert_lint_error(self, code):
        errors = self.validate()
        self.assertTrue(any(code in error for error in errors), errors)

    def test_duplicate_issue_id_is_reported(self):
        issues = self.root / "Issues.md"
        text = issues.read_text(encoding="utf-8")
        ids = list(re.finditer(r"^- \[[ x~*\-]\] `(PDK-M\d{2}-S\d{2})`", text, re.M))
        self.assertGreaterEqual(len(ids), 2)
        duplicate_id = ids[0].group(1)
        target = ids[1]
        mutated = text[:target.start(1)] + duplicate_id + text[target.end(1):]
        issues.write_text(mutated, encoding="utf-8")
        self.assert_lint_error(f"DUPLICATE_ISSUE: {duplicate_id}")

    def test_dangling_dependency_is_reported(self):
        self.change_once(
            "Issues.md",
            "`depends_on`: PDK-M00-S01",
            "`depends_on`: PDK-M99-S99",
        )
        self.assert_lint_error("UNKNOWN_DEP: PDK-M00-S02->PDK-M99-S99")

    def test_dependency_cycle_is_reported(self):
        self.change_once(
            "Issues.md",
            "`depends_on`: none",
            "`depends_on`: PDK-M00-S05",
        )
        self.assert_lint_error("CYCLE:")

    def test_open_decision_without_concrete_resolver_is_reported(self):
        self.change_once("decisions.md", "| PDK-M05-S02 |", "| M05 |")
        self.assert_lint_error("OPEN_NO_RESOLVER: O-001")

    def test_broken_markdown_link_is_reported(self):
        self.change_once("README.md", "](THREAT_MODEL.md)", "](missing-threat-model.md)")
        self.assert_lint_error("BROKEN_LINK: README.md -> missing-threat-model.md")

    def test_cursor_status_mismatch_is_reported(self):
        issues = self.root / "Issues.md"
        text = issues.read_text(encoding="utf-8")
        text, count = re.subn(
            r"(?m)^(\s*issue_state:\s*)\S+",
            r"\1INVALID_ENUM",
            text,
            count=1,
        )
        self.assertEqual(count, 1, "fixture issue_state anchor missing")
        issues.write_text(text, encoding="utf-8")
        self.assert_lint_error("CURSOR_STATUS_MISMATCH")

    def test_generated_index_is_derived_from_issues_source(self):
        errors, records, source_sha = LINTER.validate(self.root, check_generated=False)
        self.assertEqual(errors, [])
        self.assertEqual(
            source_sha,
            __import__("hashlib").sha256(
                (self.root / "Issues.md").read_bytes()
            ).hexdigest(),
        )
        rendered = LINTER.render(records, source_sha)
        self.assertIn(f"Issues.md SHA-256: `{source_sha}`", rendered)
        self.assertIn("PDK-M00-S08", rendered)

        # Changing the source issue changes the generated digest and index content.
        self.change_once(
            "Issues.md",
            "`acceptance`: Issue ID重複",
            "`acceptance`: Issue識別子の重複",
        )
        changed_errors, changed_records, changed_sha = LINTER.validate(
            self.root, check_generated=False
        )
        self.assertEqual(changed_errors, [])
        self.assertNotEqual(changed_sha, source_sha)
        changed_rendered = LINTER.render(changed_records, changed_sha)
        self.assertIn("PDK-M00-S08", changed_rendered)
        self.assertNotEqual(changed_rendered, rendered)


if __name__ == "__main__":
    unittest.main()
