"""Mutation tests for the S03 document/evidence tracking contract."""
from pathlib import Path
import importlib.util
import json
import re
import shutil
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("paddock_lint_s03", SOURCE / "scripts" / "lint_design.py")
LINTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINTER)


class S03TrackingContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in LINTER.NAME_FILES:
            shutil.copy2(SOURCE / name, self.root / name)
        shutil.copy2(SOURCE / "AGENTS.md", self.root / "AGENTS.md")
        shutil.copytree(SOURCE / "rules", self.root / "rules")
        (self.root / "docs").mkdir()
        shutil.copy2(SOURCE / "docs" / "issue-dependencies.generated.md", self.root / "docs" / "issue-dependencies.generated.md")
        shutil.copy2(SOURCE / "docs" / "bootstrap-safety.md", self.root / "docs" / "bootstrap-safety.md")
        (self.root / "scripts").mkdir()
        shutil.copy2(SOURCE / "scripts" / "lint_design.py", self.root / "scripts" / "lint_design.py")

    def tearDown(self):
        self.temp.cleanup()

    def errors(self):
        return LINTER.validate(self.root, check_generated=False)[0]

    def mutate(self, path, old, new):
        file = self.root / path
        data = file.read_text(encoding="utf-8")
        self.assertIn(old, data)
        file.write_text(data.replace(old, new, 1), encoding="utf-8")

    def test_clean_cursor_with_none_receipt_is_valid(self):
        self.assertEqual(self.errors(), [])

    def test_missing_receipt_reference_is_rejected(self):
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "receipts/PDK-M00-S02/missing.json"')
        self.assertTrue(any("RECEIPT_REF_INVALID" in err for err in self.errors()))

    def test_receipt_symlink_escape_is_rejected(self):
        external = self.root.parent / "outside-receipt.json"
        external.write_text(json.dumps({"schema_version": "paddock.receipt/1", "issue_id": "PDK-M00-S02"}), encoding="utf-8")
        link = self.root / "receipts" / "PDK-M00-S02" / "linked.json"
        link.parent.mkdir(parents=True)
        link.symlink_to(external)
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "receipts/PDK-M00-S02/linked.json"')
        self.assertTrue(any("RECEIPT_REF_INVALID" in err for err in self.errors()))

    def test_receipt_schema_and_issue_reference_are_checked(self):
        path = self.root / "receipts" / "PDK-M00-S02" / "sample.json"
        path.parent.mkdir(parents=True)
        issues_text = (self.root / "Issues.md").read_text(encoding="utf-8")
        active_issue = re.search(r"^active_issue: (PDK-M\d{2}-S\d{2})$", issues_text, re.M).group(1)
        path.write_text(json.dumps({"schema_version": "paddock.receipt/1", "issue_id": active_issue}), encoding="utf-8")
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "receipts/PDK-M00-S02/sample.json"')
        self.assertFalse(any("RECEIPT_" in err for err in self.errors()), self.errors())
        path.write_text(json.dumps({"schema_version": "wrong/1", "issue_id": "PDK-M99-S99"}), encoding="utf-8")
        self.assertTrue(any("RECEIPT_SCHEMA_INVALID" in err for err in self.errors()))

    def test_unregistered_receipt_issue_is_rejected(self):
        path = self.root / "receipts" / "PDK-M00-S02" / "sample.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"schema_version": "paddock.receipt/1", "issue_id": "PDK-M99-S99"}), encoding="utf-8")
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "receipts/PDK-M00-S02/sample.json"')
        self.assertTrue(any("RECEIPT_SCHEMA_INVALID" in err for err in self.errors()))

    def test_receipt_issue_must_match_active_cursor(self):
        path = self.root / "receipts" / "PDK-M00-S02" / "sample.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"schema_version": "paddock.receipt/1", "issue_id": "PDK-M00-S01"}), encoding="utf-8")
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "receipts/PDK-M00-S02/sample.json"')
        self.assertTrue(any("RECEIPT_SCHEMA_INVALID" in err for err in self.errors()))

    def test_receipt_path_escape_is_rejected(self):
        self.mutate("Issues.md", 'last_receipt: NONE', 'last_receipt: "../outside.json"')
        self.assertTrue(any("RECEIPT_REF_INVALID" in err for err in self.errors()))

    def test_unknown_decision_supersedes_target_is_rejected(self):
        file = self.root / "decisions.md"
        data = file.read_text(encoding="utf-8")
        mutated, count = re.subn(r"^### D-015[^\n]*$", "### D-015 / Fixture\nsupersedes: D-999", data, count=1, flags=re.M)
        self.assertEqual(count, 1)
        file.write_text(mutated, encoding="utf-8")
        self.assertTrue(any("DECISION_SUPERSEDES_UNKNOWN" in err for err in self.errors()))

    def test_self_supersedes_is_rejected(self):
        file = self.root / "decisions.md"
        data = file.read_text(encoding="utf-8")
        mutated, count = re.subn(r"^### D-015[^\n]*$", "### D-015 / Fixture\nsupersedes: D-015", data, count=1, flags=re.M)
        self.assertEqual(count, 1)
        file.write_text(mutated, encoding="utf-8")
        self.assertTrue(any("DECISION_SUPERSEDES_SELF" in err for err in self.errors()))

    def test_cursor_state_is_required(self):
        file = self.root / "Issues.md"
        data = file.read_text(encoding="utf-8")
        mutated, count = re.subn(r"^issue_state: .*\n", "", data, count=1, flags=re.M)
        self.assertEqual(count, 1)
        file.write_text(mutated, encoding="utf-8")
        self.assertTrue(any("CURSOR_MISSING_STATE" in err for err in self.errors()))

    def test_missing_cursor_state_is_reported_even_with_bad_issue_id(self):
        file = self.root / "Issues.md"
        data = file.read_text(encoding="utf-8")
        mutated_id, count_id = re.subn(r"^active_issue: PDK-M\d{2}-S\d{2}$", "active_issue: PDK-M99-S99", data, count=1, flags=re.M)
        self.assertEqual(count_id, 1)
        mutated, count = re.subn(r"^issue_state: .*\n", "", mutated_id, count=1, flags=re.M)
        self.assertEqual(count, 1)
        file.write_text(mutated, encoding="utf-8")
        errors = self.errors()
        self.assertTrue(any("CURSOR_BAD_ID" in err for err in errors), errors)
        self.assertTrue(any("CURSOR_MISSING_STATE" in err for err in errors), errors)

    def test_duplicate_decision_id_is_rejected(self):
        self.mutate("decisions.md", "| D-015 |", "| D-014 |")
        self.assertTrue(any("DECISION_REGISTER" in err for err in self.errors()))


if __name__ == "__main__":
    unittest.main()
