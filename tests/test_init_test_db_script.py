from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "init_test_db.sh"


class InitTestDatabaseScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        self.bin_path = self.temp_path / "bin"
        self.bin_path.mkdir()
        self.log_path = self.temp_path / "psql-calls.log"
        fake_psql = self.bin_path / "psql"
        fake_psql.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "args=\"$*\"\n"
            "[[ \"${1:-}\" == 'postgresql://mock-user:mock-secret@localhost/paddock_test' ]] || exit 91\n"
            "[[ \"$args\" != *--dbname=* ]] || exit 92\n"
            "if [[ \"$args\" == *'SELECT current_database()'* ]]; then\n"
            "  printf '%s\\t%s\\n' \"${MOCK_DB_NAME:-paddock_test}\" \"${MOCK_SERVER_VERSION:-18.6}\"\n"
            "  printf 'identity\\n' >> \"$MOCK_PSQL_LOG\"\n"
            "elif [[ \"$args\" == *'SELECT count(*)'* ]]; then\n"
            "  printf '%s\\n' \"${MOCK_RAW_RELATIONS:-0}\"\n"
            "  printf 'relations\\n' >> \"$MOCK_PSQL_LOG\"\n"
            "elif [[ \"$args\" == *'--file='* ]]; then\n"
            "  printf 'apply\\n' >> \"$MOCK_PSQL_LOG\"\n"
            "  printf 'mock apply ok\\n'\n"
            "else\n"
            "  exit 93\n"
            "fi\n",
            encoding="utf-8",
        )
        fake_psql.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.bin_path}:{self.env['PATH']}",
                "PADDOCK_DB_URL": "postgresql://mock-user:mock-secret@localhost/paddock_test",
                "MOCK_PSQL_LOG": str(self.log_path),
            }
        )

    def run_script(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env.update(extra_env)
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def calls(self) -> list[str]:
        if not self.log_path.exists():
            return []
        return self.log_path.read_text(encoding="utf-8").splitlines()

    def assert_no_secret(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotIn("mock-secret", result.stdout + result.stderr)

    def test_requires_explicit_apply_before_any_connection(self) -> None:
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pass --check", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assert_no_secret(result)

    def test_help_does_not_require_dsn_or_connect(self) -> None:
        result = self.run_script("--help", PADDOCK_DB_URL="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--apply", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_refuses_wrong_database_before_schema_check(self) -> None:
        result = self.run_script("--apply", MOCK_DB_NAME="llm_memory")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not exactly paddock_test", result.stderr)
        self.assertEqual(self.calls(), ["identity"])
        self.assert_no_secret(result)

    def test_refuses_existing_raw_relations_without_applying(self) -> None:
        result = self.run_script("--apply", MOCK_RAW_RELATIONS="25")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("raw already contains relations", result.stderr)
        self.assertEqual(self.calls(), ["identity", "relations"])
        self.assert_no_secret(result)

    def test_check_is_read_only_and_reports_existing_schema(self) -> None:
        result = self.run_script("--check", MOCK_RAW_RELATIONS="25")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("raw_relations=25", result.stdout)
        self.assertIn("no DDL", result.stdout)
        self.assertEqual(self.calls(), ["identity", "relations"])
        self.assert_no_secret(result)

    def test_applies_only_after_all_guards_and_never_exposes_dsn(self) -> None:
        result = self.run_script("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PostgreSQL 18.6", result.stdout)
        self.assertEqual(self.calls(), ["identity", "relations", "apply"])
        self.assert_no_secret(result)

    def test_rejects_invalid_version_response(self) -> None:
        result = self.run_script("--apply", MOCK_SERVER_VERSION="unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server version response was invalid", result.stderr)
        self.assertEqual(self.calls(), ["identity"])
        self.assert_no_secret(result)


if __name__ == "__main__":
    unittest.main()
