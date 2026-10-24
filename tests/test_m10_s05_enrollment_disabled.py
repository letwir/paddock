"""Static acceptance checks for the disabled Coordinator enrollment fallback."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EnrollmentDisabledTests(unittest.TestCase):
    def test_handler_registers_only_health_and_pull(self):
        source = (ROOT / "internal/harness/poc.go").read_text()
        registrations = re.findall(r'mux\.HandleFunc\("([A-Z]+) ([^" ]+)', source)
        self.assertEqual(
            registrations,
            [("GET", "/healthz"), ("POST", "/pull")],
            "Coordinator handler must expose only its existing health and pull routes",
        )

    def test_loopback_guard_precedes_database_configuration_and_connection(self):
        source = (ROOT / "cmd/coordinator/main.go").read_text()
        guard = re.search(
            r'addr, err := net\.ResolveTCPAddr\("tcp", \*listen\).*?'
            r'if err != nil \|\| !addr\.IP\.IsLoopback\(\) \{.*?'
            r'log\.Fatal\("-listen must be an explicit loopback IP address"\)'
            r'.*?\n\s*\}',
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(guard, "explicit loopback listener guard must be present")
        guard_end = guard.end()
        db_config = source.index('os.Getenv("PADDOCK_DB_URL")')
        db_connect = source.index("pgxpool.NewWithConfig(")
        self.assertLess(guard_end, db_config, "listener guard must precede DB configuration")
        self.assertLess(guard_end, db_connect, "listener guard must precede DB connection setup")


if __name__ == "__main__":
    unittest.main()
