"""S02 tests for PADDOCK's independent Git-root boundary."""
from pathlib import Path
import subprocess
import unittest


PADDOCK_ROOT = Path(__file__).resolve().parents[1]
# The configured parent repository boundary is intentionally checked by path
# relationship only; the parent and any .HARNESS contents are never inspected.
PARENT_REPO_ROOT = PADDOCK_ROOT.parents[1] / ".harness"


def is_within_root(candidate: str, parent_root: str) -> bool:
    """Return whether candidate is parent_root or a descendant, lexically."""
    candidate_path = Path(candidate)
    parent_path = Path(parent_root)
    try:
        return candidate_path == parent_path or parent_path in candidate_path.parents
    except (OSError, ValueError):
        return False


class S02RepoBoundaryTests(unittest.TestCase):
    def test_paddock_identifies_its_own_git_root(self):
        result = subprocess.run(
            ["git", "-C", str(PADDOCK_ROOT), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
        git_root = Path(result.stdout.strip()).resolve()
        self.assertEqual(git_root, PADDOCK_ROOT.resolve())

    def test_git_root_is_not_nested_under_configured_parent_root(self):
        result = subprocess.run(
            ["git", "-C", str(PADDOCK_ROOT), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
        git_root = Path(result.stdout.strip()).resolve()
        self.assertFalse(
            is_within_root(str(git_root), str(PARENT_REPO_ROOT)),
            f"PADDOCK Git root {git_root} is nested under {PARENT_REPO_ROOT}",
        )

    def test_path_relationship_uses_path_strings_without_filesystem_access(self):
        self.assertTrue(is_within_root("/workspace/repo/paddock", "/workspace/repo"))
        self.assertTrue(is_within_root("/workspace/repo", "/workspace/repo"))
        self.assertFalse(is_within_root("/workspace/paddock", "/workspace/repo"))
        self.assertFalse(is_within_root("/workspace/repository", "/workspace/repo"))


if __name__ == "__main__":
    unittest.main()
