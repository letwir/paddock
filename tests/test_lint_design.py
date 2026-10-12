"""PADDOCK design linter negative fixtures; no database/network dependencies."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('paddock_lint',SOURCE/'scripts/lint_design.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DesignLintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for f in MODULE.NAME_FILES:
            shutil.copy2(SOURCE/f, self.root/f)
        (self.root/'docs').mkdir()
        (self.root/'scripts').mkdir()
        shutil.copy2(SOURCE/'scripts/lint_design.py',self.root/'scripts/lint_design.py')
        shutil.copy2(SOURCE/'docs/issue-dependencies.generated.md',self.root/'docs/issue-dependencies.generated.md')

    def tearDown(self):
        self.tmp.cleanup()

    def patch_issues(self, before, after):
        p = self.root/'Issues.md'
        t = p.read_text(encoding='utf-8')
        self.assertIn(before,t)
        p.write_text(t.replace(before,after,1), encoding='utf-8')

    def assert_error(self, text):
        errors,_,_=MODULE.validate(self.root,check_generated=False)
        self.assertTrue(any(text in e for e in errors), errors)

    def test_clean(self):
        errors,rows,_=MODULE.validate(self.root)
        self.assertEqual(errors,[])
        self.assertEqual(len(rows),89)

    def test_unknown_dependency(self):
        self.patch_issues('`depends_on`: PDK-M00-S01','`depends_on`: PDK-M99-S99')
        self.assert_error('UNKNOWN_DEP')

    def test_cycle(self):
        self.patch_issues('`depends_on`: none','`depends_on`: PDK-M00-S05')
        self.assert_error('CYCLE')

    def test_stale_generated_index(self):
        d=self.root/'docs/issue-dependencies.generated.md'
        d.write_text(d.read_text(encoding='utf-8')+'tampered\n', encoding='utf-8')
        self.assertTrue(any('STALE_GENERATED_INDEX' in e for e in MODULE.validate(self.root)[0]))

    def test_open_without_concrete_issue(self):
        p=self.root/'decisions.md'
        s=p.read_text(encoding='utf-8')
        s=s.replace('| PDK-M05-S02 |','| M05 |',1)
        p.write_text(s, encoding='utf-8')
        self.assert_error('OPEN_NO_RESOLVER')

if __name__=='__main__': unittest.main()
