"""PADDOCK design linter negative fixtures; no database/network dependencies."""
from pathlib import Path
import importlib.util
import re
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
        shutil.copy2(SOURCE/'AGENTS.md',self.root/'AGENTS.md')
        shutil.copytree(SOURCE/'rules',self.root/'rules')
        (self.root/'docs').mkdir()
        shutil.copy2(SOURCE/'docs/bootstrap-safety.md',self.root/'docs/bootstrap-safety.md')
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

    def test_s01_acceptance_content(self):
        decisions=(self.root/'decisions.md').read_text(encoding='utf-8')
        expected={f'D-{i:03d}' for i in range(1,15)}
        self.assertEqual(set(MODULE.DEC_RE.findall(decisions)),expected)
        readme=(self.root/'README.md').read_text(encoding='utf-8')
        for target in ('THREAT_MODEL.md','Issues.md','method.md'):
            self.assertRegex(readme,rf'\]\({re.escape(target)}\)')
        for path in ('decisions.md','THREAT_MODEL.md','README.md'):
            self.assertIn('DESIGN_BASELINE',(self.root/path).read_text(encoding='utf-8'))

    def test_s05_threat_model_dimensions(self):
        threat=(self.root/'THREAT_MODEL.md').read_text(encoding='utf-8')
        rows=[line for line in threat.splitlines() if re.match(r'^\| TM-\d{3} ',line)]
        self.assertEqual(len(rows),15)
        for heading in ('守る資産','入口 / Trust Boundary','推奨Mitigation','残余リスク'):
            self.assertIn(heading,threat)
        for row in rows:
            cells=[cell.strip() for cell in row.strip('|').split('|')]
            self.assertEqual(len(cells),7,row)
            self.assertTrue(cells[1],row)
            self.assertTrue(cells[2],row)
            self.assertTrue(cells[4],row)
            self.assertTrue(cells[5],row)
            self.assertRegex(cells[6],r'PDK-M\d{2}-S\d{2}')

    def test_s06_bootstrap_safety_boundaries(self):
        safety=(self.root/'docs/bootstrap-safety.md').read_text(encoding='utf-8')
        for phrase in ('PoC approval keys','dedicated disposable test database',
                       'Emergency Stop lifecycle','Safe Baseline','**Release:**',
                       'O-002','O-003','O-010','PDK-M06-S08','PDK-M02-S05','PDK-M06-S05',
                       'remain OPEN','grants no DB access'):
            self.assertIn(phrase,safety)

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
