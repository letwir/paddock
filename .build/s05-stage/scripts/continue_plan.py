#!/usr/bin/env python3
"""Deterministically choose a PADDOCK CONTINUE/1 issue from Issues.md."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lint_design

ISSUE_RE = re.compile(r'^- \[([ x~*\-])\] `(PDK-M\d{2}-S\d{2})`[^\n]*$', re.M)
DEP_RE = re.compile(r'^  - `depends_on`: (.+)$', re.M)

STATE_NAME = {' ': 'TODO', '-': 'WIP', '~': 'IMPLEMENTED', '*': 'TESTED', 'x': 'DONE'}


def plan(root: Path) -> dict[str, str]:
    """Validate documents and return a stable issue/reason pair or fail closed."""
    root = root.resolve()
    errors, _, _ = lint_design.validate(root, check_generated=False)
    if errors:
        raise ValueError('design lint failed: ' + '; '.join(errors))

    text = (root / 'Issues.md').read_text(encoding='utf-8')
    matches = list(ISSUE_RE.finditer(text))
    records: dict[str, tuple[str, list[str], bool, bool]] = {}
    ordered: list[str] = []
    for index, match in enumerate(matches):
        issue_id, marker = match.group(2), match.group(1)
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        chunk = text[match.end():end].split('\n### ')[0].split('\n## ')[0]
        dep_match = DEP_RE.search(chunk)
        deps = [] if dep_match is None or dep_match.group(1).strip() == 'none' else re.findall(r'PDK-M\d{2}-S\d{2}', dep_match.group(1))
        blocked = bool(re.search(r'^  - `blocker`:.*\S', chunk, re.M))
        evidence = bool(re.search(r'^  - `current_evidence`:.*\S', chunk, re.M))
        records[issue_id] = (marker, deps, blocked, evidence)
        ordered.append(issue_id)

    for issue_id in ordered:
        marker, _, _, evidence = records[issue_id]
        if marker == 'x' and not evidence:
            raise ValueError(f'completed issue lacks current_evidence: {issue_id}')

    cursor_id = re.search(r'^active_issue: (.+)$', text, re.M)
    cursor_state = re.search(r'^issue_state: (.+)$', text, re.M)
    if not cursor_id or not cursor_state or cursor_id.group(1) not in records:
        raise ValueError('invalid Cursor: missing or unknown active_issue/issue_state')
    active_id, active_state = cursor_id.group(1), cursor_state.group(1)
    marker, _, blocked, _ = records[active_id]
    if STATE_NAME.get(marker) != active_state:
        raise ValueError(f'Cursor mismatch: {active_id} is {STATE_NAME.get(marker)}, Cursor says {active_state}')

    if active_state in {'WIP', 'IMPLEMENTED', 'TESTED'}:
        if blocked:
            raise ValueError(f'active issue is explicitly blocked: {active_id}')
        return {'issue_id': active_id, 'reason': f'resume_cursor_{active_state.lower()}'}

    # TODO and DONE cursors are not active work; choose first runnable TODO.
    for issue_id in ordered:
        candidate_state, deps, is_blocked, _ = records[issue_id]
        if candidate_state != ' ' or is_blocked:
            continue
        if all(records.get(dep, ('?', [], False, False))[0] == 'x' for dep in deps):
            return {'issue_id': issue_id, 'reason': 'first_ready_incomplete'}
    raise ValueError('no READY incomplete issue found')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = plan(args.root)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({'error': str(exc)}, sort_keys=True, separators=(',', ':')))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
