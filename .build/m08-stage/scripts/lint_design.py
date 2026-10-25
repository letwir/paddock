#!/usr/bin/env python3
"""PADDOCK document + small-task DAG linter. Python stdlib only.

No writes except --emit-summary (generated document). No Git/network access.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys

ISSUE_RE = re.compile(r'^- \[([ x~*\-])\] `(PDK-M\d{2}-S\d{2})`[^\n]*$', re.M)
DEP_RE = re.compile(r'^  - `depends_on`: (.+)$', re.M)
REF_RE = re.compile(r'PDK-M\d{2}-S\d{2}')
LINK_RE = re.compile(r'(?<!!)\[[^\]]*\]\(([^)]+)\)')
DEC_RE = re.compile(r'^\| (D-\d{3}) \|', re.M)
OPEN_RE = re.compile(r'^\| (O-\d{3}) \|[^\n]+$', re.M)
NAME_FILES = ['README.md','decisions.md','Issues.md','method.md','THREAT_MODEL.md']


def validate(root: Path, check_generated: bool = True) -> tuple[list[str], dict[str,tuple[str,list[str]]], str]:
    errs = []
    documents = {}
    for name in NAME_FILES:
        file = root / name
        if not file.is_file():
            errs.append(f'MISSING_FILE: {name}')
            continue
        documents[name] = file.read_text(encoding='utf-8')

    if 'Issues.md' not in documents:
        return errs, {}, ''
    text = documents['Issues.md']
    matches = list(ISSUE_RE.finditer(text))
    ids = [m.group(2) for m in matches]
    for name, count in collections.Counter(ids).items():
        if count != 1:
            errs.append(f'DUPLICATE_ISSUE: {name} ({count})')

    records = {}
    for i, m in enumerate(matches):
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        # Avoid accidentally capturing another section's narrative.
        chunk = text[m.end():end].split('\n### ')[0].split('\n## ')[0]
        dep = DEP_RE.findall(chunk)
        if len(dep) != 1:
            errs.append(f'DEP_FIELD: {m.group(2)} ({len(dep)} found)')
            continue
        parsed = REF_RE.findall(dep[0])
        if dep[0].strip() != 'none' and not parsed:
            errs.append(f'INVALID_DEPS: {m.group(2)}: {dep[0]}')
        for field in ('acceptance', 'evidence_expected'):
            if not re.search(rf'^  - `{field}`:',chunk,re.M):
                errs.append(f'MISSING_FIELD: {m.group(2)}.{field}')
        if len(parsed) != len(set(parsed)):
            errs.append(f'DUPLICATE_DEP: {m.group(2)}')
        records[m.group(2)] = (m.group(1), parsed)

    for key, (_, deps) in records.items():
        for dep in deps:
            if dep not in records:
                errs.append(f'UNKNOWN_DEP: {key}->{dep}')
            if dep == key:
                errs.append(f'SELF_DEP: {key}')
    visited, visiting = set(), set()
    def walk(key, stack):
        if key in visiting:
            errs.append('CYCLE: ' + ' -> '.join(stack + [key]))
            return
        if key in visited: return
        visiting.add(key)
        for child in records[key][1]:
            if child in records: walk(child, stack + [key])
        visiting.remove(key)
        visited.add(key)
    for key in records: walk(key, [])

    cursor_issue = re.search(r'^active_issue: (.+)$',text,re.M)
    cursor_state = re.search(r'^issue_state: (.+)$',text,re.M)
    if not cursor_issue or cursor_issue.group(1) not in records:
        errs.append('CURSOR_BAD_ID')
    if not cursor_state:
        errs.append('CURSOR_MISSING_STATE')
    elif cursor_issue and cursor_issue.group(1) in records:
        expected = {'TODO':' ', 'WIP':'-', 'IMPLEMENTED':'~', 'TESTED':'*', 'DONE':'x'}
        if expected.get(cursor_state.group(1)) != records[cursor_issue.group(1)][0]:
            errs.append('CURSOR_STATUS_MISMATCH')
    if 'execution_state: NOT_STARTED' in text and cursor_state and cursor_state.group(1) != 'TODO':
        errs.append('CURSOR_EXECUTION_CONFLICT')

    # OPEN backlog must route to a concrete issue, not just an entire milestone.
    dec = documents.get('decisions.md','')
    for open_row in OPEN_RE.finditer(dec):
        name = open_row.group(1)
        target_ids = REF_RE.findall(open_row.group(0))
        if not target_ids:
            errs.append(f'OPEN_NO_RESOLVER: {name}')
        for target in target_ids:
            if target not in records: errs.append(f'OPEN_UNKNOWN_ISSUE: {name}->{target}')
    decisions = DEC_RE.findall(dec)
    decision_numbers = sorted(int(item[2:]) for item in decisions)
    expected_decisions = list(range(1, max(decision_numbers, default=0) + 1))
    if len(decisions) != len(set(decisions)) or decision_numbers != expected_decisions or len(decisions) < 14:
        errs.append(f'DECISION_REGISTER: expected sequential unique D-001..D-N with N >= 14, got {len(decisions)}')

    # Decision supersedes are append-only: references must resolve to a
    # different registered ID. The linter never rewrites the decision record.
    decision_doc = documents.get('decisions.md', '')
    sections = list(re.finditer(r'^### (D-\d{3})[^\n]*\n', decision_doc, re.M))
    for index, section in enumerate(sections):
        end = sections[index + 1].start() if index + 1 < len(sections) else len(decision_doc)
        body = decision_doc[section.end():end]
        for superseded in re.findall(r'^\s*supersedes:\s*(D-\d{3})\s*$', body, re.M):
            if superseded == section.group(1):
                errs.append(f'DECISION_SUPERSEDES_SELF: {section.group(1)}')
            elif superseded not in decisions:
                errs.append(f'DECISION_SUPERSEDES_UNKNOWN: {section.group(1)}->{superseded}')

    # Cursor receipt references are structural evidence references only. This
    # does not authenticate the runner or turn a local report into CI proof.
    receipt_ref = re.search(r'^last_receipt: "?([^"\n]+)"?\s*$', text, re.M)
    if receipt_ref and receipt_ref.group(1) != 'NONE':
        rel = Path(receipt_ref.group(1))
        receipt_path = root / rel
        try:
            resolved_root = root.resolve()
            resolved_receipt = receipt_path.resolve(strict=True)
            inside_root = resolved_receipt == resolved_root or resolved_root in resolved_receipt.parents
        except (OSError, RuntimeError):
            inside_root = False
        if rel.is_absolute() or '..' in rel.parts or not inside_root or not receipt_path.is_file():
            errs.append(f'RECEIPT_REF_INVALID: {receipt_ref.group(1)}')
        else:
            try:
                receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
                active = cursor_issue.group(1) if cursor_issue else None
                if receipt.get('schema_version') != 'paddock.receipt/1' or receipt.get('issue_id') not in records or receipt.get('issue_id') != active:
                    errs.append(f'RECEIPT_SCHEMA_INVALID: {receipt_ref.group(1)}')
            except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
                errs.append(f'RECEIPT_SCHEMA_INVALID: {receipt_ref.group(1)}')

    # Markdown links within project; reject escapes from repo root for local links.
    for name, doc in documents.items():
        for link in LINK_RE.findall(doc):
            if link.startswith(('https://','http://','#','mailto:')): continue
            target = link.split('#',1)[0].strip('<>')
            if not target: continue
            actual = (root / name).parent / target
            if '..' in Path(target).parts or not actual.exists():
                errs.append(f'BROKEN_LINK: {name} -> {target}')

    sha = hashlib.sha256(text.encode()).hexdigest()
    derived = root / "docs" / "issue-dependencies.generated.md"
    if check_generated and derived.exists() and derived.read_text(encoding="utf-8") != render(records, sha):
        errs.append("STALE_GENERATED_INDEX: run python3 scripts/lint_design.py --emit-summary")
    return sorted(set(errs)), records, sha


def render(records, source_sha):
    counts = collections.Counter(k.split('-')[1] for k in records)
    dep_count = sum(len(v[1]) for v in records.values())
    out = [
        '# PADDOCK — Generated Issue Dependency Index',
        '',
        '> AUTO-GENERATED. **DO NOT EDIT**. Source: `Issues.md`.',
        '> Generator: `python3 scripts/lint_design.py --emit-summary`.',
        '> 中目標への集約は表示専用。**依存DAGは小目標IDでのみ成立**。',
        f'> Issues.md SHA-256: `{source_sha}`',
        '',
        f'**小目標: {len(records)}件 / 依存辺: {dep_count}本 / 中目標: {len(counts)}領域。**',
        '',
        '| 中目標 | 小目標数 |', '|---|---:|'
    ]
    for k, n in sorted(counts.items()): out.append(f'| {k} | {n} |')
    out.extend(['', '| Issue | 状態 | `depends_on` |', '|---|---|---|'])
    for k,(state,deps) in sorted(records.items()):
        out.append(f'| `{k}` | `[{state}]` | '+(', '.join('`'+x+'`' for x in deps) if deps else 'none')+' |')
    return '\n'.join(out)+'\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--emit-summary', action='store_true')
    args = ap.parse_args()
    errs, records, digest = validate(args.root.resolve(), check_generated=not args.emit_summary)
    if errs:
        for err in errs: print('FAIL',err,file=sys.stderr)
        return 1
    if args.emit_summary:
        dest = args.root / 'docs' / 'issue-dependencies.generated.md'
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(render(records,digest),encoding='utf-8')
        print('GENERATED',dest)
    print('PASS',f'issues={len(records)}',f'edges={sum(len(v[1]) for v in records.values())}', f'issue_sha256={digest}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
