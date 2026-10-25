"""Static guard against infrastructure dependencies leaking into Go domains."""

from __future__ import annotations

import os
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_ROOT = REPO_ROOT / "internal"

# Match package path components, not arbitrary substrings (e.g. a domain package
# whose name happens to contain "net"). The network packages net and net/http
# are intentionally blocked in full; domain code should not perform I/O.
FORBIDDEN_IMPORTS = (
    "database", "net", "grpc", "pgx", "sqlx", "gorm.io", "entgo.io",
    "go.mongodb.org", "github.com/lib/pq", "github.com/jackc/",
    "github.com/go-sql-driver/", "github.com/openai/", "github.com/anthropics/",
    "github.com/google/generative-ai-go", "google.golang.org/genai",
    "github.com/sashabaranov/go-openai", "github.com/tmc/langchaingo",
    "github.com/ollama/", "github.com/aws/aws-sdk-go",
    "github.com/aws/aws-sdk-go-v2", "github.com/azure/",
)


def _tokens(source: str) -> list[tuple[str, str]]:
    """Tokenize Go comments, strings, identifiers and punctuation minimally."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(source):
        char = source[i]
        if char.isspace():
            i += 1
        elif source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end + 1
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = len(source) if end < 0 else end + 2
        elif char == '"':
            start = i
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(("string", source[start:i]))
        elif char == '`':
            start = i + 1
            end = source.find('`', start)
            if end < 0:
                end = len(source)
                i = end
            else:
                i = end + 1
            tokens.append(("raw", source[start:end]))
        elif char.isalpha() or char == "_":
            start = i
            i += 1
            while i < len(source) and (source[i].isalnum() or source[i] == "_"):
                i += 1
            tokens.append(("ident", source[start:i]))
        else:
            tokens.append((char, char))
            i += 1
    return tokens


def _imports(source: str) -> list[str]:
    """Return import paths, ignoring unrelated strings and import comments."""
    tokens = _tokens(source)
    paths: list[str] = []
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind != "ident" or value != "import":
            i += 1
            continue
        i += 1
        if i < len(tokens) and tokens[i] == ("(", "("):
            i += 1
            while i < len(tokens) and tokens[i] != (")", ")"):
                if tokens[i][0] == "ident" or tokens[i] == (".", "."):
                    i += 1
                if i < len(tokens) and tokens[i][0] in ("string", "raw"):
                    paths.append(_decode_import_path(*tokens[i]))
                    i += 1
                else:
                    i += 1
        else:
            if i < len(tokens) and (tokens[i][0] == "ident" or tokens[i][0] in ("_", ".")):
                i += 1
            if i < len(tokens) and tokens[i][0] in ("string", "raw"):
                paths.append(_decode_import_path(*tokens[i]))
                i += 1
    return paths


def _decode_import_path(kind: str, value: str) -> str:
    """Decode an import literal using Go's quoted-string escape rules."""
    if kind == "raw":
        return value
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError("malformed Go string literal")
    escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}
    result: list[str] = []
    i = 1
    end = len(value) - 1
    while i < end:
        char = value[i]
        if char != "\\":
            if char in "\n\r":
                raise ValueError("newline in Go string literal")
            result.append(char)
            i += 1
            continue
        i += 1
        if i >= end:
            raise ValueError("incomplete Go string escape")
        code = value[i]
        if code in escapes:
            result.append(escapes[code])
            i += 1
            continue
        if code in "01234567":
            digits, base, count = "01234567", 8, 3
        elif code == "x":
            digits, base, count = "0123456789abcdefABCDEF", 16, 2
        elif code == "u":
            digits, base, count = "0123456789abcdefABCDEF", 16, 4
        elif code == "U":
            digits, base, count = "0123456789abcdefABCDEF", 16, 8
        else:
            raise ValueError(f"unknown Go string escape: \\{code}")
        start = i + 1 if code in "xuU" else i
        stop = start + count
        fragment = value[start:stop]
        if len(fragment) != count or any(digit not in digits for digit in fragment):
            raise ValueError("invalid Go string escape")
        number = int(fragment, base)
        if code in "uU" and (number > 0x10FFFF or 0xD800 <= number <= 0xDFFF):
            raise ValueError("invalid Unicode code point in Go string escape")
        if code in "xuU":
            i = stop
        else:
            i = stop
        result.append(chr(number))
    return "".join(result)


def _is_forbidden(import_path: str) -> bool:
    components = import_path.split("/")
    for blocked in FORBIDDEN_IMPORTS:
        if blocked.endswith("/"):
            if import_path.startswith(blocked):
                return True
        elif blocked in {"database", "net", "grpc", "pgx", "sqlx"}:
            if blocked in (part.lower() for part in components):
                return True
        elif import_path == blocked or import_path.startswith(blocked + "/"):
            return True
    lowered = import_path.lower()
    return any(marker in components for marker in ("openai", "anthropic", "bedrock", "vertexai", "genai", "llm-provider")) or "langchain" in lowered


def domain_go_files(root: Path = DOMAIN_ROOT) -> list[Path]:
    """Find Go files below internal/**/domain without traversing symlinks."""
    root = root.resolve()
    if not root.is_dir():
        return []
    packages: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError:
            continue
        for path in entries:
            if path.is_symlink():
                continue
            if path.is_dir():
                if path.name == "domain":
                    packages.append(path)
                else:
                    pending.append(path)
    files: list[Path] = []
    for package in packages:
        pending = [package]
        while pending:
            directory = pending.pop()
            try:
                entries = sorted(directory.iterdir(), key=lambda path: path.name)
            except OSError:
                continue
            for path in entries:
                if path.is_symlink():
                    continue
                if path.is_dir():
                    pending.append(path)
                elif path.is_file() and path.suffix == ".go":
                    resolved = path.resolve()
                    if resolved == root or root in resolved.parents:
                        files.append(path)
    return sorted(files)


class DomainDependencyBoundaryTest(unittest.TestCase):
    def test_current_domain_imports_are_within_boundary(self) -> None:
        files = domain_go_files()
        self.assertTrue(files, "expected at least one internal/**/domain Go file")
        violations = [
            f"{path.relative_to(REPO_ROOT)}: {imp}"
            for path in files
            for imp in _imports(path.read_text(encoding="utf-8"))
            if _is_forbidden(imp)
        ]
        self.assertEqual([], violations, "forbidden domain imports:\n" + "\n".join(violations))

    def test_synthetic_import_forms_aliases_comments_and_path_delimiters(self) -> None:
        fixture = r'''package domain
import "fmt"
import net "net/http"
import (
    // a comment before an item
    _ "database/sql"
    . `github.com/jackc/pgx/v5)` // ) is part of the raw string
    alias "google.golang.org/grpc"
    /* comment inside group: import "net/rpc" */
    "errors" // trailing comment
    `example.org/path)with/paren`
)
var unrelated = "github.com/openai/fake"
// import "net/http"
'''
        expected = [
            "fmt", "net/http", "database/sql", "github.com/jackc/pgx/v5)",
            "google.golang.org/grpc", "errors", "example.org/path)with/paren",
        ]
        self.assertEqual(expected, _imports(fixture))
        self.assertEqual(
            ["net/http", "database/sql", "github.com/jackc/pgx/v5)", "google.golang.org/grpc"],
            [path for path in _imports(fixture) if _is_forbidden(path)],
        )
        self.assertFalse(any(_is_forbidden(path) for path in ("fmt", "errors", "encoding/json", "example.org/domain/value")))

    def test_go_string_escapes_decode_and_forbidden_paths_are_rejected(self) -> None:
        fixture = r'''import "net\x2fhttp"
import "net\u002fhttp"
import "net\U0000002fhttp"
import "net\057http"
import "net\thttp"'''
        decoded = _imports(fixture)
        self.assertEqual(["net/http"] * 4 + ["net\thttp"], decoded)
        self.assertEqual([True] * 4 + [False], [_is_forbidden(path) for path in decoded])
        self.assertEqual('a\nb\\c"d', _decode_import_path("string", r'"a\nb\\c\"d"'))

    def test_single_quoted_alias_and_depth_arbitrary_discovery(self) -> None:
        self.assertEqual(["fmt", "example.org/value)"], _imports('import f "fmt"\nimport . `example.org/value)`'))
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp) / "internal"
            target = root / "one" / "two" / "domain" / "nested.go"
            target.parent.mkdir(parents=True)
            target.write_text('package domain\nimport "fmt"\n', encoding="utf-8")
            self.assertEqual([target], domain_go_files(root))

    def test_symlinks_outside_internal_root_are_not_scanned_or_reported(self) -> None:
        with __import__("tempfile").TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "internal"
            package = root / "pkg" / "domain"
            package.mkdir(parents=True)
            inside = package / "inside.go"
            inside.write_text('package domain\nimport "fmt"\n', encoding="utf-8")
            outside = base / "outside.go"
            outside.write_text('package domain\nimport "net/http"\n', encoding="utf-8")
            links = [(package / "linked.go", outside), (root / "linked-domain", outside.parent / "external-domain")]
            (outside.parent / "external-domain").mkdir()
            (outside.parent / "external-domain" / "escape.go").write_text('package domain\nimport "net/http"\n', encoding="utf-8")
            try:
                for link, destination in links:
                    link.symlink_to(destination, target_is_directory=destination.is_dir())
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unsupported: {error}")
            files = domain_go_files(root)
            self.assertEqual([inside], files)
            scanned = [imp for path in files for imp in _imports(path.read_text(encoding="utf-8"))]
            self.assertNotIn("net/http", scanned)
            self.assertNotIn(outside, files)


if __name__ == "__main__":
    unittest.main()
