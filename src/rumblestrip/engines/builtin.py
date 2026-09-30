from __future__ import annotations

import ast
import fnmatch
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from rumblestrip.core.errors import ToolError
from rumblestrip.core.models import Rule, Violation


def matches_glob(path: str, patterns: Iterable[str]) -> bool:
    clean = path.replace("\\", "/")
    for pattern in patterns:
        pattern = pattern.replace("\\", "/")
        variants = {pattern}
        # pathlib/fnmatch differ on whether ** may match zero directories. Git
        # globs do, so check the zero-directory forms too.
        reduced = pattern
        while "**/" in reduced:
            reduced = reduced.replace("**/", "", 1)
            variants.add(reduced)
        for variant in variants:
            if fnmatch.fnmatch(clean, variant) or fnmatch.fnmatch("/" + clean, "*/" + variant):
                return True
    return False


def scope_matches(rule: Rule, relative: str) -> bool:
    scope = rule.scope or {}
    include = scope.get("include") or ["**/*"]
    exclude = scope.get("exclude") or []
    return matches_glob(relative, include) and not matches_glob(relative, exclude)


def make_violation(rule: Rule, relative: str, line: int, column: int, text: str) -> Violation:
    return Violation(rule.id, rule.severity, rule.statement, relative, max(1, line), max(1, column), text, rule.rationale, rule.fix_hint)


def run_text_regex(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    pattern = spec.get("pattern") or spec.get("regex")
    if not isinstance(pattern, str) or not pattern:
        raise ToolError(f"{rule.id}: text_regex requires a string pattern")
    flags = re.MULTILINE
    if spec.get("ignore_case"):
        flags |= re.IGNORECASE
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        matched = list(re.finditer(pattern, text, flags))
    except re.error as exc:
        raise ToolError(f"{rule.id}: invalid regex: {exc}") from exc
    return [make_violation(rule, relative, text.count("\n", 0, item.start()) + 1, item.start() - text.rfind("\n", 0, item.start()), item.group(0)) for item in matched]


def run_path_naming(rule: Rule, spec: dict[str, Any], _: Path, relative: str) -> list[Violation]:
    pattern = spec.get("pattern") or spec.get("regex")
    if not isinstance(pattern, str):
        raise ToolError(f"{rule.id}: path_naming requires pattern")
    target = relative if spec.get("target", "path") == "path" else Path(relative).name
    try:
        valid = re.fullmatch(pattern, target) is not None
    except re.error as exc:
        raise ToolError(f"{rule.id}: invalid path regex: {exc}") from exc
    return [] if valid else [make_violation(rule, relative, 1, 1, target)]


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def run_python_call_keyword(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    call = spec.get("call")
    keyword = spec.get("required_keyword")
    if not isinstance(call, str) or not isinstance(keyword, str):
        raise ToolError(f"{rule.id}: python_call_requires_keyword needs call and required_keyword")
    found: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and dotted_name(node.func) == call:
            if not any(item.arg == keyword for item in node.keywords):
                found.append(make_violation(rule, relative, node.lineno, node.col_offset + 1, ast.unparse(node)))
    return found


def run_dependency(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    forbidden = spec.get("forbidden") or spec.get("module")
    if not isinstance(forbidden, str):
        raise ToolError(f"{rule.id}: dependency requires forbidden module")
    text = path.read_text(encoding="utf-8", errors="replace")
    escaped = re.escape(forbidden)
    pattern = re.compile(
        rf"^\s*(?:from\s+{escaped}(?:\.|\s)|import\s+{escaped}(?:\.|\s|$))|"
        rf"(?:from\s+|require\(\s*)['\"]{escaped}(?:/|['\"])",
        re.MULTILINE,
    )
    findings = []
    for item in pattern.finditer(text):
        findings.append(make_violation(rule, relative, text.count("\n", 0, item.start()) + 1, 1, item.group(0).strip()))
    return findings


def run_required_companion(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    trigger = spec.get("when_regex")
    required = spec.get("required_regex")
    if not isinstance(trigger, str) or not isinstance(required, str):
        raise ToolError(f"{rule.id}: required_companion needs when_regex and required_regex")
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(trigger, text, re.MULTILINE)
    if not match or re.search(required, text, re.MULTILINE):
        return []
    return [make_violation(rule, relative, text.count("\n", 0, match.start()) + 1, 1, match.group(0))]


def run_ast_pattern(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    mode = spec.get("mode")
    if mode == "python_call_requires_keyword":
        return run_python_call_keyword(rule, spec, path, relative)
    # An ast-grep-shaped rule remains declarative. Materialise it as JSON (valid
    # YAML) in a temporary file so no generated instructions or code are run.
    binary = shutil.which("ast-grep") or shutil.which("sg")
    if not binary:
        raise ToolError(f"{rule.id}: ast-grep is required for this custom ast_pattern rule")
    payload = {key: value for key, value in spec.items() if key not in {"mode", "files", "ignores"}}
    if "rule" not in payload:
        raise ToolError(f"{rule.id}: ast_pattern needs mode=python_call_requires_keyword or an ast-grep rule")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", delete=False) as temp:
        json.dump(payload, temp)
        rule_path = temp.name
    try:
        completed = subprocess.run(
            [binary, "run", "--json=stream", "-r", rule_path, str(path)], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"{rule.id}: ast-grep failed: {exc}") from exc
    finally:
        Path(rule_path).unlink(missing_ok=True)
    if completed.returncode not in {0, 1}:
        raise ToolError(f"{rule.id}: ast-grep failed: {completed.stderr.strip()}")
    findings: list[Violation] = []
    for line in completed.stdout.splitlines():
        try:
            item = json.loads(line)
            position = item.get("range", {}).get("start", item.get("start", {}))
            source = item.get("text") or item.get("metaVariables", {}) or "ast-grep match"
            findings.append(make_violation(rule, relative, int(position.get("line", 0)) + 1, int(position.get("column", 0)) + 1, str(source)))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return findings


def run_rule(rule: Rule, spec: dict[str, Any], path: Path, relative: str) -> list[Violation]:
    if not scope_matches(rule, relative):
        return []
    if rule.kind == "text_regex":
        return run_text_regex(rule, spec, path, relative)
    if rule.kind == "path_naming":
        return run_path_naming(rule, spec, path, relative)
    if rule.kind == "dependency":
        return run_dependency(rule, spec, path, relative)
    if rule.kind == "required_companion":
        return run_required_companion(rule, spec, path, relative)
    if rule.kind == "ast_pattern":
        return run_ast_pattern(rule, spec, path, relative)
    return []
