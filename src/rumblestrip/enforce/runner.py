from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any

from rumblestrip.core.errors import IntegrityError, ToolError
from rumblestrip.core.git import changed_files
from rumblestrip.core.models import SEVERITY_ORDER, Violation
from rumblestrip.core.paths import load_config
from rumblestrip.engines.builtin import matches_glob, run_rule
from rumblestrip.store.database import StateDB
from rumblestrip.store.rules_repo import load_baseline, load_rules, verify_rule


def fingerprint(violation: Violation, occurrence: int) -> str:
    normalized = " ".join(violation.matched_text.split())
    payload = f"{violation.rule_id}\0{violation.file}\0{normalized}\0{occurrence}".encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def is_binary(path: Path) -> bool:
    try:
        return b"\0" in path.read_bytes()[:4096]
    except OSError:
        return True


def resolve_targets(root: Path, config: dict[str, Any], mode: str, files: list[str] | None, diff_base: str | None) -> tuple[list[tuple[Path, str]], list[str]]:
    requested = files if files is not None else changed_files(root, mode, diff_base)
    targets: list[tuple[Path, str]] = []
    skipped: list[str] = []
    ignore = config["paths"].get("ignore", [])
    maximum = int(config["enforce"].get("max_file_bytes", 1_000_000))
    for name in sorted(set(requested)):
        candidate = (root / name).resolve()
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:
            skipped.append(f"{name} (outside repository)")
            continue
        if not candidate.is_file():
            continue
        if relative.startswith(".rumblestrip/") or matches_glob(relative, ignore):
            continue
        if candidate.stat().st_size > maximum:
            skipped.append(f"{relative} (over size limit)")
            continue
        if is_binary(candidate):
            skipped.append(f"{relative} (binary)")
            continue
        targets.append((candidate, relative))
    return targets, skipped


def has_allow_comment(path: Path, rule_id: str) -> bool:
    marker = f"rumblestrip-allow[{rule_id}]:"
    try:
        return any(marker in line and line.split(marker, 1)[1].strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return False


def run_checks(root: Path, *, mode: str = "all", files: list[str] | None = None, diff_base: str | None = None, surface: str = "manual", record_ledger: bool = True, verify_integrity: bool = True) -> dict[str, Any]:
    root = root.resolve()
    start = perf_counter()
    config = load_config(root)
    targets, skipped = resolve_targets(root, config, mode, files, diff_base)
    loaded = load_rules(root)
    if verify_integrity:
        for rule, check, tests, _ in loaded:
            verify_rule(rule, check, tests)
    baselines = load_baseline(root)
    violations: list[Violation] = []
    errors: list[str] = []
    occurrence: dict[tuple[str, str, str], int] = {}
    for rule, check, _, _ in loaded:
        for path, relative in targets:
            try:
                findings = run_rule(rule, check, path, relative)
            except ToolError as exc:
                errors.append(str(exc))
                continue
            for finding in findings:
                key = (finding.rule_id, finding.file, " ".join(finding.matched_text.split()))
                occurrence[key] = occurrence.get(key, 0) + 1
                finding.fingerprint = fingerprint(finding, occurrence[key])
                finding.baseline = finding.fingerprint in baselines
                finding.suppressed = has_allow_comment(path, finding.rule_id)
                violations.append(finding)
    violations.sort(key=lambda item: (item.file, item.line, item.column, item.rule_id))
    visible = [item for item in violations if not item.baseline and not item.suppressed]
    if record_ledger and violations:
        try:
            db = StateDB()
            db.record_violations(root, violations, surface)
            db.close()
        except Exception:
            # Ledger failure must not affect enforcement.
            pass
    fail_on = config["enforce"].get("fail_on", "error")
    threshold = SEVERITY_ORDER.get(fail_on, 99)
    failure_count = sum(SEVERITY_ORDER.get(item.severity, 0) >= threshold for item in visible)
    return {
        "violations": violations, "visible": visible, "errors": errors, "files_checked": len(targets),
        "rules_checked": len(loaded), "skipped": skipped, "seconds": perf_counter() - start,
        "failure_count": failure_count, "fail_on": fail_on,
    }


def text_report(result: dict[str, Any], *, verbose: bool = False) -> str:
    lines = [f"Checked {result['files_checked']} files against {result['rules_checked']} rules in {result['seconds']:.2f}s"]
    for item in result["visible"]:
        lines.append(f"  {item.file}:{item.line}:{item.column}  {item.severity:<7} {item.rule_id}  {item.message}")
    if verbose:
        for item in result["violations"]:
            if item.baseline:
                lines.append(f"  {item.file}:{item.line}:{item.column}  baselined {item.rule_id}")
            elif item.suppressed:
                lines.append(f"  {item.file}:{item.line}:{item.column}  suppressed {item.rule_id}")
        lines.extend(f"Skipped {entry}" for entry in result["skipped"])
    lines.extend(f"tool error: {error}" for error in result["errors"])
    errors = sum(item.severity == "error" for item in result["visible"])
    warnings = sum(item.severity == "warning" for item in result["visible"])
    if result["failure_count"]:
        lines.append(f"{errors} errors, {warnings} warnings. Commit blocked (fail_on: {result['fail_on']}).")
    else:
        lines.append(f"{errors} errors, {warnings} warnings.")
    return "\n".join(lines)


def json_report(result: dict[str, Any]) -> str:
    data = {key: value for key, value in result.items() if key not in {"violations", "visible"}}
    data["violations"] = [item.to_dict() for item in result["visible"]]
    data["baselined"] = [item.to_dict() for item in result["violations"] if item.baseline]
    data["suppressed"] = [item.to_dict() for item in result["violations"] if item.suppressed]
    return json.dumps(data, indent=2, sort_keys=True)


def sarif_report(result: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for item in result["visible"]:
        rules.setdefault(item.rule_id, {"id": item.rule_id, "shortDescription": {"text": item.message}, "properties": {"rationale": item.rationale, "fix_hint": item.fix_hint}})
        findings.append({
            "ruleId": item.rule_id, "level": "warning" if item.severity == "warning" else "error",
            "message": {"text": item.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.file}, "region": {"startLine": item.line, "startColumn": item.column}}}],
            "partialFingerprints": {"rumblestrip/v1": item.fingerprint},
        })
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Rumblestrip", "rules": list(rules.values())}}, "results": findings}]}, indent=2)


def github_report(result: dict[str, Any]) -> str:
    return "\n".join(f"::{item.severity} file={item.file},line={item.line},col={item.column},title={item.rule_id}::{item.message}" for item in result["visible"])
