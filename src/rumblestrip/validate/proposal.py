from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from rumblestrip.core.models import CHECK_KINDS, Rule
from rumblestrip.core.errors import ToolError
from rumblestrip.engines.builtin import run_rule


def _example_results(rule: Rule, check: dict[str, Any], tests: dict[str, Any]) -> tuple[bool, str]:
    language = str(tests.get("language") or "").lower()
    suffix = ".py" if "python" in language or rule.kind in {"dependency", "ast_pattern"} else ".txt"
    relative = "src/rumblestrip_example" + suffix
    invalid = list(tests.get("invalid") or [])
    valid = list(tests.get("valid") or [])
    if not invalid or not valid:
        return False, "Both invalid and valid examples are required for an enforceable rule"
    with tempfile.TemporaryDirectory(prefix="rumblestrip-validate-") as directory:
        path = Path(directory) / f"example{suffix}"
        for item in invalid:
            path.write_text(str(item.get("source") or ""), encoding="utf-8")
            if not run_rule(rule, check, path, relative):
                return False, f"Invalid example {item.get('name', 'unnamed')} was not flagged"
        for item in valid:
            path.write_text(str(item.get("source") or ""), encoding="utf-8")
            if run_rule(rule, check, path, relative):
                return False, f"Valid example {item.get('name', 'unnamed')} was flagged"
    return True, "Invalid examples are flagged and valid examples are clean"


def validate(root: Path, rule_data: dict[str, Any], check: dict[str, Any], tests: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, str]] = []
    try:
        rule = Rule.from_dict(rule_data)
        valid_id = bool(re.fullmatch(r"rs-(?=.{1,40}$)[a-z0-9]+(?:-[a-z0-9]+)*", rule.id))
        results.append({"step": "V0", "status": "ok" if valid_id and rule.kind in CHECK_KINDS else "fail", "message": "Rule schema and id are valid" if valid_id else "Rule id is invalid"})
        if rule.kind == "text_regex" and check:
            re.compile(str(check.get("pattern", "")))
        if any(".." in str(value) for value in [*rule.scope.get("include", []), *rule.scope.get("exclude", [])]):
            raise ValueError("scope may not traverse upward")
        results.append({"step": "V1", "status": "ok", "message": "Declarative check is safe to parse"})
        if rule.kind == "advisory":
            results.append({"step": "V2", "status": "n/a", "message": "Advisory rules are not mechanically testable"})
        else:
            examples_ok, message = _example_results(rule, check, tests)
            results.append({"step": "V2", "status": "ok" if examples_ok else "fail", "message": message})
            if examples_ok:
                again_ok, _ = _example_results(rule, check, tests)
                results.append({"step": "V4", "status": "ok" if again_ok else "fail", "message": "Example checks are deterministic across two runs"})
        return {"ok": all(entry["status"] != "fail" for entry in results), "steps": results}
    except (ValueError, re.error, ToolError) as exc:
        results.append({"step": "V1", "status": "fail", "message": str(exc)})
        return {"ok": False, "steps": results}
