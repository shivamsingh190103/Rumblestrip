from __future__ import annotations

import re
from hashlib import sha256
from typing import Any


def slug(text: str) -> str:
    words = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-").split("-")
    return "-".join(words[:7]) or "correction"


def title_case(text: str) -> str:
    return text[:1].upper() + text[1:] if text else "Project correction"


def synthesize(evidence: dict[str, Any], candidate_id: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    correction = str(evidence.get("correction") or "").strip()
    lowered = correction.lower()
    rule_id = f"rs-{slug(correction)}"
    statement = correction.rstrip(".") + "."
    kind = "advisory"
    check: dict[str, Any] = {}
    tests: dict[str, Any] = {"schema_version": 1, "language": "", "invalid": [], "valid": []}
    scope = {"include": ["**/*"], "exclude": ["tests/**", "vendor/**"]}
    if "timeout" in lowered and ("requests" in lowered or "http" in lowered or "outbound" in lowered or "always" in lowered):
        rule_id = "rs-http-timeout"
        statement = "Every outbound requests call must pass timeout=."
        kind = "ast_pattern"
        scope = {"include": ["**/*.py"], "exclude": ["tests/**"]}
        check = {"mode": "python_call_requires_keyword", "call": "requests.get", "required_keyword": "timeout"}
        tests = {"schema_version": 1, "language": "Python", "invalid": [{"name": "missing timeout", "source": "requests.get(url)"}], "valid": [{"name": "with timeout", "source": "requests.get(url, timeout=10)"}]}
    else:
        import_match = re.search(r"(?:do not|don't|never)\s+import\s+(?:from\s+)?([A-Za-z_][\w.]*)", lowered)
        if import_match:
            forbidden = import_match.group(1)
            rule_id = f"rs-no-import-{slug(forbidden)}"
            statement = f"Do not import from {forbidden}."
            kind = "dependency"
            check = {"forbidden": forbidden}
            tests = {"schema_version": 1, "language": "Python", "invalid": [{"name": "forbidden import", "source": f"from {forbidden} import thing"}], "valid": [{"name": "allowed import", "source": "from app.core import thing"}]}
        else:
            avoid = re.search(r"(?:do not|don't|never|avoid)\s+(?:use\s+)?[`'\"]?([A-Za-z_][\w.-]{2,})", lowered)
            if avoid:
                forbidden = avoid.group(1)
                rule_id = f"rs-no-{slug(forbidden)}"
                statement = f"Do not use {forbidden}."
                kind = "text_regex"
                check = {"pattern": rf"\b{re.escape(forbidden)}\b"}
    # Candidate ids make unrelated but similarly worded proposals non-colliding.
    if kind == "advisory":
        rule_id = f"rs-{slug(correction)}-{candidate_id}"
    rule = {
        "schema_version": 1, "id": rule_id[:43], "title": title_case(statement.rstrip(".")), "status": "active",
        "kind": kind, "severity": "error" if kind != "advisory" else "info", "statement": statement,
        "rationale": correction, "rejected_alternatives": [], "fix_hint": "Follow the approved project convention.",
        "scope": scope, "provenance": {"source": "local-session", "session_ref": "sha256:" + sha256(correction.encode()).hexdigest(), "captured_at": "pending approval"},
        "check": {"engine": "builtin", "file": "check.yml"} if kind != "advisory" else {},
    }
    return rule, check, tests
