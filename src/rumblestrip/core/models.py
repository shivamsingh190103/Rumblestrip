from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
CHECK_KINDS = {"ast_pattern", "path_naming", "text_regex", "dependency", "required_companion", "advisory"}


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    status: str
    kind: str
    severity: str
    statement: str
    rationale: str = ""
    rejected_alternatives: list[dict[str, str]] = field(default_factory=list)
    fix_hint: str = ""
    scope: dict[str, list[str]] = field(default_factory=lambda: {"include": ["**/*"], "exclude": []})
    provenance: dict[str, Any] = field(default_factory=dict)
    check: dict[str, Any] = field(default_factory=dict)
    approval: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        required = ("id", "title", "status", "kind", "severity", "statement")
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise ValueError(f"missing rule fields: {', '.join(missing)}")
        return cls(
            id=str(data["id"]), title=str(data["title"]), status=str(data["status"]),
            kind=str(data["kind"]), severity=str(data["severity"]), statement=str(data["statement"]),
            rationale=str(data.get("rationale", "")),
            rejected_alternatives=list(data.get("rejected_alternatives") or []),
            fix_hint=str(data.get("fix_hint", "")), scope=dict(data.get("scope") or {}),
            provenance=dict(data.get("provenance") or {}), check=dict(data.get("check") or {}),
            approval=dict(data.get("approval") or {}), schema_version=int(data.get("schema_version", 1)),
        )

    def to_dict(self, *, include_approval: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version, "id": self.id, "title": self.title,
            "status": self.status, "kind": self.kind, "severity": self.severity,
            "statement": self.statement, "rationale": self.rationale,
            "rejected_alternatives": self.rejected_alternatives, "fix_hint": self.fix_hint,
            "scope": self.scope, "provenance": self.provenance, "check": self.check,
        }
        if include_approval and self.approval:
            data["approval"] = self.approval
        return data


@dataclass(slots=True)
class Violation:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    matched_text: str
    rationale: str = ""
    fix_hint: str = ""
    baseline: bool = False
    suppressed: bool = False
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "severity": self.severity, "message": self.message,
            "file": self.file, "line": self.line, "column": self.column,
            "matched_text": self.matched_text, "rationale": self.rationale,
            "fix_hint": self.fix_hint, "baseline": self.baseline, "suppressed": self.suppressed,
            "fingerprint": self.fingerprint,
        }
