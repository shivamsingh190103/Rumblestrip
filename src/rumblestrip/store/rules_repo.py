from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rumblestrip.core.errors import ConfigError, IntegrityError
from rumblestrip.core.git import git_email
from rumblestrip.core.models import CHECK_KINDS, Rule
from rumblestrip.core.paths import rs_dir
from rumblestrip.core.serde import canonical_bytes, dump_data, load_data

# `rs-` plus no more than 40 lowercase kebab-case characters.
RULE_ID = re.compile(r"^rs-(?=.{1,40}$)[a-z0-9]+(?:-[a-z0-9]+)*$")


def rule_dir(root: Path, rule_id: str) -> Path:
    return rs_dir(root) / "rules" / rule_id


def load_rules(root: Path, *, include_inactive: bool = False) -> list[tuple[Rule, dict[str, Any], dict[str, Any], Path]]:
    directory = rs_dir(root) / "rules"
    if not directory.exists():
        return []
    rules: list[tuple[Rule, dict[str, Any], dict[str, Any], Path]] = []
    for child in sorted(directory.iterdir()):
        if not child.is_dir() or not (child / "rule.yml").exists():
            continue
        try:
            raw = load_data(child / "rule.yml")
            rule = Rule.from_dict(raw)
            if rule.id != child.name:
                raise ConfigError(f"rule directory {child.name} does not match id {rule.id}")
            if rule.kind not in CHECK_KINDS or rule.severity not in {"info", "warning", "error"}:
                raise ConfigError(f"invalid kind or severity for {rule.id}")
            check = load_data(child / "check.yml") if (child / "check.yml").exists() else {}
            tests = load_data(child / "tests.yml") if (child / "tests.yml").exists() else {}
            if include_inactive or rule.status == "active":
                rules.append((rule, check or {}, tests or {}, child))
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"invalid rule in {child}: {exc}") from exc
    return rules


def content_hash(rule: Rule, check: dict[str, Any], tests: dict[str, Any]) -> str:
    payload = {
        "rule": rule.to_dict(include_approval=False),
        "check": check,
        "tests": tests,
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def verify_rule(rule: Rule, check: dict[str, Any], tests: dict[str, Any]) -> None:
    if rule.status != "active":
        return
    expected = rule.approval.get("content_hash")
    if not expected:
        raise IntegrityError(f"{rule.id} has no approval integrity hash")
    actual = content_hash(rule, check, tests)
    if actual != expected:
        raise IntegrityError(f"{rule.id} integrity hash does not match; run rumblestrip rules approve {rule.id} after review")


def write_rule_bundle(root: Path, rule_data: dict[str, Any], check: dict[str, Any], tests: dict[str, Any], *, approved_by: str | None = None) -> Rule:
    rule = Rule.from_dict(rule_data)
    if not RULE_ID.fullmatch(rule.id):
        raise ConfigError("rule id must be rs- followed by lowercase kebab-case (at most 40 segments)")
    if rule.kind not in CHECK_KINDS:
        raise ConfigError(f"unsupported rule kind: {rule.kind}")
    directory = rule_dir(root, rule.id)
    if directory.exists():
        raise ConfigError(f"rule {rule.id} already exists")
    directory.mkdir(parents=True)
    rule.approval = {
        "approved_by": approved_by or git_email(root),
        "approved_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    rule.approval["content_hash"] = content_hash(rule, check, tests)
    dump_data(directory / "rule.yml", rule.to_dict())
    if rule.kind != "advisory":
        dump_data(directory / "check.yml", check)
        dump_data(directory / "tests.yml", tests)
    return rule


def reapprove(root: Path, rule_id: str) -> Rule:
    directory = rule_dir(root, rule_id)
    if not directory.exists():
        raise ConfigError(f"unknown rule: {rule_id}")
    rule = Rule.from_dict(load_data(directory / "rule.yml"))
    check = load_data(directory / "check.yml") if (directory / "check.yml").exists() else {}
    tests = load_data(directory / "tests.yml") if (directory / "tests.yml").exists() else {}
    rule.approval["approved_by"] = git_email(root)
    rule.approval["approved_at"] = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rule.approval["content_hash"] = content_hash(rule, check, tests)
    dump_data(directory / "rule.yml", rule.to_dict())
    return rule


def retire(root: Path, rule_id: str) -> Rule:
    directory = rule_dir(root, rule_id)
    rule = Rule.from_dict(load_data(directory / "rule.yml"))
    check = load_data(directory / "check.yml") if (directory / "check.yml").exists() else {}
    tests = load_data(directory / "tests.yml") if (directory / "tests.yml").exists() else {}
    rule.status = "retired"
    rule.approval["content_hash"] = content_hash(rule, check, tests)
    dump_data(directory / "rule.yml", rule.to_dict())
    return rule


def load_baseline(root: Path) -> set[str]:
    path = rs_dir(root) / "baseline.json"
    if not path.exists():
        return set()
    data = load_data(path)
    return set(data.get("fingerprints") or [])


def save_baseline(root: Path, fingerprints: set[str]) -> None:
    dump_data(rs_dir(root) / "baseline.json", {"schema_version": 1, "fingerprints": sorted(fingerprints)})
