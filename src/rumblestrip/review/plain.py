from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rumblestrip.core.errors import ConfigError
from rumblestrip.store.database import StateDB
from rumblestrip.store.rules_repo import write_rule_bundle


def queue(root: Path) -> list[dict[str, Any]]:
    db = StateDB()
    rows = db.proposals(root)
    db.close()
    return [{"id": row["id"], "candidate_id": row["candidate_id"], "rule": json.loads(row["rule_json"]), "validation": json.loads(row["validation_json"]), "evidence": json.loads(row["evidence_json"])} for row in rows]


def approve(root: Path, proposal_id: int, *, baseline: bool = False) -> str:
    db = StateDB()
    row = db.proposal(proposal_id)
    if not row or row["state"] != "pending":
        db.close()
        raise ConfigError(f"pending proposal {proposal_id} was not found")
    rule = json.loads(row["rule_json"])
    artifacts = json.loads(row["artifacts_json"])
    validation = json.loads(row["validation_json"])
    if not validation.get("ok"):
        db.close()
        raise ConfigError(f"proposal {proposal_id} has failed validation and cannot be approved")
    write_rule_bundle(root, rule, artifacts.get("check", {}), artifacts.get("tests", {}))
    db.decide_proposal(proposal_id, "approved", "approved with baseline" if baseline else "approved")
    db.close()
    return rule["id"]


def decide(proposal_id: int, state: str, reason: str) -> None:
    db = StateDB()
    db.decide_proposal(proposal_id, state, reason)
    db.close()
