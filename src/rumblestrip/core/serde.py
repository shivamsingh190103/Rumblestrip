"""Safe serialization helpers.

Rumblestrip writes JSON-shaped YAML. JSON is valid YAML, which means rule bundles
stay readable even in minimal environments. PyYAML is used when installed to read
ordinary YAML authored by people.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ConfigError


def load_data(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ConfigError(
                f"{path} is YAML rather than JSON-shaped YAML; install PyYAML to read it"
            ) from exc
        try:
            return yaml.safe_load(raw)
        except Exception as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc


def dump_data(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def canonical_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
