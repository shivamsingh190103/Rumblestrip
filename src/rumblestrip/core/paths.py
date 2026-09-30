from __future__ import annotations

import os
from pathlib import Path

from .errors import ConfigError
from .serde import dump_data, load_data


DEFAULT_CONFIG = {
    "schema_version": 1,
    "languages": ["python", "typescript", "javascript"],
    "enforce": {
        "fail_on": "error", "on_tool_error": "warn", "max_new_allows_per_pr": 0,
        "timeout_seconds": {"precommit": 5, "hook": 3, "ci": 120}, "max_file_bytes": 1_000_000,
    },
    "paths": {"ignore": ["vendor/**", "**/generated/**", "dist/**", "node_modules/**", "**/*.min.js"]},
    "agents": {"claude_code": {"enabled": True, "scope": "project"}, "codex": {"enabled": True, "scope": "project"}},
    "agent_summary": {"enabled": False, "max_rules": 12, "max_tokens": 800},
    "hooks": {"bash_changes": False},
}


def find_repo_root(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return here


def rs_dir(root: Path) -> Path:
    return root / ".rumblestrip"


def config_path(root: Path) -> Path:
    return rs_dir(root) / "config.yml"


def load_config(root: Path, override: Path | None = None) -> dict:
    path = override or config_path(root)
    if not path.exists():
        raise ConfigError(f"Rumblestrip is not initialized in {root}. Run: rumblestrip init")
    data = load_data(path)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ConfigError(f"unsupported config schema in {path}")
    return deep_merge(DEFAULT_CONFIG, data)


def init_repository(root: Path) -> Path:
    directory = rs_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "rules").mkdir(exist_ok=True)
    (directory / ".cache").mkdir(exist_ok=True)
    dump_data(config_path(root), DEFAULT_CONFIG)
    dump_data(directory / "baseline.json", {"schema_version": 1, "fingerprints": []})
    (directory / ".gitignore").write_text(".cache/\n", encoding="utf-8")
    return directory


def state_home() -> Path:
    configured = os.environ.get("RUMBLESTRIP_HOME")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "rumblestrip"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / "rumblestrip"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "rumblestrip"


def deep_merge(default: dict, override: dict) -> dict:
    result = dict(default)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result
