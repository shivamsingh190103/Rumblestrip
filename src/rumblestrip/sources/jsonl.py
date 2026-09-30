from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Event:
    role: str
    text: str
    raw_type: str = "unknown"
    path: str | None = None


def string_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        chunks = []
        for item in value:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                chunks.append(str(item.get("text") or item.get("content") or ""))
        return "\n".join(chunks)
    if isinstance(value, dict):
        return str(value.get("text") or value.get("content") or value.get("message") or "")
    return ""


def normalise(record: dict[str, Any]) -> Event | None:
    # Both vendors have changed formats. This deliberately recognizes broad field
    # shapes and leaves unknown records harmless rather than treating them as fatal.
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
    record_type = str(record.get("type") or payload.get("type") or "unknown")
    role = str(payload.get("role") or record.get("role") or "").lower()
    if role in {"user", "human"}:
        return Event("user", string_content(payload.get("content") or payload.get("message") or record.get("message")), record_type)
    if role in {"assistant", "agent"}:
        return Event("assistant", string_content(payload.get("content") or payload.get("message") or record.get("message")), record_type)
    lowered = record_type.lower()
    if "user" in lowered or "input" in lowered:
        return Event("user", string_content(payload.get("content") or payload.get("text") or record.get("message")), record_type)
    if "assistant" in lowered or "response" in lowered or "message" in lowered:
        return Event("assistant", string_content(payload.get("content") or payload.get("text") or record.get("message")), record_type)
    tool = str(payload.get("name") or payload.get("tool_name") or "")
    if tool in {"Edit", "Write", "MultiEdit", "apply_patch"} or "edit" in lowered:
        arguments = payload.get("input") or payload.get("arguments") or {}
        return Event("edit", string_content(arguments), record_type, str(arguments.get("file_path") or arguments.get("path") or "") if isinstance(arguments, dict) else None)
    return None


def read_new_events(path: Path, offset: int) -> tuple[list[Event], int, str | None]:
    events: list[Event] = []
    try:
        safe_offset = max(0, int(offset))
        with path.open("rb") as stream:
            stream.seek(safe_offset)
            while True:
                line = stream.readline()
                if not line:
                    break
                if len(line) > 5_000_000:
                    # Skip suspiciously large records instead of exhausting memory.
                    continue
                if not line.endswith(b"\n"):
                    return events, stream.tell() - len(line), None
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # Keep valid lines flowing. A malformed complete line is skipped.
                    continue
                if isinstance(record, dict):
                    event = normalise(record)
                    if event:
                        events.append(event)
            return events, stream.tell(), None
    except OSError as exc:
        return events, max(0, int(offset)), str(exc)


def discover(kind: str) -> Iterator[Path]:
    import os
    if kind == "claude":
        root = Path(os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude"))) / "projects"
    else:
        root = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "sessions"
    if root.exists():
        yield from root.rglob("*.jsonl")
