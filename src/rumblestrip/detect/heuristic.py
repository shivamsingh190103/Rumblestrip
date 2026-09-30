from __future__ import annotations

import hashlib
from typing import Any

from rumblestrip.redact.redactor import redact
from rumblestrip.sources.jsonl import Event


SIGNALS = ("don't", "do not", "always", "never", "instead", "wrong", "stop", "revert", "must", "we use", "no,")


def is_correction(text: str) -> bool:
    lowered = text.lower()
    return any(signal in lowered for signal in SIGNALS)


def correction_windows(events: list[Event]) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    previous: Event | None = None
    for index, event in enumerate(events):
        if event.role == "user" and is_correction(event.text) and previous is not None:
            after = next((item for item in events[index + 1:] if item.role in {"assistant", "edit"}), None)
            evidence = {
                "before": redact(previous.text, source_path=previous.path),
                "correction": redact(event.text),
                "after": redact(after.text, source_path=after.path) if after else "",
                "source_type": previous.raw_type,
            }
            encoded = "\n".join(str(evidence[key]) for key in ("before", "correction", "after"))
            windows.append({"hash": hashlib.sha256(encoded.encode()).hexdigest(), "evidence": evidence})
        if event.role in {"assistant", "edit"}:
            previous = event
    return windows
