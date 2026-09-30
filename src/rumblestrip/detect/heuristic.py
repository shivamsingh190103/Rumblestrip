from __future__ import annotations

import hashlib
from typing import Any

from rumblestrip.redact.redactor import redact
from rumblestrip.sources.jsonl import Event

SIGNALS = ("don't", "do not", "always", "never", "instead", "wrong", "stop", "revert", "must", "we use", "no,")


def is_correction(text: str) -> bool:
    lowered = text.lower()
    return any(signal in lowered for signal in SIGNALS)


def confidence(correction: str, before: str, after: str) -> dict[str, Any]:
    lowered = correction.lower()
    matched = [signal for signal in SIGNALS if signal in lowered]
    score = 0.2
    if matched:
        score += 0.4
    if len(correction.strip()) >= 20:
        score += 0.2
    if before.strip() and after.strip() and before.strip() != after.strip():
        score += 0.2
    score = min(score, 1.0)
    return {"score": round(score, 2), "signals": matched}


def cluster_id(evidence: dict[str, Any]) -> str:
    normalized = " ".join(str(evidence.get("correction") or "").lower().split())
    if not normalized:
        normalized = "unknown-correction"
    return "sha256:" + hashlib.sha256(normalized.encode()).hexdigest()[:20]


def correction_windows(events: list[Event]) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    previous: Event | None = None
    for index, event in enumerate(events):
        if event.role == "user" and is_correction(event.text) and previous is not None:
            after = next((item for item in events[index + 1:] if item.role in {"assistant", "edit"}), None)
            before = redact(previous.text, source_path=previous.path)
            correction = redact(event.text)
            after_text = redact(after.text, source_path=after.path) if after else ""
            evidence = {
                "before": before,
                "correction": correction,
                "after": after_text,
                "source_type": previous.raw_type,
            }
            quality = confidence(correction, before, after_text)
            encoded = "\n".join(str(evidence[key]) for key in ("before", "correction", "after"))
            windows.append({
                "hash": hashlib.sha256(encoded.encode()).hexdigest(),
                "cluster_id": cluster_id(evidence),
                "signal": "heuristic",
                "quality": quality,
                "evidence": evidence,
            })
        if event.role in {"assistant", "edit"}:
            previous = event
    return windows
