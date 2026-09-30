from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from rumblestrip.core.paths import find_repo_root, rs_dir
from rumblestrip.enforce.runner import run_checks


def patch_files(command: str) -> list[str]:
    files: list[str] = []
    for line in command.splitlines():
        for prefix in ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "):
            if line.startswith(prefix):
                files.append(line[len(prefix):].strip())
    return files


def compact_feedback(result: dict[str, Any]) -> str:
    findings = result["visible"][:5]
    if not findings:
        return ""
    lines = [f"rumblestrip: {len(result['visible'])} rule violation(s)"]
    for item in findings:
        lines.append(f"  {item.rule_id} ({item.severity}), {item.file}:{item.line}: {item.message}")
        if item.rationale:
            lines.append(f"    Why: {item.rationale}")
        if item.fix_hint:
            lines.append(f"    Do instead: {item.fix_hint}")
    if len(result["visible"]) > len(findings):
        lines.append(f"  and {len(result['visible']) - len(findings)} more; run rumblestrip check")
    lines.append("Fix the code. Do not edit .rumblestrip/ or add allow-comments.")
    return "\n".join(lines)[:3500]


def handle_hook(agent: str, event: str) -> int:
    try:
        payload: dict[str, Any] = json.load(sys.stdin)
        root = find_repo_root(Path(payload.get("cwd") or Path.cwd()))
        if event == "session-end":
            queue = rs_dir(root) / ".cache" / "queue"
            queue.mkdir(parents=True, exist_ok=True)
            (queue / f"{payload.get('session_id', 'unknown')}.json").write_text(json.dumps({"kind": "harvest", "transcript_path": payload.get("transcript_path")}), encoding="utf-8")
            return 0
        if event == "session-start":
            summary = rs_dir(root) / "AGENT_RULES.md"
            if summary.exists():
                print(summary.read_text(encoding="utf-8")[:10000])
            return 0
        if event == "post-tool-use":
            command = str((payload.get("tool_input") or {}).get("command") or "")
            files = patch_files(command)
            if not files:
                file_path = (payload.get("tool_input") or {}).get("file_path")
                files = [str(file_path)] if file_path else []
            result = run_checks(root, files=files, mode="files", surface="hook")
        elif event == "stop":
            if payload.get("stop_hook_active"):
                return 0
            result = run_checks(root, mode="diff", diff_base="HEAD", surface="hook")
        else:
            return 0
        feedback = compact_feedback(result)
        if feedback:
            print(feedback, file=sys.stderr)
            return 2
    except Exception:
        # Hooks fail open; CI and direct checks still fail on tool/config errors.
        return 0
    return 0
