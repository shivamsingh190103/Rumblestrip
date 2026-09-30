from __future__ import annotations

import subprocess
from pathlib import Path


def git(root: Path, *args: str) -> tuple[int, str]:
    completed = subprocess.run(["git", *args], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return completed.returncode, completed.stdout.strip()


def changed_files(root: Path, mode: str, diff_base: str | None = None) -> list[str]:
    if mode == "all":
        code, output = git(root, "ls-files", "--cached", "--others", "--exclude-standard")
    elif mode == "staged":
        code, output = git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    else:
        spec = diff_base or "HEAD"
        code, output = git(root, "diff", "--name-only", "--diff-filter=ACMR", spec)
    if code:
        return []
    return [line for line in output.splitlines() if line]


def git_email(root: Path) -> str:
    code, output = git(root, "config", "user.email")
    return output if code == 0 and output else "unknown"
