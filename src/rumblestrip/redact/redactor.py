from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

DENY_FILE_PATTERNS = (".env", ".env.*", "*.pem", "id_rsa*", "*.p12", "secrets.*", "credentials*")
TOKEN_PATTERNS: tuple[tuple[str, str], ...] = (
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ("aws_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("jwt", r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"),
    ("connection_string", r"\b(?:postgres(?:ql)?|mysql|mongodb)://[^\s:@/]+:[^\s@/]+@[^\s]+"),
)
KEY_VALUE = re.compile(r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\b\s*(?:=|:|=>)\s*)(['\"]?)([^\s,'\"}\]]+)")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{7,}\d)(?!\w)")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def should_redact_file(path: str | Path) -> bool:
    name = Path(path).name.lower()
    return name == ".env" or name.startswith(".env.") or name.endswith((".pem", ".p12")) or name.startswith("id_rsa") or name.startswith("secrets.") or name.startswith("credentials")


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) if value else 0.0


def redact(text: str, *, source_path: str | Path | None = None, extra_patterns: list[str] | None = None) -> str:
    if source_path and should_redact_file(source_path):
        return "[REDACTED FILE]"
    result = text
    for kind, pattern in TOKEN_PATTERNS:
        result = re.sub(pattern, f"[REDACTED:{kind}]", result, flags=re.IGNORECASE if kind == "private_key" else 0)
    result = KEY_VALUE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED:key_value]", result)
    result = EMAIL.sub("[REDACTED:email]", result)
    result = PHONE.sub("[REDACTED:phone]", result)
    result = IP.sub("[REDACTED:ip]", result)
    for candidate in set(re.findall(r"\b[A-Za-z0-9+/=_-]{20,}\b", result)):
        if not re.fullmatch(r"[0-9a-f]{40,64}", candidate, re.IGNORECASE) and entropy(candidate) >= 4.0:
            result = result.replace(candidate, "[REDACTED:high_entropy]")
    home = str(Path.home())
    if home and home != "/":
        result = result.replace(home, "~")
    for pattern in extra_patterns or []:
        try:
            result = re.sub(pattern, "[REDACTED:custom]", result)
        except re.error:
            continue
    return result
