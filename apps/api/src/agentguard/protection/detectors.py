"""Personal data and credential detection, and redaction.

Detectors validate what they can (Luhn for card numbers, ISO 7064 mod 97 for IBANs,
Verhoeff for Aadhaar, the entity character of a PAN, area and group rules for US SSNs), so
an order number that looks like a card is not reported. Each finding has a ``kind`` and the
``data class`` it belongs to: ``pii``, ``financial`` or ``credentials``.

Parameters and tool responses are JSON: :func:`scan_value` walks them, and also treats the
value of any key named like a credential (``password``, ``api_key``, ``token``...) as one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

MAX_SCAN_CHARS = 2_000_000
MAX_DEPTH = 20


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    data_class: str
    path: str
    start: int
    end: int

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "class": self.data_class, "path": self.path}


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(raw: str) -> bool:
    iban = raw.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34:
        return False
    moved = iban[4:] + iban[:4]
    try:
        number = int("".join(str(int(c, 36)) for c in moved))
    except ValueError:
        return False
    return number % 97 == 1


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return c == 0


def _ssn_ok(m: re.Match[str]) -> bool:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    return not (area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000")


# (kind, data class, pattern, validator on the match or None)
_DETECTORS: list[tuple[str, str, re.Pattern[str], Any]] = [
    (
        "private_key",
        "credentials",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]{0,8000}?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----"
        ),
        None,
    ),
    ("aws_access_key", "credentials", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"), None),
    (
        "aws_secret_key",
        "credentials",
        re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"=:\s]([A-Za-z0-9/+]{40})\b"),
        None,
    ),
    (
        "github_token",
        "credentials",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
        None,
    ),
    ("slack_token", "credentials", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), None),
    ("stripe_key", "credentials", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), None),
    ("anthropic_key", "credentials", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), None),
    ("openai_key", "credentials", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"), None),
    ("google_api_key", "credentials", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), None),
    (
        "agentguard_secret",
        "credentials",
        re.compile(r"\b(?:ags|agk)_[0-9a-f]{12}_[A-Za-z0-9_-]{20,}\b"),
        None,
    ),
    (
        "jwt",
        "credentials",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        None,
    ),
    (
        "password_assignment",
        "credentials",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\"]{8,})"
        ),
        None,
    ),
    (
        "card_number",
        "financial",
        re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        lambda m: (
            13 <= len(re.sub(r"\D", "", m.group(0))) <= 19
            and luhn_ok(re.sub(r"\D", "", m.group(0)))
        ),
    ),
    (
        "iban",
        "financial",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
        lambda m: iban_ok(m.group(0)),
    ),
    (
        "us_ssn",
        "pii",
        re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"),
        _ssn_ok,
    ),
    (
        "aadhaar",
        "pii",
        re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"),
        lambda m: verhoeff_ok(re.sub(r"\D", "", m.group(0))),
    ),
    ("pan", "pii", re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"), None),
    (
        "email",
        "pii",
        re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"),
        None,
    ),
    (
        "phone",
        "pii",
        re.compile(
            r"(?<![\w+])(?:\+\d{1,3}[ .-]?)(?:\(?\d{2,4}\)?[ .-]?){2,4}\d{2,4}(?!\d)|(?<!\d)\(\d{3}\) ?\d{3}-\d{4}(?!\d)|(?<![\d+])[6-9]\d{4}[ -]?\d{5}(?!\d)"
        ),
        lambda m: 8 <= len(re.sub(r"\D", "", m.group(0))) <= 15,
    ),
]

_CREDENTIAL_KEY = re.compile(
    r"(?i)^(?:password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|private[_-]?key|authorization|cookie|session)$"
)


def scan_text(text: str, path: str = "") -> list[Finding]:
    text = text[:MAX_SCAN_CHARS]
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for kind, data_class, pattern, validator in _DETECTORS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            if any(s < span[1] and span[0] < e for s, e in taken):
                continue  # a stronger detector already claimed this text
            if validator is not None and not validator(m):
                continue
            taken.append(span)
            findings.append(Finding(kind, data_class, path, span[0], span[1]))
    return findings


def scan_value(value: Any, path: str = "$", depth: int = 0) -> list[Finding]:
    """Findings in any JSON value: strings scanned, credential-named keys flagged."""
    if depth > MAX_DEPTH:
        return []
    if isinstance(value, str):
        return scan_text(value, path)
    if isinstance(value, dict):
        out: list[Finding] = []
        for key, item in value.items():
            child = f"{path}.{key}"
            if _CREDENTIAL_KEY.match(str(key)) and isinstance(item, str) and item:
                out.append(Finding("credential_field", "credentials", child, 0, len(item)))
                continue
            out.extend(scan_value(item, child, depth + 1))
        return out
    if isinstance(value, list):
        out = []
        for i, item in enumerate(value[:10_000]):
            out.extend(scan_value(item, f"{path}[{i}]", depth + 1))
        return out
    if isinstance(value, int) and not isinstance(value, bool):
        digits = str(abs(value))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return [Finding("card_number", "financial", path, 0, len(digits))]
    return []


def data_classes(findings: list[Finding]) -> list[str]:
    return sorted({f.data_class for f in findings})


def redact_text(text: str, findings: list[Finding] | None = None) -> str:
    findings = scan_text(text) if findings is None else findings
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        out = out[: f.start] + f"[REDACTED:{f.kind}]" + out[f.end :]
    return out


def redact_value(value: Any, fields: list[str] | None = None, depth: int = 0) -> Any:
    """A copy with personal data and credentials replaced, and named fields removed."""
    fields_lower = {f.lower() for f in fields or []}
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in fields_lower:
                out[key] = "[REDACTED]"
            elif _CREDENTIAL_KEY.match(str(key)) and isinstance(item, str) and item:
                out[key] = "[REDACTED:credential_field]"
            else:
                out[key] = redact_value(item, fields, depth + 1)
        return out
    if isinstance(value, list):
        return [redact_value(item, fields, depth + 1) for item in value[:10_000]]
    if isinstance(value, int) and not isinstance(value, bool):
        digits = str(abs(value))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return "[REDACTED:card_number]"
    return value


def contains_secret(text: str, secret: str) -> bool:
    """Whether a known secret value appears in text (exact, or with whitespace removed)."""
    if len(secret) < 6:
        return False
    return secret in text or secret in re.sub(r"\s+", "", text)
