"""Confidential / secret file detection.

This is the trust-sensitive part of Prodogy. Design constraints, taken directly
from the product safety requirements:

  * The tool NEVER auto-approves a confidential file. A feedback/allow entry may
    only *reduce* severity (error -> warning) and always leaves an audit note.
  * Detection is rule-based and explainable, not a black box.
  * The recommendation is constructive ("use a secrets manager"), not just an
    alarm.

Detection combines two signals:
  1. Filename patterns (``.env.prod``, ``*.pem``, ``credentials``...).
  2. Content patterns (``password=``, private key headers, high-entropy tokens
     assigned to secret-looking keys).
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity

# Env files are the primary target, but content scanning also helps for
# manifests/unknowns that slipped through.
_APPLIES = (
    FileKind.ENV_FILE,
    FileKind.UNKNOWN,
)

_SECRET_KEY_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z0-9_]*"
    r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)"
    r"[A-Za-z0-9_]*)\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE,
)

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

_PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "example", "placeholder", "xxx", "todo",
    "your_password_here", "yourpasswordhere", "secret", "password", "null",
    "none", "<redacted>", "redacted", "dummy",
}

# Names that strongly imply the file is an example/template, not a live secret.
_EXAMPLE_HINTS = ("example", "sample", "template", "dist", "default")

# High-confidence provider credential formats. A match here is almost certainly
# a real secret regardless of surrounding context, so it bypasses the entropy
# heuristic. Each maps to a human label.
_KNOWN_TOKEN_PATTERNS = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS temporary access key ID"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token"),
    (re.compile(r"\bsk-[0-9A-Za-z]{20,}\b"), "OpenAI-style API key"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "JWT"),
)


def detect_known_token(text: str) -> str | None:
    """Return a label if ``text`` contains a known provider credential format."""
    for pattern, label in _KNOWN_TOKEN_PATTERNS:
        if pattern.search(text):
            return label
    return None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _char_class_diversity(s: str) -> int:
    """Count how many character classes (lower/upper/digit/symbol) appear."""
    classes = 0
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def _looks_like_real_secret(value: str) -> bool:
    v = value.strip().strip("\"'")
    low = v.lower()
    if low in _PLACEHOLDER_VALUES:
        return False
    if v.startswith("$") or v.startswith("${") or "{{" in v:
        return False  # variable reference / template, not a literal
    # A recognized provider token format is a near-certain secret.
    if detect_known_token(v):
        return True
    # Otherwise require length + high entropy + character diversity to reduce
    # false positives on config values, UUIDs and plain identifiers.
    if len(v) >= 16 and _shannon_entropy(v) >= 3.5 and _char_class_diversity(v) >= 3:
        return True
    if len(v) >= 12 and _shannon_entropy(v) >= 4.0:
        return True
    return False


class ConfidentialFileRule(Rule):
    id = "SECRET001"
    title = "File appears to contain secrets"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _APPLIES
    rationale = (
        "This file looks like it holds live credentials. Committing secrets to a "
        "repository exposes them to everyone with read access and to anyone who "
        "clones the history — rotation becomes the only remedy, and it is easy to "
        "miss a copy."
    )
    remediation = (
        "Move these values to a secrets manager (Vault, AWS/GCP Secrets Manager, "
        "Kubernetes Secrets sourced from one) and reference them at runtime. Add "
        "the file to .gitignore and rotate anything already committed."
    )

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        text = artifact.raw
        if not text:
            return
        # Only the filename decides the 'example/template' hint — not parent
        # directories — so a real 'staging.env' isn't downgraded just because it
        # lives under an 'examples/' tree.
        filename_lower = artifact.path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        is_example = any(h in filename_lower for h in _EXAMPLE_HINTS)

        hits: list[tuple[int, str]] = []  # (line, message)

        for i, line in enumerate(artifact.lines, start=1):
            if _PRIVATE_KEY_RE.search(line):
                hits.append((i, "Private key material detected"))
                continue
            m = _SECRET_KEY_RE.match(line)
            if not m:
                continue
            key, _kind, value = m.group(1), m.group(2), m.group(3)
            if _looks_like_real_secret(value):
                hits.append((i, f"'{key}' appears to hold a real secret value"))

        if not hits:
            return

        # Trust rule: never silently downgrade. An 'example'-looking filename
        # reduces severity to WARNING but always records an audit note so a human
        # can review. It is never auto-approved away.
        for line, msg in hits:
            severity = self.severity
            audit = ""
            if is_example:
                severity = Severity.WARNING
                audit = (
                    "Severity reduced to warning: filename matches an "
                    "example/template pattern. Confirm this file holds no real "
                    "secret before ignoring."
                )
            f = self.finding(path=artifact.path, message=msg, line=line, severity=severity)
            f.audit_note = audit
            yield f


registry.register(ConfidentialFileRule())
