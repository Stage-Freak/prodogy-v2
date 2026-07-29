"""In-file suppression handling.

Teams need an escape hatch for context-dependent rules (a batch job may not
need probes). Prodogy honours inline comments:

    # prodogy-ok:K8S002            -> suppress rule K8S002 on the next line / this line
    # prodogy-ok:K8S002 reason...  -> optional trailing reason (kept as audit trail)
    # prodogy-ok:*                 -> suppress all rules on that line

A suppression applies to findings whose line matches the comment's line or the
immediately following non-comment line. Suppressed findings are *kept* in the
report (marked ``suppressed=True``) so there is always an audit trail — they
simply do not count toward the gate. This deliberately does not allow silently
deleting findings.
"""

from __future__ import annotations

import re

from prodogy.models import Finding

_SUPPRESS_RE = re.compile(r"#\s*prodogy-ok:([A-Za-z0-9_*]+)\s*(.*)$")


def parse_suppressions(lines: list[str]) -> dict[int, list[tuple[str, str]]]:
    """Return ``{line_number: [(rule_id, reason), ...]}`` (1-based lines).

    Each suppression is associated both with its own line and the next line, so
    developers can place the comment above or at the end of the offending line.
    """
    result: dict[int, list[tuple[str, str]]] = {}
    for idx, line in enumerate(lines, start=1):
        m = _SUPPRESS_RE.search(line)
        if not m:
            continue
        rule_id = m.group(1)
        reason = m.group(2).strip()
        for target in (idx, idx + 1):
            result.setdefault(target, []).append((rule_id, reason))
    return result


def apply_suppressions(
    findings: list[Finding],
    lines: list[str],
    protected_categories: list | None = None,
) -> None:
    """Mark findings suppressed in-place based on inline comments.

    Findings whose category is in ``protected_categories`` (e.g. CONFIDENTIAL)
    can never be suppressed. This enforces the "never auto-approve a secret"
    trust guarantee: an inline comment on a secret finding is recorded as an
    attempted suppression in the audit note, but the finding still counts toward
    the gate.
    """
    suppressions = parse_suppressions(lines)
    if not suppressions:
        return
    protected = set(protected_categories or [])
    for f in findings:
        if f.location.line is None:
            continue
        entries = suppressions.get(f.location.line)
        if not entries:
            continue
        for rule_id, reason in entries:
            if rule_id in (f.rule_id, "*"):
                if f.category in protected:
                    note = (
                        f"Suppression attempt IGNORED (prodogy-ok:{rule_id}): "
                        f"'{f.category.value}' findings are non-suppressible."
                    )
                    f.audit_note = (f.audit_note + " " + note).strip()
                    break
                f.suppressed = True
                note = f"Suppressed via inline comment (prodogy-ok:{rule_id})"
                if reason:
                    note += f" — {reason}"
                f.audit_note = (f.audit_note + " " + note).strip()
                break
