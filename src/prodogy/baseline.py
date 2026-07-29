"""Baseline support: fail only on *new* findings.

Adopting a linter on an existing ("brownfield") repo is painful when the first
run reports hundreds of pre-existing issues. A baseline records the fingerprints
of findings that already existed and are accepted for now, so subsequent scans
can gate only on findings that are *new* relative to the baseline.

This is the single most effective alert-fatigue mitigation: teams get value on
day one without a wall of red, and the gate still catches regressions.

Baseline file format (JSON):

    {
      "schema_version": "1.0",
      "created_at": "...",
      "fingerprints": ["ab12...", "cd34...", ...]
    }

A finding's ``fingerprint`` is stable across runs (rule + path + line + message),
so moving unrelated code does not silently re-accept a different issue.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from prodogy.models import Report

BASELINE_SCHEMA_VERSION = "1.0"


def write_baseline(report: Report, path: Path) -> int:
    """Write the fingerprints of all active findings to a baseline file.

    Returns the number of fingerprints recorded.
    """
    fingerprints = sorted({f.fingerprint for f in report.active_findings()})
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(payload, indent=2))
    return len(fingerprints)


def load_baseline(path: Path) -> set[str]:
    """Load the set of baselined fingerprints. Missing file -> empty set."""
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    return set(data.get("fingerprints", []))


def apply_baseline(report: Report, baselined: set[str]) -> int:
    """Mark findings present in the baseline as suppressed.

    Returns the number of findings suppressed by the baseline. Suppressed
    findings remain in the report (audit trail) but do not count toward the gate.
    Confidential findings are never baselined away — new secrets must always
    surface, consistent with the non-suppressible trust guarantee.
    """
    from prodogy.models import Category

    suppressed = 0
    for f in report.findings:
        if f.suppressed:
            continue
        if f.category is Category.CONFIDENTIAL:
            continue
        if f.fingerprint in baselined:
            f.suppressed = True
            f.audit_note = (f.audit_note + " Baselined (pre-existing).").strip()
            suppressed += 1
    report.recompute_summary()
    return suppressed
