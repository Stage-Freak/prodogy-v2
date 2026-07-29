"""Unit tests for suppression, classification, secret heuristics and renderers."""

from __future__ import annotations

from pathlib import Path

from prodogy.discovery import classify
from prodogy.models import (
    Category,
    Finding,
    Location,
    Report,
    ScannedFile,
    Severity,
)
from prodogy.renderers import render_markdown, render_sarif
from prodogy.rules.secret_rules import _looks_like_real_secret
from prodogy.suppression import apply_suppressions, parse_suppressions


def test_classify_by_name():
    assert classify(Path("Dockerfile"), read_content=False).value == "dockerfile"
    assert classify(Path(".env.prod"), read_content=False).value == "env_file"
    assert classify(Path("values.yaml"), read_content=False).value == "helm_values"


def test_suppression_marks_finding():
    lines = [
        "containers:",
        "  - name: web  # prodogy-ok:K8S002 batch job, no probes needed",
    ]
    f = Finding(
        rule_id="K8S002",
        title="probe",
        severity=Severity.WARNING,
        category=Category.DEPLOY_RISK,
        location=Location(path="d.yaml", line=2),
        message="missing probe",
    )
    apply_suppressions([f], lines)
    assert f.suppressed
    assert "batch job" in f.audit_note


def test_suppression_wildcard_and_next_line():
    lines = ["# prodogy-ok:*", "image: nginx:latest"]
    f = Finding(
        rule_id="DOCKER001",
        title="tag",
        severity=Severity.ERROR,
        category=Category.DEPLOY_RISK,
        location=Location(path="D", line=2),
        message="latest",
    )
    apply_suppressions([f], lines)
    assert f.suppressed


def test_parse_suppressions_associates_two_lines():
    supp = parse_suppressions(["# prodogy-ok:K8S001"])
    assert 1 in supp and 2 in supp


def test_secret_heuristic_ignores_placeholders():
    assert not _looks_like_real_secret("changeme")
    assert not _looks_like_real_secret("${DB_PASSWORD}")
    assert not _looks_like_real_secret("")
    assert _looks_like_real_secret("sk_live_9f8a7b6c5d4e3f2a1b0c")


def _sample_report() -> Report:
    r = Report(root=".")
    r.files.append(ScannedFile(path="Dockerfile", kind="dockerfile"))
    r.findings.append(Finding(
        rule_id="DOCKER001",
        title="latest tag",
        severity=Severity.ERROR,
        category=Category.DEPLOY_RISK,
        location=Location(path="Dockerfile", line=1),
        message="uses latest",
        rationale="why it matters",
        remediation="pin it",
    ))
    r.recompute_summary()
    return r


def test_markdown_render_contains_finding():
    md = render_markdown(_sample_report())
    assert "DOCKER001" in md
    assert "Dockerfile:1" in md


def test_sarif_is_valid_structure():
    import json

    sarif = json.loads(render_sarif(_sample_report()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Prodogy"
    assert run["results"][0]["ruleId"] == "DOCKER001"
    assert run["results"][0]["level"] == "error"
