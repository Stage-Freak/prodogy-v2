"""Tests for the scanner end-to-end against the example fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from prodogy.models import Severity
from prodogy.scanner import Scanner

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="module")
def scanner() -> Scanner:
    return Scanner()


def _rule_ids(report) -> set[str]:
    return {f.rule_id for f in report.active_findings()}


def test_bad_dockerfile_flags_expected_rules(scanner):
    report = scanner.scan(EXAMPLES / "bad" / "Dockerfile")
    ids = _rule_ids(report)
    assert "DOCKER001" in ids  # latest tag
    assert "DOCKER002" in ids  # root user
    assert "DOCKER003" in ids  # no healthcheck
    assert "DOCKER004" in ids  # hardcoded secret
    assert "DOCKER005" in ids  # ADD vs COPY


def test_good_dockerfile_is_clean(scanner):
    report = scanner.scan(EXAMPLES / "good" / "Dockerfile")
    ids = _rule_ids(report)
    # None of the docker rules should fire on the good file.
    assert not any(i.startswith("DOCKER") for i in ids), ids


def test_bad_deployment_flags_expected_rules(scanner):
    report = scanner.scan(EXAMPLES / "bad" / "deployment.yaml")
    ids = _rule_ids(report)
    assert "K8S001" in ids  # missing limits
    assert "K8S002" in ids  # missing probes
    assert "K8S003" in ids  # privileged
    assert "K8S004" in ids  # missing app label
    assert "K8S005" in ids  # deprecated apiVersion


def test_good_deployment_is_clean(scanner):
    report = scanner.scan(EXAMPLES / "good" / "deployment.yaml")
    ids = _rule_ids(report)
    assert not any(i.startswith("K8S") for i in ids), ids


def test_env_secret_detection(scanner):
    report = scanner.scan(EXAMPLES / "bad" / ".env.prod")
    findings = [f for f in report.active_findings() if f.rule_id == "SECRET001"]
    assert findings, "expected secret findings in .env.prod"
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_findings_have_line_numbers(scanner):
    report = scanner.scan(EXAMPLES / "bad")
    for f in report.active_findings():
        # Every finding should point at a concrete line for PR annotations.
        assert f.location.line is not None, f"{f.rule_id} missing line"


def test_gate_blocks_on_bad_and_passes_on_good(scanner):
    bad = scanner.scan(EXAMPLES / "bad")
    good = scanner.scan(EXAMPLES / "good")
    assert bad.has_blocking(Severity.ERROR)
    assert not good.has_blocking(Severity.ERROR)


def test_summary_is_consistent(scanner):
    report = scanner.scan(EXAMPLES / "bad")
    total = sum(report.summary.by_severity.values())
    assert total == report.summary.total_findings
    assert report.summary.total_findings == len(report.active_findings())
