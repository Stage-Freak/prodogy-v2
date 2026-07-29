"""Tests for robustness/edge cases and the newer rule modules (CI, CORE)."""

from __future__ import annotations

from pathlib import Path

import pytest

from prodogy.models import FileKind
from prodogy.parsers import load_artifact, parse_dockerfile, parse_yaml_documents
from prodogy.scanner import Scanner

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="module")
def scanner() -> Scanner:
    return Scanner()


def _ids(report):
    return {f.rule_id for f in report.active_findings()}


def test_unparseable_manifest_is_flagged(tmp_path, scanner):
    p = tmp_path / "broken.yaml"
    p.write_text("apiVersion: apps/v1\nkind: Deployment\nmeta: [unclosed\n")
    report = scanner.scan(p)
    assert "CORE001" in _ids(report)
    assert report.has_blocking()


def test_empty_directory_scans_clean(tmp_path, scanner):
    report = scanner.scan(tmp_path)
    assert report.summary.total_findings == 0
    assert not report.has_blocking()


def test_multidoc_yaml_all_docs_checked(tmp_path, scanner):
    content = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: c1\n          image: nginx:latest\n"
        "---\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: b\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: c2\n          image: redis:latest\n"
    )
    p = tmp_path / "multi.yaml"
    p.write_text(content)
    report = scanner.scan(p)
    # Both deployments should produce missing-limits findings (one per container).
    k8s001 = [f for f in report.active_findings() if f.rule_id == "K8S001"]
    assert len(k8s001) == 2


def test_ci_unpinned_action_and_secret(scanner):
    report = scanner.scan(EXAMPLES / "bad" / ".github" / "workflows" / "ci.yml")
    ids = _ids(report)
    assert "CI001" in ids
    assert "CI002" in ids


def test_dockerfile_continuation_parsing():
    text = "RUN apt-get update \\\n    && apt-get install -y curl \\\n    && rm -rf /var/lib/apt/lists/*\n"
    insts = parse_dockerfile(text)
    assert len(insts) == 1
    assert insts[0].cmd == "RUN"
    assert "curl" in insts[0].value


def test_yaml_parse_error_returned():
    docs, err = parse_yaml_documents("a: [1, 2\n")
    assert docs == []
    assert err


def test_multistage_dockerfile_user_reset(tmp_path, scanner):
    # A USER in an early stage must not satisfy a later stage that resets to root.
    content = (
        "FROM base AS builder\n"
        "USER app\n"
        "RUN build\n"
        "FROM runtime\n"
        "COPY --from=builder /app /app\n"
    )
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    report = scanner.scan(p)
    assert "DOCKER002" in _ids(report)  # final stage has no USER


def test_sha_pinned_image_not_flagged(tmp_path, scanner):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM python@sha256:" + "a" * 64 + "\nUSER app\n")
    report = scanner.scan(p)
    assert "DOCKER001" not in _ids(report)


def test_unknown_file_skipped(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello")
    art = load_artifact(p, FileKind.UNKNOWN)
    assert art.data is None


def test_relative_paths_in_findings(scanner):
    report = scanner.scan(EXAMPLES / "bad")
    for f in report.active_findings():
        assert not f.location.path.startswith("/"), f.location.path
