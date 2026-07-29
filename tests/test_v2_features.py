"""Tests for v0.2 features: config, protected suppression, new rules,
compliance renderer, secret formats, and web security controls."""

from __future__ import annotations

from pathlib import Path

import pytest

from prodogy.config import Config, ConfigError, load_config, resolve_config
from prodogy.models import Category, Severity
from prodogy.renderers import render_compliance
from prodogy.rules.secret_rules import detect_known_token
from prodogy.scanner import Scanner

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="module")
def scanner() -> Scanner:
    return Scanner()


def _ids(report):
    return {f.rule_id for f in report.active_findings()}


# ---- Config -----------------------------------------------------------------

def test_config_disables_rule(tmp_path):
    (tmp_path / ".prodogy.yml").write_text("disabled_rules: [DOCKER001]\n")
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:latest\n")
    report = Scanner().scan(tmp_path)
    assert "DOCKER001" not in _ids(report)


def test_config_severity_override(tmp_path):
    (tmp_path / ".prodogy.yml").write_text("severity_overrides:\n  DOCKER001: info\n")
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER app\n")
    report = Scanner().scan(tmp_path)
    d1 = [f for f in report.active_findings() if f.rule_id == "DOCKER001"]
    assert d1 and d1[0].severity is Severity.INFO


def test_config_exclude_path(tmp_path):
    (tmp_path / ".prodogy.yml").write_text('exclude: ["**/skip/**"]\n')
    skip = tmp_path / "skip"
    skip.mkdir()
    (skip / "Dockerfile").write_text("FROM python:latest\n")
    report = Scanner().scan(tmp_path)
    assert report.summary.total_findings == 0


def test_config_rejects_unknown_keys(tmp_path):
    cfg = tmp_path / ".prodogy.yml"
    cfg.write_text("bogus_key: 1\n")
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_config_absent_returns_defaults(tmp_path):
    cfg = resolve_config(tmp_path)
    assert isinstance(cfg, Config)
    assert cfg.category_is_protected(Category.CONFIDENTIAL)


# ---- Protected suppression --------------------------------------------------

def test_confidential_finding_cannot_be_suppressed(tmp_path):
    env = tmp_path / ".env.prod"
    env.write_text("API_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789  # prodogy-ok:SECRET001\n")
    report = Scanner().scan(tmp_path)
    secrets_found = [f for f in report.findings if f.rule_id == "SECRET001"]
    assert secrets_found
    # Must remain active (not suppressed) despite the inline comment.
    assert all(not f.suppressed for f in secrets_found)
    assert any("IGNORED" in f.audit_note for f in secrets_found)


def test_non_confidential_finding_still_suppressible(tmp_path):
    df = tmp_path / "Dockerfile"
    # Suppression comment on its own line applies to the following instruction.
    df.write_text("# prodogy-ok:DOCKER001\nFROM python:latest\nUSER app\n")
    report = Scanner().scan(tmp_path)
    d1 = [f for f in report.findings if f.rule_id == "DOCKER001"]
    assert d1 and all(f.suppressed for f in d1)


# ---- New K8s hardening rules ------------------------------------------------

def _write_k8s(tmp_path, spec_extra="", container_extra=""):
    content = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: x
  labels:
    app.kubernetes.io/name: x
spec:
  template:
    metadata:
      labels:
        app.kubernetes.io/name: x
    spec:
{spec_extra}
      containers:
        - name: c
          image: x:1.0
          resources:
            requests: {{cpu: 100m, memory: 64Mi}}
            limits: {{cpu: 200m, memory: 128Mi}}
          readinessProbe: {{httpGet: {{path: /, port: 8080}}}}
          livenessProbe: {{httpGet: {{path: /, port: 8080}}}}
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
{container_extra}
"""
    p = tmp_path / "d.yaml"
    p.write_text(content)
    return p


def test_host_namespace_rule(tmp_path, scanner):
    p = _write_k8s(tmp_path, spec_extra="      hostNetwork: true")
    assert "K8S006" in _ids(scanner.scan(p))


def test_dangerous_capabilities_rule(tmp_path, scanner):
    extra = "            capabilities:\n              add: [SYS_ADMIN]"
    p = _write_k8s(tmp_path, container_extra=extra)
    assert "K8S007" in _ids(scanner.scan(p))


def test_writable_root_fs_rule(tmp_path, scanner):
    # No readOnlyRootFilesystem set -> K8S008 fires.
    p = _write_k8s(tmp_path)
    assert "K8S008" in _ids(scanner.scan(p))


def test_plaintext_secret_manifest_rule(tmp_path, scanner):
    p = tmp_path / "secret.yaml"
    p.write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
        "stringData:\n  password: RealP@ssw0rdValue123\n"
    )
    assert "K8S009" in _ids(scanner.scan(p))


def test_service_account_token_rule(tmp_path, scanner):
    p = _write_k8s(tmp_path)
    assert "K8S010" in _ids(scanner.scan(p))


# ---- CI hardening rules -----------------------------------------------------

def test_broad_permissions_rule(tmp_path, scanner):
    wf = tmp_path / ".github" / "workflows" / "w.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: w\non: [push]\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@abc\n"
    )
    assert "CI003" in _ids(scanner.scan(wf))


def test_pull_request_target_rule(tmp_path, scanner):
    wf = tmp_path / ".github" / "workflows" / "prt.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: w\non: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@abc\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "CI004" in _ids(scanner.scan(wf))


# ---- Secret format detection ------------------------------------------------

@pytest.mark.parametrize("token,label", [
    ("AKIAIOSFODNN7EXAMPLE", "AWS access key ID"),
    ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GitHub token"),
    ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "Google API key"),
])
def test_known_token_detection(token, label):
    assert detect_known_token(token) == label


def test_random_uuid_not_flagged_as_secret(tmp_path, scanner):
    # A UUID-like config value should not be flagged (entropy alone insufficient).
    env = tmp_path / "config.env"
    env.write_text("REQUEST_ID=123e4567-e89b-12d3-a456-426614174000\n")
    report = scanner.scan(env)
    assert "SECRET001" not in _ids(report)


def test_private_key_material_flagged(tmp_path, scanner):
    env = tmp_path / "id_rsa.env"
    env.write_text("KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n")
    report = scanner.scan(env)
    assert "SECRET001" in _ids(report)


def test_example_filename_downgrades_to_warning(tmp_path, scanner):
    env = tmp_path / "example.env"
    env.write_text("API_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")
    report = scanner.scan(env)
    findings = [f for f in report.active_findings() if f.rule_id == "SECRET001"]
    assert findings
    assert all(f.severity is Severity.WARNING for f in findings)
    assert all("example/template" in f.audit_note for f in findings)


def test_placeholder_not_flagged(tmp_path, scanner):
    env = tmp_path / "config.env"
    env.write_text("PASSWORD=changeme\nSECRET=your_password_here\n")
    report = scanner.scan(env)
    assert "SECRET001" not in _ids(report)


# ---- Compliance renderer ----------------------------------------------------

def test_compliance_report_groups_frameworks(scanner):
    report = scanner.scan(EXAMPLES / "bad")
    md = render_compliance(report)
    assert "Prodogy Compliance Report" in md
    assert "CIS Kubernetes Benchmark" in md
    assert "CIS-K8s" in md


# ---- Baseline ---------------------------------------------------------------

def test_baseline_suppresses_preexisting_but_not_secrets(tmp_path, scanner):
    from prodogy.baseline import apply_baseline, load_baseline, write_baseline

    report = scanner.scan(EXAMPLES / "bad")
    bpath = tmp_path / "baseline.json"
    write_baseline(report, bpath)

    # Re-scan and apply the baseline: pre-existing non-secret findings suppressed.
    report2 = scanner.scan(EXAMPLES / "bad")
    suppressed = apply_baseline(report2, load_baseline(bpath))
    assert suppressed > 0

    # Confidential findings must NOT be baselined away.
    active_secrets = [
        f for f in report2.active_findings()
        if f.category is Category.CONFIDENTIAL
    ]
    assert active_secrets, "secrets must still surface despite baseline"


def test_baseline_missing_file_is_empty(tmp_path):
    from prodogy.baseline import load_baseline

    assert load_baseline(tmp_path / "nope.json") == set()


# ---- Web security -----------------------------------------------------------

def test_web_rejects_path_traversal():
    from fastapi.testclient import TestClient

    from prodogy.web.server import create_app
    app = create_app(allowed_roots=[EXAMPLES], auth_token=None)
    c = TestClient(app)
    r = c.post("/api/scan", json={"path": "/etc", "maintainability": False})
    assert r.status_code == 403


def test_web_requires_auth_when_token_set():
    from fastapi.testclient import TestClient

    from prodogy.web.server import create_app
    app = create_app(allowed_roots=[EXAMPLES], auth_token="sekret")
    c = TestClient(app)
    assert c.post("/api/scan", json={"path": str(EXAMPLES / "bad")}).status_code == 401
    ok = c.post(
        "/api/scan",
        json={"path": str(EXAMPLES / "bad"), "maintainability": False},
        headers={"Authorization": "Bearer sekret"},
    )
    assert ok.status_code == 200
