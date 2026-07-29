"""Tests for the CLI (via click's runner), maintainability, and renderers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from prodogy.cli import cli
from prodogy.maintainability import compute_signals
from prodogy.models import ScannedFile
from prodogy.renderers import render_terminal
from prodogy.scanner import Scanner

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_cli_version(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_cli_rules_lists_rules(runner):
    result = runner.invoke(cli, ["rules"])
    assert result.exit_code == 0
    assert "DOCKER001" in result.output
    assert "CI001" in result.output


def test_cli_scan_bad_fails_gate(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "bad"), "--fail-on", "error"])
    assert result.exit_code == 1
    assert "Gate failed" in result.output


def test_cli_scan_good_passes_gate(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "good"), "--fail-on", "error"])
    assert result.exit_code == 0
    assert "Gate passed" in result.output


def test_cli_json_output_is_valid(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "good"), "-f", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1.0"


def test_cli_sarif_output_is_valid(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "bad"), "-f", "sarif", "--fail-on", "critical"])
    # Exit 1 due to gate, but SARIF must still be emitted before the gate check.
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"


def test_cli_markdown_output(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "bad"), "-f", "markdown", "--fail-on", "critical"])
    assert "Prodogy" in result.output
    assert "|" in result.output  # a markdown table


def test_cli_compliance_output(runner):
    result = runner.invoke(cli, ["scan", str(EXAMPLES / "bad"), "-f", "compliance", "--fail-on", "critical"])
    assert "Compliance Report" in result.output
    assert "CIS" in result.output


def test_cli_invalid_config_errors(runner, tmp_path):
    (tmp_path / ".prodogy.yml").write_text("unknown_key: true\n")
    (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "Config error" in result.output


def test_cli_output_to_file(runner, tmp_path):
    out = tmp_path / "report.json"
    result = runner.invoke(
        cli, ["scan", str(EXAMPLES / "good"), "-f", "json", "-o", str(out)]
    )
    assert result.exit_code == 0
    assert out.exists()
    json.loads(out.read_text())


def test_cli_changed_files_mode(runner, tmp_path):
    changed = tmp_path / "changed.txt"
    changed.write_text(str(EXAMPLES / "bad" / "Dockerfile") + "\n")
    result = runner.invoke(
        cli, ["scan", ".", "--changed", str(changed), "-f", "json", "--fail-on", "critical"]
    )
    payload = json.loads(result.output)
    # Only the one Dockerfile should have been scanned.
    assert payload["summary"]["scanned_files"] == 1


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)


def test_maintainability_computes_heat(tmp_path):
    _init_repo(tmp_path)
    # Two files that always change together -> coupling signal.
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    for i in range(3):
        a.write_text(f"x: {i}\n# TODO fix later\n")
        b.write_text(f"y: {i}\n")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-qm", f"c{i}"], cwd=tmp_path, check=True)

    files = [ScannedFile(path="a.yaml", kind="k8s_manifest"),
             ScannedFile(path="b.yaml", kind="k8s_manifest")]
    signals = compute_signals(tmp_path, files)
    by_path = {s.path: s for s in signals}
    assert by_path["a.yaml"].change_frequency == 3
    assert "b.yaml" in by_path["a.yaml"].coupled_with
    assert by_path["a.yaml"].todo_count >= 1
    assert by_path["a.yaml"].heat > 0


def test_maintainability_non_git_dir_degrades(tmp_path):
    (tmp_path / "a.yaml").write_text("x: 1\n")
    files = [ScannedFile(path="a.yaml", kind="k8s_manifest")]
    signals = compute_signals(tmp_path, files)
    assert signals[0].change_frequency == 0  # no git history


def test_render_terminal_smoke():
    from rich.console import Console

    report = Scanner().scan(EXAMPLES / "bad")
    console = Console(record=True, width=120)
    render_terminal(report, console=console)
    text = console.export_text()
    assert "SECRET001" in text or "K8S003" in text
    assert "Summary" in text
