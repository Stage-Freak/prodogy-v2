"""File discovery and classification.

Walks a directory (or accepts an explicit file list, e.g. changed files in a PR)
and classifies each file into a :class:`FileKind`. Classification uses filename
patterns first (cheap) and falls back to a light content sniff for ambiguous
YAML (a manifest vs. a Helm values file look identical by extension).

Performance note: we only read file contents for the sniff when the name alone
is inconclusive, and we skip common vendored/binary directories entirely. This
keeps monorepo scans fast.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from prodogy.models import FileKind

_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".terraform",
    "vendor", ".idea", ".vscode",
}

_YAML_EXT = (".yaml", ".yml")

# Content markers used to disambiguate YAML files.
_K8S_KIND_RE = re.compile(r"^\s*kind:\s*([A-Za-z]+)\s*$", re.MULTILINE)
_K8S_APIVERSION_RE = re.compile(r"^\s*apiVersion:\s*", re.MULTILINE)


def _classify_by_name(path: Path) -> FileKind | None:
    name = path.name
    lower = name.lower()

    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return FileKind.DOCKERFILE

    if lower.endswith(".tf") or lower.endswith(".tf.json"):
        return FileKind.TERRAFORM

    # Docker Compose files
    if lower in {
        "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.override.yml", "docker-compose.override.yaml",
        "compose.yml", "compose.yaml",
    }:
        return FileKind.DOCKER_COMPOSE

    # GitHub Actions live under .github/workflows/*.yml
    parts = {p.lower() for p in path.parts}
    if ".github" in parts and "workflows" in parts and path.suffix in _YAML_EXT:
        return FileKind.GITHUB_ACTIONS

    if lower in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
        return FileKind.GITLAB_CI

    if lower in {"values.yaml", "values.yml"} or lower.startswith("values."):
        if path.suffix in _YAML_EXT:
            return FileKind.HELM_VALUES

    # .env, .env.prod, staging.env, etc.
    if lower == ".env" or lower.startswith(".env.") or lower.endswith(".env"):
        return FileKind.ENV_FILE

    # Grafana dashboards / alerting provisioning
    if lower.endswith(".json") and "grafana" in str(path).lower():
        return FileKind.GRAFANA
    if lower in {"grafana.ini", "grafana.yml", "grafana.yaml"}:
        return FileKind.GRAFANA
    # Grafana provisioning files live under grafana/ directories
    if "grafana" in parts:
        if lower.endswith(_YAML_EXT):
            return FileKind.GRAFANA

    # Prometheus configs — only match explicit prometheus.* filenames
    if lower in {"prometheus.yml", "prometheus.yaml", "prometheus.json"}:
        return FileKind.PROMETHEUS

    # Promtail configs are NOT Prometheus — skip them
    if "promtail" in lower:
        return None

    # Ansible playbooks / roles
    if lower.endswith(".yml") or lower.endswith(".yaml"):
        if "roles" in parts and ("tasks" in parts or "handlers" in parts or "defaults" in parts):
            return FileKind.ANSIBLE
        if lower in {"playbook.yml", "playbook.yaml", "playbooks.yml", "playbooks.yaml"}:
            return FileKind.ANSIBLE
        if "group_vars" in parts or "host_vars" in parts:
            return FileKind.ANSIBLE

    return None


def _classify_yaml_content(text: str) -> FileKind:
    """Disambiguate a generic .yaml file by peeking at its content."""
    # K8s manifests have apiVersion + kind
    if _K8S_APIVERSION_RE.search(text):
        m = _K8S_KIND_RE.search(text)
        if not m:
            return FileKind.K8S_MANIFEST
        kind = m.group(1)
        mapping = {
            "Deployment": FileKind.K8S_DEPLOYMENT,
            "StatefulSet": FileKind.K8S_STATEFULSET,
        }
        return mapping.get(kind, FileKind.K8S_MANIFEST)

    # Docker Compose has 'services:' at top level
    if re.search(r"^\s*services:\s*$", text, re.MULTILINE):
        return FileKind.DOCKER_COMPOSE

    # Prometheus has 'global:' with 'scrape_interval' AND 'scrape_configs'
    # (Promtail also has scrape_configs, so require the global section too)
    if re.search(r"^\s*global:\s*$", text, re.MULTILINE) and re.search(r"scrape_interval", text):
        if re.search(r"^\s*scrape_configs:\s*$", text, re.MULTILINE):
            return FileKind.PROMETHEUS

    # Ansible playbooks start with '- hosts:' or '- name:' at top level
    if re.search(r"^\s*-\s+hosts:\s+", text, re.MULTILINE):
        return FileKind.ANSIBLE
    if re.search(r"^\s*-\s+name:\s+", text, re.MULTILINE) and re.search(r"^\s+tasks:\s*$", text, re.MULTILINE):
        return FileKind.ANSIBLE

    return FileKind.UNKNOWN


def classify(path: Path, read_content: bool = True) -> FileKind:
    """Return the :class:`FileKind` for a single path."""
    by_name = _classify_by_name(path)
    if by_name is not None:
        return by_name

    if path.suffix in _YAML_EXT and read_content:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return FileKind.UNKNOWN
        return _classify_yaml_content(text)

    return FileKind.UNKNOWN


def discover(root: str | Path) -> Iterator[tuple[Path, FileKind]]:
    """Walk ``root`` and yield ``(path, kind)`` for every relevant file."""
    root = Path(root)
    if root.is_file():
        yield root, classify(root)
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            kind = classify(p)
            if kind is not FileKind.UNKNOWN:
                yield p, kind


def discover_paths(paths: Iterable[str | Path]) -> Iterator[tuple[Path, FileKind]]:
    """Classify an explicit list of paths (e.g. changed files in a PR)."""
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            kind = classify(p)
            if kind is not FileKind.UNKNOWN:
                yield p, kind
