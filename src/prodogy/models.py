"""Core data models for Prodogy.

These models define the report *contract*. Every part of the system depends on
this schema:

  * Parsers and rules produce ``Finding`` objects.
  * The scanner aggregates them into a ``Report``.
  * All renderers (CLI, PR comment, SARIF, web UI) consume the ``Report``.

Because CI pass/fail gates depend on this data, the schema must be stable and
deterministic. The optional LLM enrichment layer may only *decorate* findings
(e.g. fill ``explanation``); it must never create findings or change severity.
"""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Severity levels, ordered from most to least critical.

    ``CRITICAL`` and ``ERROR`` findings fail a CI build by default.
    """

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.ERROR: 3,
            Severity.WARNING: 2,
            Severity.INFO: 1,
        }
        return order[self]


class Category(str, enum.Enum):
    """The four core questions Prodogy answers, plus operational buckets."""

    PRODUCTION_SAFETY = "production_safety"      # Is this config production-safe?
    DEPLOY_RISK = "deploy_risk"                  # What could break at deploy time?
    MAINTAINABILITY = "maintainability"          # What is hard to maintain later?
    CONFIDENTIAL = "confidential"                # Files needing permission/redaction.


class FileKind(str, enum.Enum):
    """Classification of a discovered file."""

    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    K8S_DEPLOYMENT = "k8s_deployment"
    K8S_STATEFULSET = "k8s_statefulset"
    K8S_MANIFEST = "k8s_manifest"          # Any other kubernetes kind.
    HELM_VALUES = "helm_values"
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    ENV_FILE = "env_file"
    TERRAFORM = "terraform"
    GRAFANA = "grafana"
    PROMETHEUS = "prometheus"
    ANSIBLE = "ansible"
    UNKNOWN = "unknown"


class Location(BaseModel):
    """Where a finding occurred within a file."""

    path: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None

    def as_str(self) -> str:
        if self.line is None:
            return self.path
        return f"{self.path}:{self.line}"


class Finding(BaseModel):
    """A single issue detected by a rule.

    ``rule_id`` is the stable identifier (e.g. ``DOCKER001``) used for
    suppression and for referencing docs. ``fingerprint`` is derived and used to
    deduplicate/track findings across runs.
    """

    rule_id: str
    title: str
    severity: Severity
    category: Category
    location: Location
    message: str
    # Plain-language "why it matters" — the staff-engineer voice. May be
    # enriched by the LLM layer, but a deterministic default is always present.
    rationale: str = ""
    remediation: str = ""
    # Set to True when a suppression comment lowered/removed this finding.
    suppressed: bool = False
    # If the confidential-detector reduced severity via feedback, we keep a note.
    audit_note: str = ""
    # Compliance control references, e.g. ["CIS-Docker-4.1", "NSA-K8s-nonroot"].
    # Enables mapping findings to framework controls for audit reports.
    compliance_refs: list[str] = Field(default_factory=list)
    # LLM-generated contextual explanation. Only set after explicit enrichment.
    # The LLM never modifies rule-provided fields (severity, rationale, remediation).
    # This field is purely advisory — it enriches the finding with project-specific
    # context, deeper remediation guidance, and related findings correlation.
    llm_explanation: str = ""

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.location.path}|{self.location.line}|{self.message}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ScannedFile(BaseModel):
    """Metadata about a file that was discovered and classified."""

    path: str
    kind: FileKind
    scanned: bool = True
    skip_reason: str = ""


class MaintainabilitySignal(BaseModel):
    """A git-history / heuristic signal used to build the maintainability heatmap."""

    path: str
    change_frequency: int = 0          # commits touching this file.
    last_changed_days: int | None = None
    coupled_with: list[str] = Field(default_factory=list)  # frequently co-changed files.
    todo_count: int = 0
    complexity_score: float = 0.0
    heat: float = 0.0                  # 0..1 normalized "attention needed" score.


class Summary(BaseModel):
    """Aggregate counts for quick consumption and gate decisions."""

    total_files: int = 0
    scanned_files: int = 0
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    """The single source of truth produced by a scan."""

    schema_version: str = "1.0"
    tool: str = "prodogy"
    tool_version: str = "0.2.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    root: str = "."
    files: list[ScannedFile] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    maintainability: list[MaintainabilitySignal] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)

    def active_findings(self) -> list[Finding]:
        """Findings that still count (not suppressed)."""
        return [f for f in self.findings if not f.suppressed]

    def recompute_summary(self) -> None:
        active = self.active_findings()
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for f in active:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
        self.summary = Summary(
            total_files=len(self.files),
            scanned_files=sum(1 for f in self.files if f.scanned),
            total_findings=len(active),
            by_severity=by_sev,
            by_category=by_cat,
        )

    def has_blocking(self, fail_on: Severity = Severity.ERROR) -> bool:
        """Whether the report contains a finding at or above ``fail_on``."""
        threshold = fail_on.rank
        return any(f.severity.rank >= threshold for f in self.active_findings())
