"""The scanner orchestrates discovery, parsing, rule execution and suppression.

Flow:
  1. Discover + classify files (whole tree or an explicit changed-file list).
  2. Parse each file into a ParsedArtifact.
  3. Run every applicable rule, collecting findings.
  4. Apply inline suppressions (findings kept but marked).
  5. Optionally compute maintainability signals from git history.
  6. Assemble and return a Report.

Everything here is deterministic and offline. This is the contract that CI
gates rely on.
"""

from __future__ import annotations

from pathlib import Path

from prodogy import __version__
from prodogy.config import Config, resolve_config
from prodogy.discovery import discover, discover_paths
from prodogy.engine import RuleRegistry, load_default_rules
from prodogy.models import (
    Category,
    Finding,
    Location,
    Report,
    ScannedFile,
    Severity,
)
from prodogy.parsers import load_artifact
from prodogy.suppression import apply_suppressions


class Scanner:
    def __init__(
        self,
        registry: RuleRegistry | None = None,
        config: Config | None = None,
    ) -> None:
        self.registry = registry or load_default_rules()
        # An explicitly provided config wins; otherwise it is resolved per-scan
        # from the scan root (so a repo's .prodogy.yml is picked up automatically).
        self._explicit_config = config

    def scan(
        self,
        root: str | Path,
        *,
        changed_paths: list[str] | None = None,
        with_maintainability: bool = False,
        config_path: str | Path | None = None,
    ) -> Report:
        root = Path(root)
        cfg = self._explicit_config or resolve_config(
            root if root.is_dir() else root.parent,
            Path(config_path) if config_path else None,
        )
        report = Report(root=str(root), tool_version=__version__)

        if changed_paths:
            discovered = list(discover_paths(changed_paths))
        else:
            discovered = list(discover(root))

        for path, kind in discovered:
            rel = self._relpath(path, root)
            if cfg.is_excluded(rel):
                report.files.append(
                    ScannedFile(path=rel, kind=kind, scanned=False, skip_reason="excluded by config")
                )
                continue

            scanned = ScannedFile(path=rel, kind=kind)
            report.files.append(scanned)

            artifact = load_artifact(path, kind)
            artifact.path = rel  # normalize to relative path in findings

            file_findings: list[Finding] = []
            for rule in self.registry.for_kind(kind):
                if cfg.is_rule_disabled(rule.id):
                    continue
                try:
                    for finding in rule.check(artifact):
                        # Apply configured severity override, if any.
                        finding.severity = cfg.severity_for(rule.id, finding.severity)
                        file_findings.append(finding)
                except Exception as exc:  # a bad rule must not abort the scan
                    # Surface the error as a finding instead of silently skipping,
                    # so a buggy rule can never hide a file's real state.
                    file_findings.append(
                        Finding(
                            rule_id="CORE002",
                            title="Rule execution error",
                            severity=Severity.WARNING,
                            category=Category.DEPLOY_RISK,
                            location=Location(path=rel, line=1),
                            message=f"Rule {rule.id} raised an error and could not fully scan this file: {exc}",
                            rationale=(
                                "A rule crashed while inspecting this file, so its findings for that "
                                "rule are missing. The file may contain issues that went undetected."
                            ),
                            remediation="Report this rule error; re-run once the rule is fixed.",
                        )
                    )
            apply_suppressions(
                file_findings, artifact.lines, protected_categories=cfg.non_suppressible
            )
            report.findings.extend(file_findings)

        if with_maintainability:
            self._add_maintainability(report, root)

        report.recompute_summary()
        return report

    @staticmethod
    def _relpath(path: Path, root: Path) -> str:
        try:
            if root.is_file():
                return path.name
            return str(path.relative_to(root))
        except ValueError:
            return str(path)

    def _add_maintainability(self, report: Report, root: Path) -> None:
        # Imported lazily so a non-git directory doesn't pay the cost.
        from prodogy.maintainability import compute_signals

        report.maintainability = compute_signals(root, report.files)


def scan(root: str | Path, **kwargs) -> Report:
    """Module-level convenience wrapper."""
    return Scanner().scan(root, **kwargs)
