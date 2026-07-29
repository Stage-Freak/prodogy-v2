"""Report renderers.

Every renderer consumes a :class:`Report` — the single source of truth — and
produces a different view:

  * ``render_terminal``  : rich, human-friendly console output.
  * ``render_markdown``  : a PR-comment body.
  * ``render_sarif``     : SARIF 2.1.0 for native CI code-scanning integration.
  * ``render_json``      : the raw report (schema contract) for tooling / web UI.
  * ``render_compliance``: a control-mapped audit report (CIS/NSA/PCI/SOC2).

Renderers never change pass/fail — they only display.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from prodogy.models import Report, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.ERROR: "bold red",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
}
_SEV_EMOJI = {
    Severity.CRITICAL: "🛑",
    Severity.ERROR: "❌",
    Severity.WARNING: "⚠️",
    Severity.INFO: "ℹ️",
}


def render_json(report: Report, *, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def render_terminal(report: Report, *, console: Console | None = None, show_rationale: bool = True) -> None:
    console = console or Console()
    active = sorted(
        report.active_findings(),
        key=lambda f: (-f.severity.rank, f.location.path, f.location.line or 0),
    )

    console.print(f"\n[bold]Prodogy[/bold] scanned [cyan]{report.summary.scanned_files}[/cyan] "
                  f"file(s) in [dim]{report.root}[/dim]\n")

    if not active:
        console.print("[bold green]✓ No issues found. Looks production-ready.[/bold green]\n")
    else:
        for f in active:
            style = _SEV_STYLE[f.severity]
            emoji = _SEV_EMOJI[f.severity]
            console.print(
                f"{emoji} [{style}]{f.severity.value.upper():<8}[/] "
                f"[bold]{f.rule_id}[/bold]  {f.location.as_str()}"
            )
            console.print(f"    {f.message}")
            if show_rationale and f.rationale:
                console.print(f"    [dim]why:[/dim] {f.rationale}")
            if f.remediation:
                console.print(f"    [green]fix:[/green] {f.remediation}")
            if f.llm_explanation:
                console.print(f"    [blue]llm:[/blue] {f.llm_explanation}")
            if f.audit_note:
                console.print(f"    [magenta]audit:[/magenta] {f.audit_note}")
            console.print()

    _render_summary_table(report, console)

    if report.maintainability:
        _render_heatmap(report, console)


def _render_summary_table(report: Report, console: Console) -> None:
    table = Table(title="Summary", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in (Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO):
        count = report.summary.by_severity.get(sev.value, 0)
        table.add_row(f"[{_SEV_STYLE[sev]}]{sev.value}[/]", str(count))
    console.print(table)


def _render_heatmap(report: Report, console: Console) -> None:
    hot = [s for s in report.maintainability if s.heat > 0][:10]
    if not hot:
        return
    table = Table(title="Maintainability Heatmap (top hotspots)", header_style="bold")
    table.add_column("File")
    table.add_column("Heat", justify="right")
    table.add_column("Churn", justify="right")
    table.add_column("TODOs", justify="right")
    table.add_column("Coupled with")
    for s in hot:
        bar = "█" * int(round(s.heat * 10))
        table.add_row(
            s.path,
            f"{s.heat:.2f} [red]{bar}[/red]",
            str(s.change_frequency),
            str(s.todo_count),
            ", ".join(s.coupled_with[:3]) or "-",
        )
    console.print(table)


def render_markdown(report: Report) -> str:
    active = sorted(
        report.active_findings(),
        key=lambda f: (-f.severity.rank, f.location.path, f.location.line or 0),
    )
    lines: list[str] = ["## 🚀 Prodogy — Deployment Readiness Report", ""]

    s = report.summary
    lines.append(
        f"Scanned **{s.scanned_files}** file(s) — "
        f"🛑 {s.by_severity.get('critical', 0)} critical, "
        f"❌ {s.by_severity.get('error', 0)} error, "
        f"⚠️ {s.by_severity.get('warning', 0)} warning, "
        f"ℹ️ {s.by_severity.get('info', 0)} info."
    )
    lines.append("")

    if not active:
        lines.append("✅ **No issues found. This looks production-ready.**")
        return "\n".join(lines)

    lines.append("| Severity | Rule | Location | Issue |")
    lines.append("|---|---|---|---|")
    for f in active:
        emoji = _SEV_EMOJI[f.severity]
        loc = f.location.as_str()
        msg = f.message.replace("|", "\\|")
        lines.append(f"| {emoji} {f.severity.value} | `{f.rule_id}` | `{loc}` | {msg} |")
    lines.append("")

    lines.append("<details><summary>Why these matter & how to fix</summary>")
    lines.append("")
    for f in active:
        lines.append(f"**{f.rule_id} — {f.title}** (`{f.location.as_str()}`)")
        if f.rationale:
            lines.append(f"- _Why:_ {f.rationale}")
        if f.remediation:
            lines.append(f"- _Fix:_ {f.remediation}")
        if f.llm_explanation:
            lines.append(f"- _LLM:_ {f.llm_explanation}")
        if f.audit_note:
            lines.append(f"- _Audit:_ {f.audit_note}")
        lines.append("")
    lines.append("</details>")

    if report.maintainability:
        hot = [m for m in report.maintainability if m.heat > 0][:5]
        if hot:
            lines.append("")
            lines.append("### 🔥 Maintainability hotspots")
            lines.append("| File | Heat | Churn | TODOs |")
            lines.append("|---|---|---|---|")
            for m in hot:
                lines.append(f"| `{m.path}` | {m.heat:.2f} | {m.change_frequency} | {m.todo_count} |")

    return "\n".join(lines)


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0 — consumed natively by GitHub/GitLab code scanning."""
    level_map = {
        Severity.CRITICAL: "error",
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "note",
    }

    rule_index: dict[str, int] = {}
    rules_meta = []
    results = []
    for f in report.active_findings():
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules_meta)
            rules_meta.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.rationale or f.title},
                "helpUri": f"https://prodogy.dev/rules/{f.rule_id}",
            })
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": level_map[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path},
                    "region": {"startLine": f.location.line or 1},
                }
            }],
        }
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Prodogy",
                    "version": report.tool_version,
                    "informationUri": "https://prodogy.dev",
                    "rules": rules_meta,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# Human-readable names for the framework prefixes used in rule compliance_refs.
_FRAMEWORK_NAMES = {
    "CIS-Docker": "CIS Docker Benchmark",
    "CIS-K8s": "CIS Kubernetes Benchmark",
    "NSA-K8s": "NSA/CISA Kubernetes Hardening Guide",
    "PCI-DSS": "PCI DSS v4.0",
    "SOC2": "SOC 2",
    "SLSA": "SLSA Supply-chain Framework",
}


def _framework_of(ref: str) -> str:
    """Map a control ref like 'CIS-K8s-5.2.1' to its framework display name."""
    for prefix, name in _FRAMEWORK_NAMES.items():
        if ref.startswith(prefix):
            return name
    return ref.split("-")[0]


def render_compliance(report: Report) -> str:
    """A control-mapped compliance/audit report grouped by framework.

    For each framework, lists the controls that were exercised, the finding
    count per control, and the specific file:line locations — the evidence an
    auditor needs. Suppressed findings are shown separately as documented
    exceptions with their audit notes.
    """
    active = report.active_findings()
    suppressed = [f for f in report.findings if f.suppressed]

    # Group: framework -> control ref -> findings.
    by_framework: dict[str, dict[str, list]] = {}
    unmapped: list = []
    for f in active:
        if not f.compliance_refs:
            unmapped.append(f)
            continue
        for ref in f.compliance_refs:
            fw = _framework_of(ref)
            by_framework.setdefault(fw, {}).setdefault(ref, []).append(f)

    lines: list[str] = ["# Prodogy Compliance Report", ""]
    lines.append(f"- Tool: Prodogy v{report.tool_version}")
    lines.append(f"- Generated: {report.generated_at.isoformat()}")
    lines.append(f"- Scope: `{report.root}` — {report.summary.scanned_files} file(s) scanned")
    lines.append(f"- Active findings: {len(active)} | Documented exceptions (suppressed): {len(suppressed)}")
    lines.append("")

    if not by_framework:
        lines.append("_No control-mapped findings. All mapped controls passed._")
    for fw in sorted(by_framework):
        controls = by_framework[fw]
        lines.append(f"## {fw}")
        lines.append("")
        lines.append("| Control | Status | Findings | Evidence (file:line) |")
        lines.append("|---|---|---|---|")
        for ref in sorted(controls):
            fs = controls[ref]
            evidence = "; ".join(sorted({fnd.location.as_str() for fnd in fs}))
            lines.append(f"| `{ref}` | ❌ FAIL | {len(fs)} | {evidence} |")
        lines.append("")

    if suppressed:
        lines.append("## Documented Exceptions (suppressed findings)")
        lines.append("")
        lines.append("| Rule | Location | Justification |")
        lines.append("|---|---|---|")
        for f in suppressed:
            note = (f.audit_note or "—").replace("|", "\\|")
            lines.append(f"| `{f.rule_id}` | `{f.location.as_str()}` | {note} |")
        lines.append("")

    if unmapped:
        lines.append(f"## Additional findings without control mappings ({len(unmapped)})")
        lines.append("")
        lines.append("| Rule | Severity | Location | Issue |")
        lines.append("|---|---|---|---|")
        for f in sorted(unmapped, key=lambda x: (-x.severity.rank, x.location.path)):
            msg = f.message.replace("|", "\\|")
            lines.append(f"| `{f.rule_id}` | {f.severity.value} | `{f.location.as_str()}` | {msg} |")
        lines.append("")

    return "\n".join(lines)
