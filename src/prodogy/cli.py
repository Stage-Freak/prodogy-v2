"""Prodogy command-line interface.

Subcommands:
  prodogy scan PATH        Scan a directory or file and print findings.
  prodogy rules            List all registered rules.
  prodogy enrich PATH      Enrich a previous scan's findings with LLM context.

The exit code is meaningful for CI: non-zero when a finding at or above the
``--fail-on`` threshold exists. This is the pipeline gate.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

import click
from rich.console import Console

from prodogy import __version__
from prodogy.config import ConfigError
from prodogy.engine import load_default_rules
from prodogy.models import Severity
from prodogy.renderers import (
    render_compliance,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)
from prodogy.scanner import Scanner

console = Console()

_FORMATS = ("terminal", "json", "markdown", "sarif", "compliance")


@click.group()
@click.version_option(__version__, prog_name="prodogy")
def cli() -> None:
    """Prodogy — intelligent deployment-readiness linter."""


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-f", "--format", "fmt",
    type=click.Choice(_FORMATS),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default="error",
    help="Minimum severity that fails the build (exit non-zero).",
)
@click.option(
    "--changed",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="File listing changed paths (one per line) to scan only those — for PRs.",
)
@click.option(
    "--maintainability/--no-maintainability",
    default=False,
    help="Compute the git-history maintainability heatmap.",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a .prodogy.yml config (auto-discovered at the scan root if omitted).",
)
@click.option(
    "--baseline",
    type=click.Path(path_type=Path),
    default=None,
    help="Baseline file: suppress pre-existing findings so the gate fails only on new ones.",
)
@click.option(
    "--write-baseline",
    type=click.Path(path_type=Path),
    default=None,
    help="Write current findings to this baseline file and exit 0 (accept the current state).",
)
@click.option(
    "--enrich/--no-enrich",
    default=False,
    help="Enrich findings with LLM-generated contextual explanations.",
)
def scan(
    path: Path,
    fmt: str,
    fail_on: str,
    changed: Path | None,
    maintainability: bool,
    output: Path | None,
    config: Path | None,
    baseline: Path | None,
    write_baseline: Path | None,
    enrich: bool,
) -> None:
    """Scan PATH for deployment-readiness issues."""
    changed_paths = None
    if changed is not None:
        changed_paths = [
            line.strip()
            for line in changed.read_text().splitlines()
            if line.strip()
        ]

    scanner = Scanner()
    try:
        report = scanner.scan(
            path,
            changed_paths=changed_paths,
            with_maintainability=maintainability,
            config_path=config,
        )
    except ConfigError as exc:
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        sys.exit(2)

    # Accept-current-state: record findings as the baseline and stop.
    if write_baseline is not None:
        from prodogy.baseline import write_baseline as _wb

        count = _wb(report, write_baseline)
        console.print(f"[green]Wrote baseline with {count} finding(s) to {write_baseline}[/green]")
        return

    # Apply an existing baseline: suppress pre-existing findings.
    baselined_count = 0
    if baseline is not None:
        from prodogy.baseline import apply_baseline, load_baseline

        baselined_count = apply_baseline(report, load_baseline(baseline))

    # Enrich findings with LLM if requested and configured.
    enriched_count = 0
    if enrich:
        from prodogy.config import resolve_config as _resolve_config
        from prodogy.enricher import Enricher, EnrichmentError

        cfg = _resolve_config(
            path if path.is_dir() else path.parent,
            config,
        )
        enricher = Enricher(config=cfg.model_dump(), root=str(path))
        try:
            report = enricher.enrich_report(report)
            enriched_count = sum(
                1 for f in report.active_findings() if f.llm_explanation
            )
        except EnrichmentError as exc:
            console.print(f"[yellow]Enrichment skipped:[/yellow] {exc}")

    effective_fail_on = fail_on

    if fmt == "terminal":
        render_terminal(report, console=console)
        if baselined_count:
            console.print(f"[dim]{baselined_count} pre-existing finding(s) suppressed by baseline.[/dim]")
        if enriched_count:
            console.print(f"[dim]{enriched_count} finding(s) enriched with LLM context.[/dim]")
    else:
        rendered = {
            "json": render_json,
            "markdown": render_markdown,
            "sarif": render_sarif,
            "compliance": render_compliance,
        }[fmt](report)
        if output:
            output.write_text(rendered)
            console.print(f"[green]Wrote {fmt} report to {output}[/green]")
        else:
            click.echo(rendered)

    if output and fmt == "terminal":
        console.print("[yellow]--output is ignored for terminal format[/yellow]")

    fail_threshold = Severity(effective_fail_on)
    if report.has_blocking(fail_threshold):
        blocking = sum(
            1 for f in report.active_findings() if f.severity.rank >= fail_threshold.rank
        )
        if fmt == "terminal":
            console.print(
                f"[bold red]✗ Gate failed: {blocking} finding(s) at or above "
                f"'{effective_fail_on}'.[/bold red]"
            )
        sys.exit(1)
    if fmt == "terminal":
        console.print("[bold green]✓ Gate passed.[/bold green]")


@cli.command(name="rules")
def list_rules() -> None:
    """List all registered rules."""
    from rich.table import Table

    registry = load_default_rules()
    table = Table(title=f"Prodogy rules ({len(registry)})", header_style="bold")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")
    for rule in sorted(registry.all(), key=lambda r: r.id):
        table.add_row(rule.id, rule.severity.value, rule.category.value, rule.title)
    console.print(table)


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-f", "--format", "fmt",
    type=click.Choice(_FORMATS),
    default="terminal",
    help="Output format for the enriched report.",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a .prodogy.yml config (auto-discovered at the scan root if omitted).",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Re-enrich all findings even if cache exists.",
)
@click.option(
    "--cache-stats",
    is_flag=True,
    default=False,
    help="Show cache statistics and exit.",
)
def enrich(
    path: Path,
    fmt: str,
    output: Path | None,
    config: Path | None,
    force: bool,
    cache_stats: bool,
) -> None:
    """Enrich findings with LLM-generated contextual explanations.

    Scans PATH, then sends findings to the LLM for project-aware explanations.
    The LLM never changes severity or deterministic fields — it only adds
    contextual ``llm_explanation`` to each finding.

    Results are cached in .prodogy-enrich-cache.json to avoid redundant API calls.
    Use --force to re-enrich even cached findings.
    """
    from prodogy.config import resolve_config as _resolve_config
    from prodogy.enricher import Enricher, EnrichmentError

    cfg = _resolve_config(
        path if path.is_dir() else path.parent,
        config,
    )

    enricher = Enricher(config=cfg.model_dump(), root=str(path))

    if cache_stats:
        stats = enricher.cache_stats()
        console.print("[bold]Enrichment Cache[/bold]")
        for k, v in stats.items():
            console.print(f"  {k}: {v}")
        return

    if not enricher.is_configured():
        console.print(
            "[yellow]LLM not configured.[/yellow] "
            "Set [bold]PRODOGY_LLM_API_KEY[/bold] env var or add [bold]llm.api_key[/bold] "
            "to your [bold].prodogy.yml[/bold].\n"
            "Example: [dim]export PRODOGY_LLM_API_KEY=sk-...[/dim]"
        )
        sys.exit(0)

    console.print(f"[dim]Scanning {path}...[/dim]")
    scanner = Scanner()
    try:
        report = scanner.scan(path, config_path=config)
    except ConfigError as exc:
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        sys.exit(2)

    if not report.active_findings():
        console.print("[bold green]No findings to enrich. Nothing to do.[/bold green]")
        return

    console.print(f"[dim]Enriching {len(report.active_findings())} finding(s) with LLM...[/dim]")
    try:
        report = enricher.enrich_report(report, only_unenriched=not force)
        enriched_count = sum(
            1 for f in report.active_findings() if f.llm_explanation
        )
    except EnrichmentError as exc:
        console.print(f"[bold red]Enrichment failed:[/bold red] {exc}")
        sys.exit(1)

    if fmt == "terminal":
        render_terminal(report, console=console)
        console.print(f"[dim]{enriched_count} finding(s) enriched with LLM context.[/dim]")
    else:
        rendered = {
            "json": render_json,
            "markdown": render_markdown,
            "sarif": render_sarif,
            "compliance": render_compliance,
        }[fmt](report)
        if output:
            output.write_text(rendered)
            console.print(f"[green]Wrote {fmt} report to {output}[/green]")
        else:
            click.echo(rendered)

    if output and fmt == "terminal":
        console.print("[yellow]--output is ignored for terminal format[/yellow]")


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind host (default localhost).")
@click.option("--port", default=8765, type=int, help="Bind port.")
@click.option(
    "--allow",
    "allow_roots",
    multiple=True,
    type=click.Path(path_type=Path),
    help="Directory the dashboard may scan (repeatable). Defaults to the current dir.",
)
@click.option(
    "--no-auth",
    is_flag=True,
    default=False,
    help="Disable the auth token (NOT recommended). By default a random token is required.",
)
def serve(host: str, port: int, allow_roots: tuple[Path, ...], no_auth: bool) -> None:
    """Launch the local web dashboard.

    By default the dashboard requires a per-run auth token and restricts scans to
    the current directory (or --allow roots), so it never exposes arbitrary files.
    """
    import os

    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]The web dashboard needs the 'web' extra.[/red]\n"
            "Install it with: [cyan]pip install -e '.[web]'[/cyan]"
        )
        sys.exit(2)

    roots = [str(Path(p).resolve()) for p in allow_roots] or [str(Path.cwd())]
    os.environ["PRODOGY_ALLOWED_ROOTS"] = os.pathsep.join(roots)

    token = None
    if not no_auth:
        token = secrets.token_urlsafe(24)
        os.environ["PRODOGY_AUTH_TOKEN"] = token
    else:
        os.environ.pop("PRODOGY_AUTH_TOKEN", None)

    if host not in {"127.0.0.1", "localhost"}:
        console.print(
            f"[yellow]⚠ Binding to {host}. The dashboard executes filesystem scans. "
            "Ensure the auth token stays secret and the allowed roots are minimal.[/yellow]"
        )
    console.print(f"[green]Prodogy dashboard:[/green] http://{host}:{port}")
    console.print(f"[dim]Allowed scan roots:[/dim] {', '.join(roots)}")
    if token:
        console.print(f"[bold cyan]Auth token:[/bold cyan] {token}")
        console.print(
            f"[dim]Open with:[/dim] http://{host}:{port}/?token={token}"
        )
    else:
        console.print("[yellow]Auth disabled (--no-auth).[/yellow]")
    uvicorn.run("prodogy.web.server:app", host=host, port=port, log_level="warning")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
