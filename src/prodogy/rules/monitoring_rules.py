"""Grafana and Prometheus configuration rules.

These target grafana.ini / grafana.yml, prometheus.yml, and Grafana dashboard
JSON files for common misconfigurations that weaken observability or expose
the monitoring stack.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.rules import yaml_nav as nav

_GRAFANA = (FileKind.GRAFANA,)
_PROMETHEUS = (FileKind.PROMETHEUS,)
_MON = (FileKind.GRAFANA, FileKind.PROMETHEUS)


# ---------------------------------------------------------------------------
# Grafana rules
# ---------------------------------------------------------------------------


class GrafanaAnonymousAuthRule(Rule):
    id = "MON001"
    title = "Grafana anonymous authentication enabled"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _GRAFANA
    rationale = (
        "Anonymous authentication allows unauthenticated users to view "
        "dashboards and potentially sensitive metrics. In production, this "
        "exposes internal system state to anyone who can reach the Grafana URL."
    )
    remediation = "Disable anonymous auth: [auth.anonymous] enabled = false"

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        text = artifact.raw
        # Check YAML format
        if artifact.data and isinstance(artifact.data, list):
            for doc in artifact.data:
                if not hasattr(doc, "get"):
                    continue
                auth = nav.get(doc, "auth") or {}
                anon = nav.get(auth, "anonymous")
                if isinstance(anon, dict) and nav.get(anon, "enabled") is True:
                    line = nav.key_line(auth, "anonymous") or nav.node_line(doc)
                    yield self.finding(
                        path=artifact.path,
                        message="Grafana has anonymous authentication enabled",
                        line=line,
                    )
        # Check INI/text format
        if re.search(r"\[auth\.anonymous\]\s*\n\s*enabled\s*=\s*true", text, re.IGNORECASE):
            for i, line in enumerate(artifact.lines, start=1):
                if "enabled" in line and "true" in line.lower():
                    # Check if we're in [auth.anonymous] section
                    preceding = "\n".join(artifact.lines[max(0, i - 5):i])
                    if "auth.anonymous" in preceding:
                        yield self.finding(
                            path=artifact.path,
                            message="Grafana has anonymous authentication enabled",
                            line=i,
                        )
                        break


class GrafanaNoHttpsRule(Rule):
    id = "MON002"
    title = "Grafana not configured for HTTPS"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _GRAFANA
    rationale = (
        "Without HTTPS, dashboard credentials and session cookies are transmitted "
        "in plaintext, making them interceptable via network sniffing."
    )
    remediation = (
        "Set [server] protocol = https and provide cert_file/key_file, "
        "or use a TLS-terminating reverse proxy."
    )

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        text = artifact.raw
        # Check INI format
        if re.search(r"\[server\]\s*\n\s*protocol\s*=\s*http\b(?!s)", text, re.IGNORECASE):
            for i, line in enumerate(artifact.lines, start=1):
                if "protocol" in line and "http" in line.lower() and "https" not in line.lower():
                    preceding = "\n".join(artifact.lines[max(0, i - 5):i])
                    if "[server]" in preceding:
                        yield self.finding(
                            path=artifact.path,
                            message="Grafana server protocol is HTTP, not HTTPS",
                            line=i,
                        )
                        break
        # Check YAML format
        if artifact.data and isinstance(artifact.data, list):
            for doc in artifact.data:
                if not hasattr(doc, "get"):
                    continue
                server = nav.get(doc, "server") or {}
                protocol = nav.get(server, "protocol")
                if protocol == "http":
                    line = nav.key_line(server, "protocol") or nav.node_line(doc)
                    yield self.finding(
                        path=artifact.path,
                        message="Grafana server protocol is HTTP, not HTTPS",
                        line=line,
                    )


class GrafanaNoPasswordRule(Rule):
    id = "MON003"
    title = "Grafana admin password not changed from default"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _GRAFANA
    rationale = (
        "The default admin password 'admin' is publicly known. If not changed, "
        "anyone with network access can take over the Grafana instance."
    )
    remediation = "Set a strong password under [security] admin_password or use an external auth provider."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        text = artifact.raw
        # Check INI format
        if re.search(r"\[security\]\s*\n\s*admin_password\s*=\s*admin\b", text, re.IGNORECASE):
            for i, line in enumerate(artifact.lines, start=1):
                if "admin_password" in line.lower() and "= admin" in line.lower():
                    preceding = "\n".join(artifact.lines[max(0, i - 5):i])
                    if "[security]" in preceding:
                        yield self.finding(
                            path=artifact.path,
                            message="Grafana admin password is set to default 'admin'",
                            line=i,
                        )
                        break


# ---------------------------------------------------------------------------
# Prometheus rules
# ---------------------------------------------------------------------------


class PrometheusNoRetentionRule(Rule):
    id = "MON004"
    title = "Prometheus retention period not configured"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _PROMETHEUS
    rationale = (
        "Without an explicit retention period, Prometheus uses the default "
        "(15 days) which may be too short for debugging or too long for disk. "
        "Explicitly setting it avoids surprises."
    )
    remediation = "Set 'retention' in the global config (e.g. retention: 30d)."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            if not hasattr(doc, "get"):
                continue
            global_cfg = nav.get(doc, "global") or {}
            retention = nav.get(global_cfg, "retention") or nav.get(global_cfg, "retention.time")
            if not retention:
                line = nav.node_line(doc) or 1
                yield self.finding(
                    path=artifact.path,
                    message="Prometheus has no retention period configured",
                    line=line,
                )


class PrometheusNoAlertingRule(Rule):
    id = "MON005"
    title = "Prometheus has no alerting configuration"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _PROMETHEUS
    rationale = (
        "Prometheus without alerting rules means anomalies are recorded but "
        "never surfaced to humans. An alerting config (even if just pointing "
        "to Alertmanager) is a sign the monitoring stack is intentional."
    )
    remediation = "Add an 'alerting' section referencing Alertmanager, and define 'rule_files'."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            if not hasattr(doc, "get"):
                continue
            has_alerting = nav.get(doc, "alerting") is not None
            has_rule_files = nav.get(doc, "rule_files") is not None
            if not has_alerting and not has_rule_files:
                line = nav.node_line(doc) or 1
                yield self.finding(
                    path=artifact.path,
                    message="Prometheus has no alerting configuration or rule_files",
                    line=line,
                )


class PrometheusOpenMetricsExportRule(Rule):
    id = "MON006"
    title = "Prometheus metrics endpoint exposed without auth"
    severity = Severity.WARNING
    category = Category.PRODUCTION_SAFETY
    applies_to = _PROMETHEUS
    rationale = (
        "Prometheus metrics endpoints (/metrics) expose internal system state "
        "including request rates, error rates, and resource usage. If accessible "
        "without authentication, this information aids attackers in reconnaissance."
    )
    remediation = "Restrict metrics endpoint access via network policy, reverse proxy auth, or --web.config.file."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        text = artifact.raw
        # Look for scrape_configs with no auth or tls_config
        if re.search(r"^\s*scrape_configs:\s*$", text, re.MULTILINE):
            # Check if there's any web.config or basic_auth referenced
            has_web_config = bool(re.search(r"web\.config|basic_auth|bearer_token|tls_config", text))
            if not has_web_config:
                for i, line in enumerate(artifact.lines, start=1):
                    if "scrape_configs" in line:
                        yield self.finding(
                            path=artifact.path,
                            message="Prometheus scrape configs have no authentication configured",
                            line=i,
                        )
                        break


for _rule in (
    GrafanaAnonymousAuthRule(),
    GrafanaNoHttpsRule(),
    GrafanaNoPasswordRule(),
    PrometheusNoRetentionRule(),
    PrometheusNoAlertingRule(),
    PrometheusOpenMetricsExportRule(),
):
    registry.register(_rule)
