"""Docker Compose production-readiness rules.

These target docker-compose.yml / compose.yml files for the common mistakes
that cause outages or security issues in Compose-based deployments.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.rules import yaml_nav as nav

_COMPOSE = (FileKind.DOCKER_COMPOSE,)

_SECRET_ENV_RE = re.compile(
    r"\b([A-Z_]*(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z_]*)\s*[:=]\s*(\S+)",
    re.IGNORECASE,
)


class ComposeLatestTagRule(Rule):
    id = "DC001"
    title = "Service image uses ':latest' or an unpinned tag"
    severity = Severity.ERROR
    category = Category.DEPLOY_RISK
    applies_to = _COMPOSE
    rationale = (
        "An unpinned or ':latest' tag means the image you tested is not "
        "guaranteed to be the image you deploy. A silent upstream change can "
        "break production with no code change on your side."
    )
    remediation = "Pin to an immutable tag or digest, e.g. 'postgres:16.3-alpine'."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            services = nav.get(doc, "services") or {}
            if not hasattr(services, "items"):
                continue
            for svc_name, svc in services.items():
                image = nav.get(svc, "image")
                if not image or not isinstance(image, str):
                    continue
                if "@sha256:" in image:
                    continue
                last_segment = image.rsplit("/", 1)[-1]
                tag = ""
                if ":" in last_segment:
                    tag = last_segment.rsplit(":", 1)[-1]
                if tag == "" or tag == "latest":
                    msg = (
                        f"Service '{svc_name}' image '{image}' has no pinned version tag"
                        if tag == ""
                        else f"Service '{svc_name}' image '{image}' uses the ':latest' tag"
                    )
                    line = nav.key_line(svc, "image") or nav.node_line(svc)
                    yield self.finding(path=artifact.path, message=msg, line=line)


class ComposeMissingHealthcheckRule(Rule):
    id = "DC002"
    title = "Service has no healthcheck"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _COMPOSE
    rationale = (
        "Without a healthcheck, a container that has deadlocked but not crashed "
        "keeps receiving traffic. Compose's 'depends_on' with condition: "
        "service_healthy also requires a healthcheck to work."
    )
    remediation = "Add a healthcheck section to each service, or use 'depends_on' with condition."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            services = nav.get(doc, "services") or {}
            if not hasattr(services, "items"):
                continue
            for svc_name, svc in services.items():
                if not nav.get(svc, "healthcheck"):
                    line = nav.node_line(svc)
                    yield self.finding(
                        path=artifact.path,
                        message=f"Service '{svc_name}' defines no healthcheck",
                        line=line,
                    )


class ComposeHardcodedSecretRule(Rule):
    id = "DC003"
    title = "Possible hard-coded secret in service environment"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _COMPOSE
    rationale = (
        "Secrets written directly into environment blocks are committed to the "
        "repository history. Use Docker secrets, env_file with .gitignore, or "
        "a secrets manager instead."
    )
    remediation = "Use 'env_file' with a .gitignored file, or Docker secrets / external secret injection."

    _SAFE_PREFIXES = ("${", "$", "{{")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            services = nav.get(doc, "services") or {}
            if not hasattr(services, "items"):
                continue
            for svc_name, svc in services.items():
                env = nav.get(svc, "environment") or {}
                if isinstance(env, list):
                    for item in env:
                        if not isinstance(item, str):
                            continue
                        m = _SECRET_ENV_RE.search(item)
                        if m:
                            value = m.group(3).strip().strip("\"'")
                            if any(value.startswith(p) for p in self._SAFE_PREFIXES):
                                continue
                            if value.lower() in {"changeme", "example", "placeholder", "true", "false"}:
                                continue
                            line = nav.node_line(svc)
                            yield self.finding(
                                path=artifact.path,
                                message=f"Service '{svc_name}' has '{m.group(1)}' with a literal secret value",
                                line=line,
                            )
                elif isinstance(env, dict):
                    for key, value in env.items():
                        env_line = f"{key}: {value}"
                        m = _SECRET_ENV_RE.search(env_line)
                        if m:
                            v = str(value).strip().strip("\"'")
                            if any(v.startswith(p) for p in self._SAFE_PREFIXES):
                                continue
                            if v.lower() in {"changeme", "example", "placeholder", "true", "false"}:
                                continue
                            line = nav.key_line(env, key) or nav.node_line(svc)
                            yield self.finding(
                                path=artifact.path,
                                message=f"Service '{svc_name}' has '{key}' with a literal secret value",
                                line=line,
                            )


class ComposeMissingResourceLimitsRule(Rule):
    id = "DC004"
    title = "Service has no resource limits"
    severity = Severity.WARNING
    category = Category.PRODUCTION_SAFETY
    applies_to = _COMPOSE
    rationale = (
        "Without resource limits a single service can consume all host resources, "
        "causing noisy-neighbour outages and OOM kills of other services."
    )
    remediation = "Add deploy.resources.limits (Compose v3+) or mem_limit/cpu_quota."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            services = nav.get(doc, "services") or {}
            if not hasattr(services, "items"):
                continue
            for svc_name, svc in services.items():
                # Compose v3+ deploy.resources
                deploy = nav.get(svc, "deploy")
                resources = nav.get(deploy, "resources") if deploy else None
                limits = nav.get(resources, "limits") if resources else None
                # Compose v2 legacy
                mem_limit = nav.get(svc, "mem_limit")
                cpu_quota = nav.get(svc, "cpu_quota")
                if not limits and not mem_limit and not cpu_quota:
                    line = nav.node_line(svc)
                    yield self.finding(
                        path=artifact.path,
                        message=f"Service '{svc_name}' defines no resource limits",
                        line=line,
                    )


class ComposeNoRestartPolicyRule(Rule):
    id = "DC005"
    title = "Service has no restart policy"
    severity = Severity.INFO
    category = Category.DEPLOY_RISK
    applies_to = _COMPOSE
    rationale = (
        "Without a restart policy, a crashed container stays down until manual "
        "intervention. In production, services should restart automatically."
    )
    remediation = "Add 'restart: unless-stopped' or 'restart: always' to each service."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            services = nav.get(doc, "services") or {}
            if not hasattr(services, "items"):
                continue
            for svc_name, svc in services.items():
                restart = nav.get(svc, "restart")
                if restart is None:
                    line = nav.node_line(svc)
                    yield self.finding(
                        path=artifact.path,
                        message=f"Service '{svc_name}' has no restart policy",
                        line=line,
                    )


for _rule in (
    ComposeLatestTagRule(),
    ComposeMissingHealthcheckRule(),
    ComposeHardcodedSecretRule(),
    ComposeMissingResourceLimitsRule(),
    ComposeNoRestartPolicyRule(),
):
    registry.register(_rule)
