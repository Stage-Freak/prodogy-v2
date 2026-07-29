"""Dockerfile production-readiness rules.

Each rule targets a mistake that commonly causes production incidents or drift.
Rules are intentionally small and independent so they are easy to test, reason
about, and suppress individually.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.parsers import DockerInstruction

_DOCKER = (FileKind.DOCKERFILE,)


def _instructions(artifact: ParsedArtifact) -> list[DockerInstruction]:
    data = artifact.data
    return data if isinstance(data, list) else []


class LatestTagRule(Rule):
    id = "DOCKER001"
    title = "Base image uses ':latest' or an unpinned tag"
    severity = Severity.ERROR
    category = Category.DEPLOY_RISK
    applies_to = _DOCKER
    rationale = (
        "An unpinned or ':latest' tag means the image you tested is not "
        "guaranteed to be the image you deploy. A silent upstream change can "
        "break production with no code change on your side, and rollbacks "
        "become non-deterministic."
    )
    remediation = "Pin to an immutable tag or digest, e.g. 'python:3.12.4-slim' or '...@sha256:...'."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for inst in _instructions(artifact):
            if inst.cmd != "FROM":
                continue
            image = inst.value.split(" AS ")[0].split(" as ")[0].strip()
            if "@sha256:" in image:
                continue
            # Split off registry/repo from tag. A ':' after the last '/' is a tag.
            tag = ""
            last_segment = image.rsplit("/", 1)[-1]
            if ":" in last_segment:
                tag = last_segment.rsplit(":", 1)[-1]
            if tag == "" or tag == "latest":
                msg = (
                    f"Image '{image}' has no pinned version tag"
                    if tag == ""
                    else f"Image '{image}' uses the ':latest' tag"
                )
                yield self.finding(path=artifact.path, message=msg, line=inst.line)


class RootUserRule(Rule):
    id = "DOCKER002"
    title = "Container runs as root (no USER instruction)"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _DOCKER
    rationale = (
        "Without a USER instruction the container runs as root. A compromised "
        "process then has root inside the container, widening the blast radius "
        "of any vulnerability and often violating cluster PodSecurity policies."
    )
    remediation = "Add a non-root user, e.g. 'RUN adduser --disabled-password app' then 'USER app'."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        insts = _instructions(artifact)
        if not insts:
            return
        last_user = None
        last_from_line = 1
        for inst in insts:
            if inst.cmd == "FROM":
                last_user = None  # a new stage resets the user
                last_from_line = inst.line
            elif inst.cmd == "USER":
                last_user = inst.value.strip()
        if last_user is None or last_user in {"root", "0"}:
            msg = "No non-root USER set; container will run as root"
            yield self.finding(path=artifact.path, message=msg, line=last_from_line)


class MissingHealthcheckRule(Rule):
    id = "DOCKER003"
    title = "No HEALTHCHECK defined"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _DOCKER
    rationale = (
        "Without a HEALTHCHECK (or an orchestrator probe), a container that has "
        "deadlocked but not crashed keeps receiving traffic. The platform cannot "
        "tell 'running' from 'healthy'."
    )
    remediation = "Add a HEALTHCHECK, or ensure Kubernetes liveness/readiness probes cover it."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        insts = _instructions(artifact)
        if not insts:
            return
        if not any(i.cmd == "HEALTHCHECK" for i in insts):
            yield self.finding(
                path=artifact.path,
                message="Dockerfile defines no HEALTHCHECK instruction",
                line=insts[-1].line,
            )


_SECRET_ENV_RE = re.compile(
    r"\b([A-Z_]*(PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z_]*)\s*=\s*(\S+)",
    re.IGNORECASE,
)


class HardcodedSecretEnvRule(Rule):
    id = "DOCKER004"
    title = "Possible hard-coded secret in ENV/ARG"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _DOCKER
    rationale = (
        "Secrets baked into ENV or ARG are embedded in image layers and visible "
        "to anyone who can pull the image via 'docker history'. They cannot be "
        "rotated without a rebuild."
    )
    remediation = "Inject secrets at runtime via a secrets manager or orchestrator secret, not in the image."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for inst in _instructions(artifact):
            if inst.cmd not in {"ENV", "ARG"}:
                continue
            m = _SECRET_ENV_RE.search(inst.value)
            if not m:
                continue
            value = m.group(3).strip().strip("\"'")
            # Ignore build-arg placeholders / references, which are not literals.
            if value.startswith("$") or value in {"", "true", "false"}:
                continue
            yield self.finding(
                path=artifact.path,
                message=f"'{m.group(1)}' appears to be assigned a literal secret value",
                line=inst.line,
            )


class AddInsteadOfCopyRule(Rule):
    id = "DOCKER005"
    title = "ADD used where COPY is safer"
    severity = Severity.WARNING
    category = Category.MAINTAINABILITY
    applies_to = _DOCKER
    rationale = (
        "ADD has surprising behavior: it auto-extracts archives and can fetch "
        "remote URLs, which makes builds harder to reason about and can pull in "
        "unexpected content. COPY is explicit and predictable."
    )
    remediation = "Use COPY for local files; use an explicit RUN curl/tar when you truly need extraction."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for inst in _instructions(artifact):
            if inst.cmd == "ADD" and not inst.value.strip().startswith("--"):
                # A remote URL or archive is the risky case; flag ADD generally.
                yield self.finding(
                    path=artifact.path,
                    message="Prefer COPY over ADD unless you need URL fetch/auto-extract",
                    line=inst.line,
                )


for _rule in (
    LatestTagRule(),
    RootUserRule(),
    MissingHealthcheckRule(),
    HardcodedSecretEnvRule(),
    AddInsteadOfCopyRule(),
):
    registry.register(_rule)
