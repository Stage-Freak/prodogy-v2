"""General rules that apply across file kinds.

Currently: a rule that flags files which were meant to be parsed as structured
config but failed. A gate must never let an unparseable manifest pass silently —
that is exactly the kind of file that breaks a deploy.
"""

from __future__ import annotations

from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity

_STRUCTURED = (
    FileKind.K8S_DEPLOYMENT,
    FileKind.K8S_STATEFULSET,
    FileKind.K8S_MANIFEST,
    FileKind.HELM_VALUES,
    FileKind.GITHUB_ACTIONS,
    FileKind.GITLAB_CI,
    FileKind.DOCKER_COMPOSE,
    FileKind.GRAFANA,
    FileKind.PROMETHEUS,
    FileKind.ANSIBLE,
)


class UnparseableFileRule(Rule):
    id = "CORE001"
    title = "Config file could not be parsed"
    severity = Severity.ERROR
    category = Category.DEPLOY_RISK
    applies_to = _STRUCTURED
    rationale = (
        "A config file that fails to parse is almost certainly invalid and will "
        "be rejected at apply time, breaking the deploy. It also means no other "
        "rule could inspect it, so its real production-readiness is unknown."
    )
    remediation = "Fix the syntax error reported below and re-run the scan."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        if artifact.parse_error:
            yield self.finding(
                path=artifact.path,
                message=f"Failed to parse: {artifact.parse_error}",
                line=1,
            )


registry.register(UnparseableFileRule())
