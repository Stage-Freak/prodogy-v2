"""CI/CD pipeline rules for GitHub Actions and GitLab CI.

These target the mistakes that make pipelines insecure or brittle: unpinned
third-party actions (supply-chain risk), and secrets echoed/hard-coded in
pipeline definitions.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.rules import yaml_nav as nav

_GHA = (FileKind.GITHUB_ACTIONS,)
_CI = (FileKind.GITHUB_ACTIONS, FileKind.GITLAB_CI)

# A version reference that is a full 40-char commit SHA is considered pinned.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class UnpinnedActionRule(Rule):
    id = "CI001"
    title = "Third-party action not pinned to a commit SHA"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _GHA
    rationale = (
        "A GitHub Action referenced by a mutable tag (e.g. '@v3') can be changed "
        "under you by its maintainer or an attacker who compromises the repo. "
        "Since actions run with access to your secrets and code, this is a real "
        "supply-chain risk. Pinning to a full commit SHA makes it immutable."
    )
    remediation = "Pin actions to a full 40-character commit SHA, e.g. 'actions/checkout@<sha>'."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            jobs = nav.get(doc, "jobs") or {}
            if not hasattr(jobs, "items"):
                continue
            for _job_name, job in jobs.items():
                steps = nav.get(job, "steps") or []
                for step in steps:
                    uses = nav.get(step, "uses")
                    if not uses or not isinstance(uses, str):
                        continue
                    # Local (./path) and docker:// refs are out of scope here.
                    if uses.startswith("./") or uses.startswith("docker://"):
                        continue
                    ref = uses.rsplit("@", 1)[-1] if "@" in uses else ""
                    if not _SHA_RE.match(ref):
                        line = nav.node_line(step)
                        yield self.finding(
                            path=artifact.path,
                            message=f"Action '{uses}' is not pinned to a commit SHA",
                            line=line,
                        )


_SECRET_LITERAL_RE = re.compile(
    r"\b([A-Za-z0-9_]*(PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_]*)\s*[:=]\s*"
    r"['\"]?([^\s'\"$#{]{8,})",
    re.IGNORECASE,
)


class HardcodedCISecretRule(Rule):
    id = "CI002"
    title = "Possible hard-coded secret in pipeline"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _CI
    rationale = (
        "Secrets written directly into a pipeline file are committed to the "
        "repository history and visible in logs. Pipelines should read secrets "
        "from the CI provider's encrypted secret store instead."
    )
    remediation = "Move the value to CI secrets (GitHub 'secrets.*' / GitLab CI variables) and reference it."

    # Values that are obviously references, not literals.
    _SAFE_PREFIXES = ("${{", "$", "{{")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for i, line in enumerate(artifact.lines, start=1):
            m = _SECRET_LITERAL_RE.search(line)
            if not m:
                continue
            value = m.group(3).strip()
            if any(value.startswith(p) for p in self._SAFE_PREFIXES):
                continue
            if value.lower() in {"changeme", "example", "placeholder", "true", "false"}:
                continue
            yield self.finding(
                path=artifact.path,
                message=f"'{m.group(1)}' appears to hold a literal secret value",
                line=i,
            )


class OverlyBroadPermissionsRule(Rule):
    id = "CI003"
    title = "Workflow grants overly broad permissions"
    severity = Severity.ERROR
    category = Category.PRODUCTION_SAFETY
    applies_to = _GHA
    rationale = (
        "'permissions: write-all' (or an unset top-level permissions block, which "
        "inherits broad defaults) gives every job — and every third-party action "
        "it runs — write access to the repo and its tokens. A compromised action "
        "can then push code or steal secrets. Least privilege limits the blast "
        "radius."
    )
    remediation = "Set an explicit least-privilege 'permissions:' block (default to 'contents: read')."
    compliance_refs = ("SLSA-build-L2", "SOC2-CC6.1")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            if not hasattr(doc, "get"):
                continue
            perms = nav.get(doc, "permissions")
            if perms == "write-all":
                line = nav.key_line(doc, "permissions") or nav.node_line(doc)
                yield self.finding(
                    path=artifact.path,
                    message="Top-level 'permissions: write-all' grants excessive access",
                    line=line,
                )
            elif perms is None and nav.get(doc, "jobs"):
                # No explicit permissions block -> inherits broad default token scope.
                yield self.finding(
                    path=artifact.path,
                    message="No explicit 'permissions:' block; workflow inherits broad default token scope",
                    line=1,
                    severity=Severity.WARNING,
                )


class PullRequestTargetCheckoutRule(Rule):
    id = "CI004"
    title = "pull_request_target checks out untrusted PR code"
    severity = Severity.CRITICAL
    category = Category.PRODUCTION_SAFETY
    applies_to = _GHA
    rationale = (
        "'pull_request_target' runs with a read/write token and access to secrets "
        "in the context of the base repo. Checking out the PR head in that context "
        "runs untrusted contributor code with those privileges — the single most "
        "exploited GitHub Actions vulnerability class."
    )
    remediation = (
        "Avoid checking out PR head under pull_request_target, or split into a "
        "privileged job that never runs untrusted code and an unprivileged one that does."
    )
    compliance_refs = ("SLSA-source", "SOC2-CC7.1")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            if not hasattr(doc, "get"):
                continue
            # 'on' may parse as bool True in YAML; check both.
            triggers = nav.get(doc, "on")
            if triggers is None:
                triggers = nav.get(doc, True)
            if not self._uses_pr_target(triggers):
                continue
            jobs = nav.get(doc, "jobs") or {}
            if not hasattr(jobs, "items"):
                continue
            for _job_name, job in jobs.items():
                for step in nav.get(job, "steps") or []:
                    uses = nav.get(step, "uses") or ""
                    ref = nav.get(step, "with", "ref")
                    if isinstance(uses, str) and uses.startswith("actions/checkout"):
                        if ref and ("head" in str(ref).lower() or "event.pull_request" in str(ref)):
                            yield self.finding(
                                path=artifact.path,
                                message="checkout of PR head under pull_request_target runs untrusted code",
                                line=nav.node_line(step),
                            )

    @staticmethod
    def _uses_pr_target(triggers) -> bool:
        if triggers is None:
            return False
        if isinstance(triggers, str):
            return triggers == "pull_request_target"
        if isinstance(triggers, list):
            return "pull_request_target" in triggers
        if hasattr(triggers, "get"):
            return "pull_request_target" in triggers
        return False


class MissingJobTimeoutRule(Rule):
    id = "CI005"
    title = "Job has no timeout limit"
    severity = Severity.WARNING
    category = Category.DEPLOY_RISK
    applies_to = _GHA
    rationale = (
        "A job without a timeout can hang indefinitely, consuming CI minutes "
        "and blocking the queue. GitHub's default timeout is 6 hours — far "
        "longer than most jobs need."
    )
    remediation = "Set 'timeout-minutes' on each job (e.g. timeout-minutes: 15)."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            jobs = nav.get(doc, "jobs") or {}
            if not hasattr(jobs, "items"):
                continue
            for job_name, job in jobs.items():
                if nav.get(job, "timeout-minutes") is None:
                    line = nav.key_line(jobs, job_name) or nav.node_line(job)
                    yield self.finding(
                        path=artifact.path,
                        message=f"Job '{job_name}' has no timeout-minutes set",
                        line=line,
                    )


class ArtifactRetentionRule(Rule):
    id = "CI006"
    title = "Artifact upload has no retention limit"
    severity = Severity.INFO
    category = Category.DEPLOY_RISK
    applies_to = _GHA
    rationale = (
        "Artifacts without a retention period use GitHub's default (90 days), "
        "which may store sensitive build outputs longer than needed."
    )
    remediation = "Set 'retention-days' on upload-artifact steps."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            jobs = nav.get(doc, "jobs") or {}
            if not hasattr(jobs, "items"):
                continue
            for _job_name, job in jobs.items():
                for step in nav.get(job, "steps") or []:
                    uses = nav.get(step, "uses") or ""
                    if isinstance(uses, str) and "upload-artifact" in uses:
                        if nav.get(step, "with", "retention-days") is None:
                            line = nav.node_line(step)
                        yield self.finding(
                            path=artifact.path,
                            message="upload-artifact has no retention-days limit",
                            line=line,
                        )


for _rule in (
    UnpinnedActionRule(),
    HardcodedCISecretRule(),
    OverlyBroadPermissionsRule(),
    PullRequestTargetCheckoutRule(),
    MissingJobTimeoutRule(),
    ArtifactRetentionRule(),
):
    registry.register(_rule)
