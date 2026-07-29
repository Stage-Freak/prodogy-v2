"""Ansible playbook and role production-readiness rules.

These target Ansible playbooks (YAML) and inventory files for common
security and reliability misconfigurations.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from prodogy.engine import ParsedArtifact, Rule, registry
from prodogy.models import Category, FileKind, Finding, Severity
from prodogy.rules import yaml_nav as nav

_ANSIBLE = (FileKind.ANSIBLE,)


class AnsibleBecomeRootRule(Rule):
    id = "ANS001"
    title = "Playbook uses 'become: yes' without restricting to specific user"
    severity = Severity.WARNING
    category = Category.PRODUCTION_SAFETY
    applies_to = _ANSIBLE
    rationale = (
        "'become: yes' without 'become_user' escalates to root. Running tasks "
        "as root increases the blast radius of any task failure or compromised "
        "module. Explicitly specifying the target user limits blast radius."
    )
    remediation = "Set 'become_user: <specific_user>' instead of relying on root escalation."

    @staticmethod
    def _is_become(val) -> bool:
        return val is True or val == "yes" or val == "true"

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            # Handle both dict (single play) and list (multiple plays) formats
            plays = [doc] if hasattr(doc, "get") else (doc if isinstance(doc, list) else [])
            for play in plays:
                if not hasattr(play, "get"):
                    continue
                become = nav.get(play, "become")
                become_user = nav.get(play, "become_user")
                if self._is_become(become) and not become_user:
                    line = nav.key_line(play, "become") or nav.node_line(play)
                    yield self.finding(
                        path=artifact.path,
                        message="Playbook uses 'become: yes' without specifying 'become_user'",
                        line=line,
                    )
                roles = nav.get(play, "roles") or []
                if isinstance(roles, list):
                    for role in roles:
                        if isinstance(role, dict):
                            role_become = nav.get(role, "become")
                            role_user = nav.get(role, "become_user")
                            if self._is_become(role_become) and not role_user:
                                line = nav.key_line(role, "become") or nav.node_line(role)
                                role_name = nav.get(role, "role", default="?")
                                yield self.finding(
                                    path=artifact.path,
                                    message=f"Role '{role_name}' uses 'become: yes' without 'become_user'",
                                    line=line,
                                )


class AnsibleHardcodedSecretRule(Rule):
    id = "ANS002"
    title = "Possible hard-coded secret in playbook variables"
    severity = Severity.CRITICAL
    category = Category.CONFIDENTIAL
    applies_to = _ANSIBLE
    rationale = (
        "Secrets hardcoded in playbooks are committed to version control and "
        "visible to anyone with repo access. Ansible Vault or an external "
        "secrets manager should be used instead."
    )
    remediation = "Use 'ansible-vault encrypt' for sensitive vars, or reference external secrets via lookup plugins."

    _SECRET_KEY_RE = re.compile(
        r"([A-Za-z0-9_]*(password|secret|token|api_key|access_key|private_key)[A-Za-z0-9_]*)\s*:\s*(.+)",
        re.IGNORECASE,
    )
    _PLACEHOLDER = {"changeme", "example", "placeholder", "xxx", "todo", "vault_encrypted!"}
    _SAFE_PREFIXES = ("{{", "$", "lookup(", "vault(")

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        for i, line in enumerate(artifact.lines, start=1):
            m = self._SECRET_KEY_RE.search(line)
            if not m:
                continue
            value = m.group(3).strip().strip("\"'")
            if any(value.startswith(p) for p in self._SAFE_PREFIXES):
                continue
            if value.lower() in self._PLACEHOLDER:
                continue
            if len(value) < 4:
                continue
            yield self.finding(
                path=artifact.path,
                message=f"'{m.group(1)}' appears to contain a literal secret value",
                line=i,
            )


class AnsibleCommandInsteadOfModuleRule(Rule):
    id = "ANS003"
    title = "Playbook uses shell/command module instead of idempotent module"
    severity = Severity.INFO
    category = Category.MAINTAINABILITY
    applies_to = _ANSIBLE
    rationale = (
        "The 'shell' and 'command' modules are not idempotent — they run every "
        "time regardless of state. Using purpose-built modules (apt, yum, "
        "service, file, etc.) makes playbooks predictable and safe to re-run."
    )
    remediation = "Replace 'shell'/'command' with the appropriate idempotent Ansible module."

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:
        docs = artifact.data if isinstance(artifact.data, list) else []
        for doc in docs:
            plays = [doc] if hasattr(doc, "get") else (doc if isinstance(doc, list) else [])
            for play in plays:
                if not hasattr(play, "get"):
                    continue
                tasks = nav.get(play, "tasks") or []
                if not isinstance(tasks, list):
                    continue
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    if "shell" in task or "command" in task:
                        module = "shell" if "shell" in task else "command"
                        name = nav.get(task, "name", default="<unnamed>")
                        line = nav.key_line(task, module) or nav.node_line(task)
                        yield self.finding(
                            path=artifact.path,
                            message=f"Task '{name}' uses '{module}' module (not idempotent)",
                            line=line,
                        )


for _rule in (
    AnsibleBecomeRootRule(),
    AnsibleHardcodedSecretRule(),
    AnsibleCommandInsteadOfModuleRule(),
):
    registry.register(_rule)
