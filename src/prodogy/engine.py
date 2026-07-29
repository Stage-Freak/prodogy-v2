"""Rule engine core: the ``Rule`` abstraction and a registry.

A rule is a small, deterministic unit that inspects a parsed artifact and yields
``Finding`` objects. Rules never call the network and never make pass/fail
decisions themselves — they simply report what they see. The scanner and the
configured gate threshold decide the build outcome.

Each rule declares the ``FileKind`` values it applies to so the scanner only
runs relevant rules against each file.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from prodogy.models import Category, FileKind, Finding, Severity


@dataclass
class ParsedArtifact:
    """A parsed file handed to rules.

    ``data`` is the parsed structure (a ruamel object for YAML that preserves
    line numbers, or a list of Dockerfile instruction dicts). ``lines`` is the
    raw text split into lines, useful for text-level checks and locating spans.
    ``parse_error`` is set when structured parsing failed, so a rule can flag
    an unparseable-but-important file rather than letting it pass silently.
    """

    path: str
    kind: FileKind
    data: object = None
    lines: list[str] = field(default_factory=list)
    raw: str = ""
    parse_error: str = ""


class Rule:
    """Base class for all rules.

    Subclasses set the class attributes and implement :meth:`check`.
    """

    id: str = ""
    title: str = ""
    severity: Severity = Severity.WARNING
    category: Category = Category.PRODUCTION_SAFETY
    applies_to: tuple[FileKind, ...] = ()
    # Default plain-language rationale. Enrichment may override per-finding.
    rationale: str = ""
    remediation: str = ""
    # Compliance control references this rule maps to (CIS, NSA/CISA, PCI...).
    compliance_refs: tuple[str, ...] = ()

    def applicable(self, kind: FileKind) -> bool:
        return kind in self.applies_to

    def check(self, artifact: ParsedArtifact) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    # Convenience factory so rules produce consistent findings.
    def finding(
        self,
        *,
        path: str,
        message: str,
        line: int | None = None,
        end_line: int | None = None,
        severity: Severity | None = None,
        rationale: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        from prodogy.models import Location

        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            category=self.category,
            location=Location(path=path, line=line, end_line=end_line),
            message=message,
            rationale=rationale if rationale is not None else self.rationale,
            remediation=remediation if remediation is not None else self.remediation,
            compliance_refs=list(self.compliance_refs),
        )


class RuleRegistry:
    """Holds all known rules and yields those applicable to a file kind."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._ids: set[str] = set()

    def register(self, rule: Rule) -> Rule:
        if not rule.id:
            raise ValueError(f"Rule {rule.__class__.__name__} is missing an id")
        if rule.id in self._ids:
            raise ValueError(f"Duplicate rule id: {rule.id}")
        self._ids.add(rule.id)
        self._rules.append(rule)
        return rule

    def for_kind(self, kind: FileKind) -> Iterator[Rule]:
        for rule in self._rules:
            if rule.applicable(kind):
                yield rule

    def all(self) -> list[Rule]:
        return list(self._rules)

    def __len__(self) -> int:
        return len(self._rules)


# A single shared registry populated at import time by the rule modules.
registry = RuleRegistry()


def load_default_rules() -> RuleRegistry:
    """Import rule modules so they register themselves, then return the registry."""
    # Imported for side effects (registration). Kept local to avoid import cycles.
    from prodogy.rules import (  # noqa: F401
        ansible_rules,
        ci_rules,
        docker_compose_rules,
        dockerfile_rules,
        general_rules,
        k8s_rules,
        monitoring_rules,
        secret_rules,
        terraform_rules,
    )

    return registry
