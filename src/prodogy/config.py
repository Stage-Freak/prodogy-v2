"""Configuration file support: ``.prodogy.yml``.

Teams need to customize behavior without editing source or scattering inline
suppressions. A ``.prodogy.yml`` at the repo root (or a path passed via
``--config``) can:

  * disable specific rules            (``disabled_rules: [K8S004]``)
  * override a rule's severity        (``severity_overrides: {DOCKER003: info}``)
  * exclude paths from scanning       (``exclude: ["**/vendor/**"]``)
  * set the default gate threshold    (``fail_on: critical``)
  * forbid suppression of categories  (``non_suppressible: [confidential]``)
  * configure LLM enrichment          (``llm: {model: gpt-4o-mini, ...}``)

The config is deliberately small, declarative, and validated. Unknown keys are
reported so typos do not silently no-op. All fields are optional; an absent
config means "use defaults", so the tool works with zero configuration.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from prodogy.models import Category, Severity

_yaml = YAML(typ="safe")

CONFIG_FILENAMES = (".prodogy.yml", ".prodogy.yaml")


class ConfigError(Exception):
    """Raised when a config file is present but invalid."""


class LlmConfig(BaseModel):
    """LLM enrichment configuration.

    All fields are optional — when no API key is provided, enrichment is
    simply skipped (the tool works perfectly without it).
    """

    model_config = {"extra": "forbid"}

    # OpenAI-compatible endpoint URL. Defaults to OpenAI's official API.
    provider_url: str = ""
    # Model to use. Defaults to gpt-4o-mini (fast, cheap).
    model: str = ""
    # API key. Can also be set via PRODOGY_LLM_API_KEY env var.
    api_key: str = ""


class Config(BaseModel):
    """Validated Prodogy configuration."""

    model_config = {"extra": "forbid"}  # reject unknown keys (catch typos)

    disabled_rules: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    exclude: list[str] = Field(default_factory=list)
    fail_on: Severity | None = None
    # Categories whose findings may never be suppressed via inline comments.
    # Defaults to protecting confidential findings (the "never auto-approve"
    # trust guarantee flagged by the security review).
    non_suppressible: list[Category] = Field(
        default_factory=lambda: [Category.CONFIDENTIAL]
    )
    # LLM enrichment configuration. When api_key is empty, enrichment is skipped.
    llm: LlmConfig = Field(default_factory=LlmConfig)

    @field_validator("llm", mode="before")
    @classmethod
    def _coerce_llm(cls, v):
        # YAML `llm:` (no value) parses as None — treat as empty config.
        if v is None:
            return {}
        return v

    # ---- helpers used by the scanner ---------------------------------------

    def is_rule_disabled(self, rule_id: str) -> bool:
        return rule_id in self.disabled_rules

    def severity_for(self, rule_id: str, default: Severity) -> Severity:
        return self.severity_overrides.get(rule_id, default)

    def is_excluded(self, rel_path: str) -> bool:
        norm = rel_path.replace("\\", "/")
        name = Path(norm).name
        for pat in self.exclude:
            if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(name, pat):
                return True
            # Support a leading '**/' recursive prefix (common glob idiom that
            # fnmatch does not natively handle): '**/skip/**' should match
            # 'skip/x' as well as 'a/b/skip/x'.
            if pat.startswith("**/") and fnmatch.fnmatch(norm, pat[3:]):
                return True
        return False

    def category_is_protected(self, category: Category) -> bool:
        return category in self.non_suppressible

    def is_llm_configured(self) -> bool:
        """Whether LLM enrichment is configured with an API key."""
        key = self.llm.api_key or ""
        return bool(key)


def find_config(root: Path) -> Path | None:
    """Locate a config file at the scan root, if present."""
    for name in CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> Config:
    """Load and validate a config file. Returns defaults when ``path`` is None."""
    if path is None:
        return Config()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config {path}: {exc}") from exc
    try:
        data = _yaml.load(raw) or {}
    except YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config {path} must be a mapping at the top level.")
    try:
        return Config(**data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid config {path}:\n{exc}") from exc


def resolve_config(root: Path, explicit: Path | None = None) -> Config:
    """Resolve config from an explicit path or by discovery at ``root``."""
    if explicit is not None:
        return load_config(explicit)
    return load_config(find_config(root))
