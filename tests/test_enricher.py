"""Tests for the LLM enrichment layer."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from prodogy.enricher import (
    Enricher,
    EnrichmentError,
    _build_project_context,
    _build_user_prompt,
    _count_tokens,
    _is_cache_valid,
    _load_cache,
    _parse_llm_response,
    _resolve_llm_config,
    _save_cache,
    _truncate_to_tokens,
)
from prodogy.models import (
    Category,
    Finding,
    Location,
    Report,
    Severity,
)


def _make_finding(
    rule_id: str = "DOCKER001",
    message: str = "uses latest",
    path: str = "Dockerfile",
    line: int = 1,
    llm_explanation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="latest tag",
        severity=Severity.ERROR,
        category=Category.DEPLOY_RISK,
        location=Location(path=path, line=line),
        message=message,
        rationale="deterministic rationale",
        remediation="pin the tag",
        llm_explanation=llm_explanation,
    )


# -----------------------------------------------------------------------
# Config resolution
# -----------------------------------------------------------------------


def test_resolve_llm_config_defaults():
    cfg = _resolve_llm_config()
    assert cfg["provider_url"] == "https://api.openai.com/v1"
    assert cfg["model"] == "gpt-4o-mini"
    assert cfg["api_key"] == ""


def test_resolve_llm_config_from_dict():
    cfg = _resolve_llm_config({"model": "claude-3", "api_key": "sk-test"})
    assert cfg["model"] == "claude-3"
    assert cfg["api_key"] == "sk-test"


def test_resolve_llm_config_from_env(monkeypatch):
    monkeypatch.setenv("PRODOGY_LLM_API_KEY", "sk-env")
    monkeypatch.setenv("PRODOGY_LLM_MODEL", "custom-model")
    cfg = _resolve_llm_config()
    assert cfg["api_key"] == "sk-env"
    assert cfg["model"] == "custom-model"


# -----------------------------------------------------------------------
# Token counting and truncation
# -----------------------------------------------------------------------


def test_count_tokens():
    assert _count_tokens("hello world") > 0
    assert _count_tokens("") == 1


def test_truncate_to_tokens():
    text = "a" * 1000
    result = _truncate_to_tokens(text, 100)
    assert len(result) < len(text)
    assert "[truncated]" in result


def test_truncate_to_tokens_no_truncation_needed():
    text = "short"
    result = _truncate_to_tokens(text, 1000)
    assert result == text


# -----------------------------------------------------------------------
# Cache
# -----------------------------------------------------------------------


def test_cache_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        cache_path = Path(tmp) / "cache.json"
        cache = {"key1": {"explanation": "hello", "_ts": 0}}
        _save_cache(cache_path, cache)
        loaded = _load_cache(cache_path)
        assert loaded == cache


def test_cache_invalid_json():
    with tempfile.TemporaryDirectory() as tmp:
        cache_path = Path(tmp) / "cache.json"
        cache_path.write_text("not json")
        loaded = _load_cache(cache_path)
        assert loaded == {}


def test_cache_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        cache_path = Path(tmp) / "nonexistent.json"
        loaded = _load_cache(cache_path)
        assert loaded == {}


def test_cache_ttl_valid():
    entry = {"explanation": "test", "_ts": 0}
    # Simulate a recent timestamp
    import time
    entry["_ts"] = time.time() - 100  # 100 seconds ago
    assert _is_cache_valid(entry) is True


def test_cache_ttl_expired():
    import time
    entry = {"explanation": "test", "_ts": time.time() - 86400 * 8}  # 8 days ago
    assert _is_cache_valid(entry) is False


# -----------------------------------------------------------------------
# Prompt building
# -----------------------------------------------------------------------


def test_build_user_prompt():
    findings = [_make_finding()]
    prompt = _build_user_prompt(findings, "/tmp")
    assert "DOCKER001" in prompt
    assert "uses latest" in prompt


def test_build_user_prompt_empty():
    prompt = _build_user_prompt([], "/tmp")
    assert "no findings" in prompt


def test_build_project_context_no_files():
    context = _build_project_context("/tmp/nonexistent")
    assert "no project context" in context


# -----------------------------------------------------------------------
# LLM response parsing
# -----------------------------------------------------------------------


def test_parse_llm_response_single():
    response = "DOCKER001: You should pin your base image to a specific version tag."
    result = _parse_llm_response(response, ["DOCKER001"])
    assert result["DOCKER001"] == "You should pin your base image to a specific version tag."


def test_parse_llm_response_indexed():
    """Parser should handle RULE_ID#INDEX format for unique per-finding tags."""
    response = (
        "DC002#0: Nginx is the reverse proxy...\n"
        "DC002#1: Redis handles session data...\n"
        "DC004#0: Nginx needs resource limits...\n"
        "DC004#1: Redis needs resource limits..."
    )
    result = _parse_llm_response(response, ["DC002#0", "DC002#1", "DC004#0", "DC004#1"])
    assert result["DC002#0"] == "Nginx is the reverse proxy..."
    assert result["DC002#1"] == "Redis handles session data..."
    assert result["DC004#0"] == "Nginx needs resource limits..."
    assert result["DC004#1"] == "Redis needs resource limits..."


def test_parse_llm_response_mixed_indexed_and_plain():
    """Parser should handle both indexed and plain RULE_ID formats."""
    response = (
        "DC002#0: Nginx is the reverse proxy...\n"
        "SECRET001: Rotate credentials.\n"
        "DC002#1: Redis handles session data..."
    )
    result = _parse_llm_response(response, ["DC002#0", "SECRET001", "DC002#1"])
    assert result["DC002#0"] == "Nginx is the reverse proxy..."
    assert result["SECRET001"] == "Rotate credentials."
    assert result["DC002#1"] == "Redis handles session data..."


def test_parse_llm_response_multiple():
    response = (
        "DOCKER001: Pin your image.\n"
        "K8S001: Add resource limits.\n"
        "SECRET001: Rotate credentials."
    )
    result = _parse_llm_response(response, ["DOCKER001", "K8S001", "SECRET001"])
    assert result["DOCKER001"] == "Pin your image."
    assert result["K8S001"] == "Add resource limits."
    assert result["SECRET001"] == "Rotate credentials."


def test_parse_llm_response_multiline():
    response = (
        "DOCKER001: This is a multi-line explanation.\n"
        "It continues here and should be part of the same finding."
    )
    result = _parse_llm_response(response, ["DOCKER001"])
    assert "multi-line" in result["DOCKER001"]
    assert "continues here" in result["DOCKER001"]


def test_parse_llm_response_unknown_rule():
    response = "UNKNOWN001: some explanation"
    result = _parse_llm_response(response, ["DOCKER001"])
    # Unknown rule IDs are not matched by the parser.
    # The fallback assigns the full response to the first finding only if
    # NO known rules were matched at all — this is intentional to avoid
    # losing model output that didn't follow the RULE_ID: format.
    assert "DOCKER001" in result  # fallback assignment
    assert "some explanation" in result["DOCKER001"]


def test_parse_llm_response_empty():
    result = _parse_llm_response("", ["DOCKER001"])
    assert result == {}


# -----------------------------------------------------------------------
# Enricher — unconfigured
# -----------------------------------------------------------------------


def test_enricher_unconfigured_returns_report_unchanged():
    enricher = Enricher(config={"llm": {"api_key": ""}})
    report = Report()
    report.recompute_summary()
    result = enricher.enrich_report(report)
    assert result is report


def test_enricher_is_configured_false():
    enricher = Enricher(config={"llm": {"api_key": ""}})
    assert enricher.is_configured() is False


def test_enricher_is_configured_true():
    enricher = Enricher(config={"llm": {"api_key": "sk-test"}})
    assert enricher.is_configured() is True


# -----------------------------------------------------------------------
# Enricher — with mocked LLM
# -----------------------------------------------------------------------


def test_enricher_enriches_findings():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding())
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = "DOCKER001: Pin your base image to avoid silent upstream changes."
            result = enricher.enrich_report(report)

        finding = result.active_findings()[0]
        assert finding.llm_explanation == "Pin your base image to avoid silent upstream changes."


def test_enricher_skips_already_enriched():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding(llm_explanation="already enriched"))
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            result = enricher.enrich_report(report)

        mock_call.assert_not_called()
        assert result.active_findings()[0].llm_explanation == "already enriched"


def test_enricher_caches_results():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding())
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = "DOCKER001: First enrichment."
            enricher.enrich_report(report)

        # Second call should use cache
        with patch("prodogy.enricher._call_llm") as mock_call2:
            enricher.enrich_report(report)

        mock_call2.assert_not_called()


def test_enricher_force_re_enrich():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding())
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = "DOCKER001: First enrichment."
            enricher.enrich_report(report)

        with patch("prodogy.enricher._call_llm") as mock_call2:
            mock_call2.return_value = "DOCKER001: Second enrichment."
            enricher.enrich_report(report, only_unenriched=False)

        mock_call2.assert_called_once()


def test_enricher_no_findings():
    enricher = Enricher(config={"llm": {"api_key": "sk-test"}})
    report = Report()
    result = enricher.enrich_report(report)
    assert result is report


def test_enricher_all_suppressed():
    enricher = Enricher(config={"llm": {"api_key": "sk-test"}})
    report = Report()
    f = _make_finding()
    f.suppressed = True
    report.findings.append(f)
    report.recompute_summary()

    with patch("prodogy.enricher._call_llm") as mock_call:
        enricher.enrich_report(report)

    mock_call.assert_not_called()


def test_enricher_clear_cache():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        enricher._cache["key1"] = {"explanation": "test", "_ts": 0}
        count = enricher.clear_cache()
        assert count == 1
        assert len(enricher._cache) == 0


def test_enricher_cache_stats():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        import time
        enricher._cache["key1"] = {"explanation": "test", "_ts": time.time()}
        stats = enricher.cache_stats()
        assert stats["total_entries"] == 1
        assert stats["valid_entries"] == 1
        assert "cache_file" in stats


# -----------------------------------------------------------------------
# Enricher — error handling
# -----------------------------------------------------------------------


def test_enricher_handles_llm_error():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding())
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.side_effect = EnrichmentError("API timeout")
            with pytest.raises(EnrichmentError, match="API timeout"):
                enricher.enrich_report(report)


def test_enricher_missing_openai_package():
    enricher = Enricher(config={"llm": {"api_key": "sk-test"}})
    report = Report()
    report.findings.append(_make_finding())
    report.recompute_summary()

    with patch("prodogy.enricher._call_llm") as mock_call:
        mock_call.side_effect = EnrichmentError(
            "The 'openai' package is required for LLM enrichment."
        )
        with pytest.raises(EnrichmentError):
            enricher.enrich_report(report)


# -----------------------------------------------------------------------
# Enricher — single finding enrichment
# -----------------------------------------------------------------------


def test_enricher_enrich_single():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        f = _make_finding()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = "DOCKER001: Pin your image."
            explanation = enricher.enrich_single(f)

        # Parser strips the rule ID prefix, so only the explanation text remains.
        assert explanation == "Pin your image."
        assert f.llm_explanation == "Pin your image."


def test_enricher_enrich_single_cached():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        f = _make_finding()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = "DOCKER001: First."
            enricher.enrich_single(f)

        with patch("prodogy.enricher._call_llm") as mock_call2:
            enricher.enrich_single(f)

        mock_call2.assert_not_called()


def test_enricher_enrich_single_unconfigured():
    enricher = Enricher(config={"llm": {"api_key": ""}})
    f = _make_finding()
    explanation = enricher.enrich_single(f)
    assert explanation == ""


# -----------------------------------------------------------------------
# Enricher — multiple findings with different rule IDs
# -----------------------------------------------------------------------


def test_enricher_handles_different_rule_ids():
    with tempfile.TemporaryDirectory() as tmp:
        enricher = Enricher(
            config={"llm": {"api_key": "sk-test"}},
            root=tmp,
        )
        report = Report()
        report.findings.append(_make_finding(rule_id="DOCKER001", path="Dockerfile"))
        report.findings.append(_make_finding(rule_id="K8S001", path="deployment.yaml"))
        report.recompute_summary()

        with patch("prodogy.enricher._call_llm") as mock_call:
            mock_call.return_value = (
                "DOCKER001: Pin your base image.\n"
                "K8S001: Add resource limits to prevent OOM kills."
            )
            result = enricher.enrich_report(report)

        findings = result.active_findings()
        explanations = {f.rule_id: f.llm_explanation for f in findings}
        assert "Pin your base image" in explanations["DOCKER001"]
        assert "resource limits" in explanations["K8S001"]


# -----------------------------------------------------------------------
# Enricher — cache file path
# -----------------------------------------------------------------------


def test_cache_path():
    from prodogy.enricher import _cache_path

    with tempfile.TemporaryDirectory() as tmp:
        cp = _cache_path(tmp)
        assert str(cp).endswith(".prodogy-enrich-cache.json")


# -----------------------------------------------------------------------
# Enricher — project context gathering
# -----------------------------------------------------------------------


def test_project_context_reads_config():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cfg = tmp_path / ".prodogy.yml"
        cfg.write_text("disabled_rules: [K8S004]\n")
        context = _build_project_context(tmp)
        assert "disabled_rules" in context


def test_project_context_reads_readme():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        readme = tmp_path / "README.md"
        readme.write_text("# My Project\n\nA test project.")
        context = _build_project_context(tmp)
        assert "My Project" in context
