from pathlib import Path

from scanner.config import (
    DefaultsConfig,
    FieldHints,
    ScannerConfig,
    SourceConfig,
    SplunkConnectionConfig,
)
from scanner.orchestrator import run_scan
from scanner.renderers.markdown import render_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _config() -> ScannerConfig:
    return ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=100, sample_strategy="random", seed=1),
        field_hints=FieldHints(origin=["host"]),
        sources=[
            SourceConfig(
                name="clean_source",
                adapter="file",
                path=str(FIXTURES / "simple" / "records.jsonl"),
                owner="ops@example.com",
            )
        ],
    )


def test_render_markdown_includes_run_metadata_and_check_findings():
    cfg = _config()
    result = run_scan(cfg, config_path="cfg.yaml")
    md = render_markdown(result, cfg)

    assert "# SOC Agent Readiness Scanner Report" in md
    assert "clean_source" in md
    assert "C1 -- Event identification" in md
    assert "C4 -- Affected entity" in md
    assert "ops@example.com" in md


def test_render_markdown_recommendations_include_remediation_and_context_advisory():
    cfg = _config()
    md = render_markdown(run_scan(cfg, config_path="cfg.yaml"), cfg)
    # The simple fixture WARNs on C2 (small skew) and C7 (composite key
    # only), so there are check-backed recommendations to enrich...
    assert "  - Add: " in md
    assert "  - Enables: " in md
    assert "  - Where: " in md
    # ...and it carries none of the agent-context fields.
    assert "[ADVISORY] clean_source / CTX (Agent context fields)" in md
    assert "maintenance_window" in md


def test_render_markdown_surfaces_envelope_hint_with_the_fix():
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=100, sample_strategy="random", seed=1),
        sources=[
            SourceConfig(
                name="export",
                adapter="file",
                path=str(FIXTURES / "enveloped" / "splunk_export.jsonl"),
                owner="ops@example.com",
            )
        ],
    )
    md = render_markdown(run_scan(cfg, config_path="cfg.yaml"), cfg)
    assert "envelope key `result`" in md
    assert "record_root: result" in md


def test_render_markdown_handles_error_sources(monkeypatch):
    # No live Splunk here -- exercises rendering of a non-"ok" source, using
    # the credential guard as a convenient, deterministic way to produce one.
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        splunk=SplunkConnectionConfig(host="splunk.example.com"),
        sources=[
            SourceConfig(
                name="splunk_source",
                adapter="splunk",
                query="index=network",
                owner="ops@example.com",
            )
        ],
    )
    result = run_scan(cfg, config_path="cfg.yaml")
    md = render_markdown(result, cfg)

    assert "splunk_source" in md
    assert "error" in md
