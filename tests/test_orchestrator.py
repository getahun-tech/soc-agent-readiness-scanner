from pathlib import Path

from scanner.config import (
    DefaultsConfig,
    FieldHints,
    ScannerConfig,
    SourceConfig,
    SplunkConnectionConfig,
)
from scanner.orchestrator import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


def _config(**source_kwargs) -> ScannerConfig:
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
                **source_kwargs,
            )
        ],
    )


def test_run_scan_wires_completeness_checks_for_file_sources():
    cfg = _config()
    result = run_scan(cfg, config_path="cfg.yaml")

    src = result["sources"]["clean_source"]
    assert src["status"] == "ok"
    assert set(src["checks"].keys()) == {"C1", "C2", "C3", "C4", "C5", "C6", "C7"}
    # No affected-entity field hint was configured explicitly, but 'user' is
    # in FieldHints' own built-in default affected-entity candidates and is
    # present, distinct from origin ('host') -> C4 finds it and PASSes.
    assert src["checks"]["C4"]["status"] == "PASS"

    assert src["verdict"]["completeness"]["denominator"] == 6  # C6 excluded
    # C2 WARN (small clock-skew between 'web01'/'web02' origins in this
    # fixture) alone blocks eligibility.
    assert src["verdict"]["eligibility"]["eligible"] is False

    assert result["estate_summary"]["sources_scanned"] == 1
    assert result["estate_summary"]["ineligible_count"] == 1
    assert isinstance(result["conflicts"], list)
    assert isinstance(result["recommendations"], list)


def test_run_scan_reports_splunk_source_without_token_as_error(monkeypatch):
    # No live Splunk here -- this only exercises the credential guard.
    # See test_splunk_adapter.py for adapter behavior against a fake connection.
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
    src = result["sources"]["splunk_source"]
    assert src["status"] == "error"
    assert "SPLUNK_TOKEN" in src["error"]
    assert src["checks"] is None
    assert src["verdict"] is None
    # error sources don't participate in estate-level aggregation.
    assert result["estate_summary"]["sources_scanned"] == 0
