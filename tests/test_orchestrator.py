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
    assert set(src["checks"].keys()) == {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
    # No affected-entity field hint was configured explicitly, but 'user' is
    # in FieldHints' own built-in default affected-entity candidates and is
    # present, distinct from origin ('host') -> C4 finds it and PASSes.
    assert src["checks"]["C4"]["status"] == "PASS"

    # event_class undeclared -> C8 runs advisory-only and stays unscored.
    assert src["checks"]["C8"]["status"] == "NOT_ASSESSED"
    assert src["verdict"]["completeness"]["denominator"] == 6  # C6 excluded, C8 not assessed
    # C2 WARN (small clock-skew between 'web01'/'web02' origins in this
    # fixture) alone blocks eligibility.
    assert src["verdict"]["eligibility"]["eligible"] is False

    assert result["estate_summary"]["sources_scanned"] == 1
    assert result["estate_summary"]["ineligible_count"] == 1
    assert isinstance(result["conflicts"], list)
    assert isinstance(result["recommendations"], list)


def _export_config(**source_kwargs) -> ScannerConfig:
    return ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=100, sample_strategy="random", seed=1),
        field_hints=FieldHints(origin=["host"]),
        sources=[
            SourceConfig(
                name="export",
                adapter="file",
                path=str(FIXTURES / "enveloped" / "splunk_export.jsonl"),
                owner="ops@example.com",
                **source_kwargs,
            )
        ],
    )


def test_enveloped_export_is_flagged_and_c5_no_longer_false_passes_on_the_wrapper():
    # Regression for a real bug: a Splunk export's wrapper key 'result'
    # (holding the whole event) used to match C5's 'result' outcome
    # candidate by name and produce a confident, wrong PASS. Flattening
    # removes the dict-valued key, so C5 now honestly finds nothing --
    # and the report names the envelope so the operator knows what to do.
    result = run_scan(_export_config(), config_path="cfg.yaml")
    src = result["sources"]["export"]
    assert src["profile"]["envelope_hint"] == "result"
    assert src["checks"]["C5"]["status"] == "FAIL"
    assert src["checks"]["C5"]["evidence"].get("field") is None


def test_record_root_unwraps_export_so_every_check_sees_real_fields():
    result = run_scan(_export_config(record_root="result"), config_path="cfg.yaml")
    src = result["sources"]["export"]
    assert src["profile"]["envelope_hint"] is None
    assert src["profile"]["parse_rate"] == 1.0

    checks = src["checks"]
    assert checks["C2"]["evidence"]["field"] == "_time"
    assert checks["C2"]["status"] == "PASS"  # tz-explicit, ingest via _indextime, no skew
    assert checks["C4"]["status"] == "PASS"  # 'dst' present, distinct from origin 'host'
    # 'action' and 'status' are both 100% present and both outcome
    # candidates; candidate order breaks the tie. Either is a real field
    # from inside the envelope -- the point is that it's no longer the
    # wrapper key.
    assert checks["C5"]["evidence"]["field"] in ("action", "status")
    assert checks["C5"]["status"] == "PASS"
    assert checks["C8"]["evidence"]["field"] == "user"  # found, advisory (event_class undeclared)
    assert src["verdict"]["eligibility"]["eligible"] is True


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
