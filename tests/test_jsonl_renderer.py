"""JSONL renderer: one event per line, shaped for SIEM re-ingestion.

Every assertion here is about the *contract* a downstream indexer relies
on -- each line parses alone, event_type partitions cleanly, run_id ties
a run's lines together -- not just "it doesn't crash."
"""

import json
from pathlib import Path

from scanner.config import DefaultsConfig, FieldHints, ScannerConfig, SourceConfig
from scanner.orchestrator import run_scan
from scanner.renderers.jsonl import render_jsonl

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


def _lines(cfg: ScannerConfig) -> list[dict]:
    result = run_scan(cfg, config_path="cfg.yaml")
    text = render_jsonl(result, cfg)
    assert text.endswith("\n")
    raw_lines = text.rstrip("\n").split("\n")
    return [json.loads(line) for line in raw_lines]


def test_every_line_is_independently_parseable_json():
    text = render_jsonl(run_scan(_config(), config_path="cfg.yaml"), _config())
    for line in text.rstrip("\n").split("\n"):
        json.loads(line)  # raises if any line isn't self-contained JSON


def test_exactly_one_scan_event_and_one_source_summary_per_source():
    events = _lines(_config())
    by_type: dict[str, list[dict]] = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)

    assert len(by_type["scan"]) == 1
    assert len(by_type["source_summary"]) == 1
    assert by_type["source_summary"][0]["source"] == "clean_source"
    # C1-C5, C7 always assessed for this fixture; C6 excluded by scoring,
    # C8 present but NOT_ASSESSED (event_class undeclared) -- still one
    # check_result per check the orchestrator actually ran.
    assert {c["check_id"] for c in by_type["check_result"]} == {
        "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"
    }
    assert all(c["source"] == "clean_source" for c in by_type["check_result"])


def test_run_id_ties_every_line_from_one_run_together_and_differs_across_runs():
    events = _lines(_config())
    run_ids = {e["run_id"] for e in events}
    assert len(run_ids) == 1
    times = {e["time"] for e in events}
    assert len(times) == 1

    other_run = _lines(_config())
    assert other_run[0]["run_id"] != events[0]["run_id"]  # generated_at differs


def test_source_summary_carries_score_eligibility_and_gates():
    events = _lines(_config())
    summary = next(e for e in events if e["event_type"] == "source_summary")
    assert summary["completeness_denominator"] == 6
    assert isinstance(summary["completeness_score"], float)
    assert summary["eligible"] is False  # small clock-skew WARN on C2 blocks it
    assert "C2" in summary["failed_gates"]
    assert summary["owner"] == "ops@example.com"
    assert summary["adapter"] == "file"


def test_check_result_carries_findings_and_evidence_verbatim():
    events = _lines(_config())
    c4 = next(e for e in events if e["event_type"] == "check_result" and e["check_id"] == "C4")
    assert c4["status"] in ("PASS", "WARN", "FAIL", "NOT_ASSESSED")
    assert isinstance(c4["findings"], list) and c4["findings"]
    assert isinstance(c4["evidence"], dict)


def test_recommendations_carry_remediation_and_error_sources_summarize_without_crashing(monkeypatch):
    from scanner.config import SplunkConnectionConfig

    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        splunk=SplunkConnectionConfig(host="splunk.example.com"),
        sources=[
            SourceConfig(name="ok", adapter="file", path=str(FIXTURES / "broken" / "broken.log"), owner="a@x.com"),
            SourceConfig(name="bad", adapter="splunk", query="index=x", owner="b@x.com"),
        ],
    )
    events = json.loads("[" + ",".join(render_jsonl(run_scan(cfg, config_path="c.yaml"), cfg).rstrip("\n").split("\n")) + "]")

    error_summary = next(e for e in events if e["event_type"] == "source_summary" and e["source"] == "bad")
    assert error_summary["status"] == "error"
    assert "SPLUNK_TOKEN" in error_summary["error"]
    assert "adapter" not in error_summary  # nothing to report for a source that never ran

    recs = [e for e in events if e["event_type"] == "recommendation" and e["source"] == "ok"]
    assert recs  # the broken fixture fails several checks
    assert any(r.get("remediation") for r in recs)


def test_log_profile_fields_reflect_detection():
    events = _lines(_config())
    summary = next(e for e in events if e["event_type"] == "source_summary")
    assert summary["log_profile_id"] is None  # simple fixture has no sourcetype-like field
    assert summary["log_profile_mixed"] is False
