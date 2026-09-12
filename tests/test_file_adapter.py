from pathlib import Path

import pytest

from scanner.adapters.file import FileAdapter
from scanner.config import DefaultsConfig, ScannerConfig, SourceConfig
from scanner.exceptions import AdapterError

FIXTURES = Path(__file__).parent / "fixtures"


def _config(sample_size=100, sample_strategy="random", seed=42) -> ScannerConfig:
    return ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=sample_size, sample_strategy=sample_strategy, seed=seed),
        sources=[],
    )


def _source(path: str, **overrides) -> SourceConfig:
    return SourceConfig(
        name="test_source",
        adapter="file",
        path=path,
        owner="ops@example.com",
        **overrides,
    )


def test_fetch_sample_reads_all_records_when_under_limit():
    cfg = _config(sample_size=100)
    source = _source(str(FIXTURES / "simple" / "records.jsonl"))
    records_iter, meta = FileAdapter().fetch_sample(source, cfg)
    records = list(records_iter)
    assert len(records) == 10
    assert meta.population_size == 10
    assert meta.actual_size == 10
    assert meta.strategy == "random"
    assert meta.seed == 42


def test_fetch_sample_respects_limit():
    cfg = _config(sample_size=3)
    source = _source(str(FIXTURES / "simple" / "records.jsonl"))
    records_iter, meta = FileAdapter().fetch_sample(source, cfg)
    records = list(records_iter)
    assert len(records) == 3
    assert meta.population_size == 10
    assert meta.actual_size == 3


def test_fetch_sample_deterministic_for_same_seed():
    source = _source(str(FIXTURES / "simple" / "records.jsonl"))
    r1 = list(FileAdapter().fetch_sample(source, _config(sample_size=4, seed=7))[0])
    r2 = list(FileAdapter().fetch_sample(source, _config(sample_size=4, seed=7))[0])
    assert [r.raw_text for r in r1] == [r.raw_text for r in r2]


def test_fetch_sample_no_files_matched_raises():
    cfg = _config()
    source = _source(str(FIXTURES / "nonexistent" / "*.log"))
    with pytest.raises(AdapterError):
        FileAdapter().fetch_sample(source, cfg)


def test_fetch_sample_reads_multiple_glob_matched_files():
    cfg = _config(sample_size=100)
    source = _source(str(FIXTURES / "mixed_formats" / "*.log"))
    _records_iter, meta = FileAdapter().fetch_sample(source, cfg)
    assert meta.population_size == 7  # 5 lines in a.log + 2 in b.log
    assert len(meta.files_read) == 2


def test_parse_cascade_json_line():
    cfg = _config(sample_size=100)
    source = _source(str(FIXTURES / "simple" / "records.jsonl"))
    records = list(FileAdapter().fetch_sample(source, cfg)[0])
    r = next(r for r in records if "alice" in r.raw_text and r.origin_line_no == 1)
    assert r.structured is True
    assert r.parse_error is None
    assert r.parsed["host"] == "web01"
    assert r.parsed["user"] == "alice"


def test_parse_cascade_logfmt_line():
    cfg = _config(sample_size=100)
    source = _source(str(FIXTURES / "mixed_formats" / "*.log"))
    records = list(FileAdapter().fetch_sample(source, cfg)[0])
    r = next(r for r in records if r.raw_text.startswith("host=fw02"))
    assert r.structured is True
    assert r.parsed["host"] == "fw02"
    assert r.parsed["action"] == "block"


def test_parse_cascade_unstructured_fallback():
    cfg = _config(sample_size=100)
    source = _source(str(FIXTURES / "mixed_formats" / "*.log"))
    records = list(FileAdapter().fetch_sample(source, cfg)[0])
    r = next(r for r in records if "completely unstructured" in r.raw_text)
    assert r.structured is False
    assert r.parse_error is None
    assert "message" in r.parsed


# --- nested JSON ----------------------------------------------------------


def test_nested_json_is_flattened_to_dotted_keys():
    source = _source(str(FIXTURES / "nested" / "records.jsonl"))
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    r = next(r for r in records if r.origin_line_no == 1)
    assert r.structured is True
    assert r.parsed["destination.ip"] == "10.0.0.2"
    assert r.parsed["agent.hostname"] == "fw01"
    assert r.parsed["event.action"] == "allow"
    assert r.parsed["related.hosts"] == ["db01", "web01"]  # list kept whole
    assert "destination" not in r.parsed  # no dict-valued parent left behind
    assert "empty" not in r.parsed  # empty object carries no field


# --- record_root (envelope unwrapping) ------------------------------------


def test_without_record_root_envelope_fields_stay_prefixed():
    source = _source(str(FIXTURES / "enveloped" / "splunk_export.jsonl"))
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    r = records[0]
    assert "result.host" in r.parsed
    assert "host" not in r.parsed
    assert "preview" in r.parsed


def test_record_root_unwraps_envelope_and_discards_wrapper_keys():
    source = _source(str(FIXTURES / "enveloped" / "splunk_export.jsonl"), record_root="result")
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    for r in records:
        assert r.structured is True
        assert r.parse_error is None
        assert r.parsed["sourcetype"] == "WinEventLog:Security"
        assert "_time" in r.parsed
        assert "preview" not in r.parsed
        assert "offset" not in r.parsed


def test_record_root_missing_from_a_record_is_a_visible_parse_error():
    source = _source(str(FIXTURES / "enveloped" / "missing_root.jsonl"), record_root="result")
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    by_line = {r.origin_line_no: r for r in records}

    assert by_line[1].parse_error is None
    assert by_line[1].parsed["host"] == "srv01"

    # Missing entirely, and present-but-not-an-object: both flagged, both
    # still inspectable rather than dropped.
    for line_no in (2, 3):
        r = by_line[line_no]
        assert r.structured is False
        assert "record_root 'result'" in r.parse_error
        assert r.parsed["offset"] == line_no - 1


# --- CSV / TSV ------------------------------------------------------------


def test_csv_rows_are_records_with_header_as_field_names():
    source = _source(str(FIXTURES / "csv" / "records.csv"))
    records_iter, meta = FileAdapter().fetch_sample(source, _config())
    records = list(records_iter)
    assert meta.population_size == 5  # rows, not physical lines; trailing blank skipped
    assert len(records) == 5
    assert all(r.structured and r.parse_error is None for r in records)
    r = next(r for r in records if r.parsed["user"] == "alice" and r.parsed["action"] == "login")
    assert r.parsed["host"] == "web01"
    assert r.parsed["status"] == "success"


def test_csv_bom_does_not_leak_into_first_header_name():
    source = _source(str(FIXTURES / "csv" / "records.csv"))
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    assert "timestamp" in records[0].parsed
    assert not any(k.startswith("﻿") for k in records[0].parsed)


def test_csv_empty_cells_are_absent_fields_not_blank_values():
    source = _source(str(FIXTURES / "csv" / "records.csv"))
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    logout = next(r for r in records if r.parsed["action"] == "logout")
    assert "dst" not in logout.parsed
    assert "note" not in logout.parsed
    assert logout.parsed["status"] == "success"


def test_csv_quoted_multiline_cell_stays_one_record():
    source = _source(str(FIXTURES / "csv" / "records.csv"))
    records = list(FileAdapter().fetch_sample(source, _config())[0])
    bob = next(r for r in records if r.parsed["user"] == "bob")
    assert bob.parsed["note"] == "multi\nline note"
    # raw_text is the canonical re-serialization of the row, quoting intact.
    assert '"multi\nline note"' in bob.raw_text
    # origin_line_no is the physical line where the row ends, so the
    # profiler's within-file ordering still reflects file order.
    assert bob.origin_line_no == 4


def test_tsv_uses_tab_delimiter():
    source = _source(str(FIXTURES / "csv" / "records.tsv"))
    records_iter, meta = FileAdapter().fetch_sample(source, _config())
    records = list(records_iter)
    assert meta.population_size == 3
    assert {r.parsed["host"] for r in records} == {"web01", "web02"}
    assert all(set(r.parsed) == {"timestamp", "host", "action"} for r in records)
