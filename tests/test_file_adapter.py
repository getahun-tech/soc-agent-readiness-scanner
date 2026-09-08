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
