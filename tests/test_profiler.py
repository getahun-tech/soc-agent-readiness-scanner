from pathlib import Path

from scanner.adapters.file import FileAdapter
from scanner.config import DefaultsConfig, ScannerConfig, SourceConfig
from scanner.profiler import Profiler

FIXTURES = Path(__file__).parent / "fixtures"


def _load(path: str, sample_size=100):
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=sample_size, sample_strategy="random", seed=1),
        sources=[],
    )
    source = SourceConfig(
        name="test_source",
        adapter="file",
        path=path,
        owner="ops@example.com",
    )
    records_iter, _ = FileAdapter().fetch_sample(source, cfg)
    return list(records_iter)


def test_profile_uniform_clean_source():
    records = _load(str(FIXTURES / "simple" / "records.jsonl"))
    profile = Profiler().profile("clean", records)

    assert profile.record_count == 10
    assert profile.parse_rate == 1.0
    assert profile.structured_rate == 1.0
    assert profile.distinct_field_sets == 1
    assert profile.dominant_field_set_rate == 1.0

    assert profile.field_stats["host"].presence_rate == 1.0
    assert profile.field_stats["host"].distinct_value_count == 2
    assert profile.field_stats["user"].distinct_value_count == 6
    assert profile.field_stats["action"].distinct_value_count == 2

    ts = profile.timestamp_analysis
    assert ts.candidate_field == "timestamp"
    assert ts.presence_rate == 1.0
    assert ts.parse_rate == 1.0
    assert ts.explicit_timezone_rate == 1.0
    assert ts.out_of_order_pairs == 0


def test_profile_mixed_formats_source():
    records = _load(str(FIXTURES / "mixed_formats" / "*.log"), sample_size=100)
    profile = Profiler().profile("mixed", records)

    assert profile.record_count == 7
    assert profile.structured_count == 6
    assert profile.distinct_field_sets == 2
    assert profile.dominant_field_set_rate == 6 / 7

    assert "message" in profile.field_stats
    assert profile.field_stats["message"].presence_count == 1
    assert profile.field_stats["host"].presence_count == 6

    ts = profile.timestamp_analysis
    assert ts.candidate_field == "timestamp"
    assert ts.presence_rate == 6 / 7
    assert ts.parse_rate == 1.0
    assert ts.out_of_order_pairs == 1
    assert ts.out_of_order_rate == 1 / 4


def test_profile_empty_sample_does_not_crash():
    profile = Profiler().profile("empty", [])
    assert profile.record_count == 0
    assert profile.parse_rate == 0.0
    assert profile.timestamp_analysis.candidate_field is None
