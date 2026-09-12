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
    assert profile.envelope_hint is None


def test_envelope_hint_names_the_wrapper_key_of_an_enveloped_export():
    # Splunk's JSON export: two transport keys + everything under 'result'.
    records = _load(str(FIXTURES / "enveloped" / "splunk_export.jsonl"))
    profile = Profiler().profile("enveloped", records)
    assert profile.envelope_hint == "result"
    # And the timestamp is invisible until the envelope is unwrapped.
    assert profile.timestamp_analysis.candidate_field is None


def test_envelope_hint_is_none_for_flat_and_for_genuinely_nested_schemas():
    assert Profiler().profile("flat", _load(str(FIXTURES / "simple" / "records.jsonl"))).envelope_hint is None
    # ECS spreads fields across many prefixes (event.*, source.*,
    # destination.*, agent.*) -- no single one dominates, so no hint.
    nested = Profiler().profile("nested", _load(str(FIXTURES / "nested" / "records.jsonl")))
    assert nested.envelope_hint is None
    assert nested.field_stats["destination.ip"].presence_rate == 1.0


def test_platform_native_timestamp_names_are_recognized():
    # `_time` is what a Splunk export carries; only the Splunk *adapter*
    # aliases it to `timestamp`, a file export still has the raw name.
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=100, sample_strategy="random", seed=1),
        sources=[],
    )
    source = SourceConfig(
        name="s",
        adapter="file",
        path=str(FIXTURES / "enveloped" / "splunk_export.jsonl"),
        owner="ops@example.com",
        record_root="result",
    )
    records = list(FileAdapter().fetch_sample(source, cfg)[0])
    ts = Profiler().profile("s", records).timestamp_analysis
    assert ts.candidate_field == "_time"
    assert ts.parse_rate == 1.0
    assert ts.explicit_timezone_rate == 1.0
