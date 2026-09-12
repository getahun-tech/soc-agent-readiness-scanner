from pathlib import Path

from scanner.adapters.file import FileAdapter
from scanner.config import DefaultsConfig, ScannerConfig, SourceConfig
from scanner.identifier_resolver import IdentifierResolver

FIXTURES = Path(__file__).parent / "fixtures"


def _records(path: str, sample_size=100):
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


def test_presence_of_a_candidate_is_the_whole_signal():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    result = IdentifierResolver().resolve(records, ["host"])

    assert result.identifier_field == "host"
    assert result.note is None
    assert result.presence_count == 10
    assert result.presence_rate == 1.0
    assert result.distinct_value_count == 2  # web01, web02


def test_no_candidate_fields_configured():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    result = IdentifierResolver().resolve(records, [])

    assert result.identifier_field is None
    assert result.note == "no candidate identifier fields configured"
    assert result.presence_rate == 0.0


def test_candidate_absent_from_sample_names_what_was_tried():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    result = IdentifierResolver().resolve(records, ["does_not_exist_in_records"])

    assert result.identifier_field is None
    assert "does_not_exist_in_records" in result.note
    assert result.presence_count == 0


def test_presence_is_a_union_across_candidates_not_just_the_single_best_field():
    # 6 records have 'host' only, 4 have 'src' only -- no single field is
    # present in 100% of records, but every record has *some* origin
    # candidate present. Presence must reflect that union, not just
    # whichever single candidate happens to be most common ('host', 6/10).
    records = _records(str(FIXTURES / "mixed_origin_fields" / "records.jsonl"))
    result = IdentifierResolver().resolve(records, ["host", "src"])

    assert result.presence_count == 10
    assert result.presence_rate == 1.0
    assert result.identifier_field == "host"  # still the single most-common, for display/grouping
    assert result.distinct_value_count == 5  # web01, web02, 10.0.0.1, 10.0.0.2, 10.0.0.3


def test_presence_matches_candidate_regardless_of_field_name_casing():
    # Data uses 'Host' (capitalized); the candidate is 'host' (lowercase).
    records = _records(str(FIXTURES / "mixed_case_origin" / "records.jsonl"))
    result = IdentifierResolver().resolve(records, ["host"])

    assert result.presence_count == 3
    assert result.presence_rate == 1.0
    assert result.identifier_field == "host"


def test_empty_string_values_do_not_count_as_present():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    # 'user' is present in every record; pretend it's the candidate and
    # confirm the resolver counts values, not keys, via the empty-cell CSV.
    csv_records = _records(str(FIXTURES / "csv" / "records.csv"))
    result = IdentifierResolver().resolve(csv_records, ["dst"])
    assert result.presence_count == 4  # one row has an empty dst cell -> absent
    assert result.presence_rate == 0.8
    assert IdentifierResolver().resolve(records, ["user"]).presence_count == 10
