from pathlib import Path

from scanner.adapters.file import FileAdapter
from scanner.asset_resolver import AssetResolver
from scanner.config import DefaultsConfig, ScannerConfig, SourceConfig

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


def test_no_inventory_configured_is_explicit_not_a_silent_pass():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    resolver = AssetResolver(None, [])
    result = resolver.resolve(records, ["host"])

    assert result.inventory_loaded is False
    assert "no inventory" in result.inventory_note


def test_missing_inventory_file_is_reported_not_raised():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    resolver = AssetResolver(str(FIXTURES / "does_not_exist.csv"), ["hostname"])
    result = resolver.resolve(records, ["host"])

    assert result.inventory_loaded is False
    assert "not found" in result.inventory_note


def test_partial_attribution_against_inventory():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    resolver = AssetResolver(str(FIXTURES / "inventory.csv"), ["hostname", "serial", "mgmt_ip"])
    result = resolver.resolve(records, ["host"])

    assert result.inventory_loaded is True
    assert result.identifier_field == "host"
    assert result.presence_count == 10
    # web01 appears 6 times and is in the inventory; web02 appears 4 times and is not.
    assert result.matched_count == 6
    assert result.attributable_count == 6
    assert result.attributable_rate == 0.6
    assert result.distinct_value_count == 2
    assert "web02" in result.unmatched_examples


def test_no_candidate_fields_configured():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    resolver = AssetResolver(str(FIXTURES / "inventory.csv"), ["hostname"])
    result = resolver.resolve(records, [])

    assert result.identifier_field is None
    assert result.inventory_note == "no candidate identifier fields configured"


def test_presence_is_a_union_across_candidates_not_just_the_single_best_field():
    # 6 records have 'host' only, 4 have 'src' only -- no single field is
    # present in 100% of records, but every record has *some* origin
    # candidate present. Presence must reflect that union, not just
    # whichever single candidate happens to be most common ('host', 6/10).
    records = _records(str(FIXTURES / "mixed_origin_fields" / "records.jsonl"))
    resolver = AssetResolver(None, [])
    result = resolver.resolve(records, ["host", "src"])

    assert result.presence_count == 10
    assert result.presence_rate == 1.0
    assert result.identifier_field == "host"  # still the single most-common, for display/grouping
    assert result.distinct_value_count == 5  # web01, web02, 10.0.0.1, 10.0.0.2, 10.0.0.3


def test_inventory_match_is_a_union_across_candidates_too():
    # Inventory only lists the 'src' values -- a record matches if *any*
    # of its present candidate fields' values is a known asset, not only
    # whichever field was picked as the single representative one.
    records = _records(str(FIXTURES / "mixed_origin_fields" / "records.jsonl"))
    resolver = AssetResolver(str(FIXTURES / "inventory.csv"), ["hostname", "serial", "mgmt_ip"])
    result = resolver.resolve(records, ["host", "src"])

    # inventory.csv (used by test_partial_attribution_against_inventory)
    # contains 'web01' (4 records) but not 'web02' (2) or any 10.0.0.x
    # src value (4) -- only the 4 'web01' records match.
    assert result.matched_count == 4
    assert result.attributable_rate == 0.4


def test_presence_matches_candidate_regardless_of_field_name_casing():
    # Data uses 'Host' (capitalized); the candidate is 'host' (lowercase).
    records = _records(str(FIXTURES / "mixed_case_origin" / "records.jsonl"))
    resolver = AssetResolver(None, [])
    result = resolver.resolve(records, ["host"])

    assert result.presence_count == 3
    assert result.presence_rate == 1.0
    assert result.identifier_field == "host"


def test_candidate_field_absent_from_sample_with_inventory_loaded():
    records = _records(str(FIXTURES / "simple" / "records.jsonl"))
    resolver = AssetResolver(str(FIXTURES / "inventory.csv"), ["hostname"])
    result = resolver.resolve(records, ["does_not_exist_in_records"])

    assert result.identifier_field is None
    assert result.inventory_loaded is True
    assert result.attributable_count == 0
    assert result.attributable_rate == 0.0
