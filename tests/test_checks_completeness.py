from pathlib import Path

from scanner.checks.completeness.c1_event_identification import C1EventIdentification
from scanner.checks.completeness.c2_temporal import C2TemporalQuality
from scanner.checks.completeness.c3_location import C3EventLocation
from scanner.checks.completeness.c4_affected_entity import C4AffectedEntity
from scanner.checks.completeness.c5_outcome import C5Outcome
from scanner.checks.completeness.c6_causality import C6Causality
from scanner.checks.completeness.c7_correlatability import C7Correlatability
from tests.helpers import build_ctx as _ctx

FIXTURES = Path(__file__).parent / "fixtures"


# --- C1: event identification -------------------------------------------


def test_c1_pass_on_clean_bounded_event_types():
    ctx = _ctx(str(FIXTURES / "simple" / "records.jsonl"))
    r = C1EventIdentification().run(ctx)
    assert r.status == "PASS"


def test_c1_warn_on_partial_presence():
    ctx = _ctx(str(FIXTURES / "mixed_formats" / "*.log"))
    r = C1EventIdentification().run(ctx)
    assert r.status == "WARN"


def test_c1_fail_on_low_presence():
    ctx = _ctx(str(FIXTURES / "broken" / "broken.log"))
    r = C1EventIdentification().run(ctx)
    assert r.status == "FAIL"


def test_c1_warn_on_high_cardinality_despite_full_presence():
    ctx = _ctx(str(FIXTURES / "high_cardinality" / "records.jsonl"))
    r = C1EventIdentification().run(ctx)
    assert r.status == "WARN"
    assert r.evidence["identified_rate"] == 1.0
    assert r.evidence["high_cardinality"] is True


def test_c1_matches_candidate_regardless_of_field_name_casing():
    # Data uses 'Action' (capitalized); the candidate list has 'action'.
    ctx = _ctx(str(FIXTURES / "mixed_case_fields" / "records.jsonl"))
    r = C1EventIdentification().run(ctx)
    assert r.status == "PASS"
    assert r.evidence["field"] == "Action"  # reports the data's actual casing
    assert r.evidence["identified_rate"] == 1.0


# --- C2: temporal quality -------------------------------------------------


def test_c2_pass_when_clean_tz_explicit_and_ingest_present():
    ctx = _ctx(str(FIXTURES / "temporal" / "clean.jsonl"))
    r = C2TemporalQuality().run(ctx)
    assert r.status == "PASS"


def test_c2_warn_on_skew_under_threshold():
    ctx = _ctx(str(FIXTURES / "temporal" / "skew_warn.jsonl"), origin_hints=["host"])
    r = C2TemporalQuality().run(ctx)
    assert r.status == "WARN"
    assert r.evidence["skew_assessed"] is True
    assert 0 < r.evidence["max_abs_offset_seconds"] <= 5.0


def test_c2_fail_on_skew_above_threshold():
    ctx = _ctx(str(FIXTURES / "temporal" / "skew_fail.jsonl"), origin_hints=["host"])
    r = C2TemporalQuality().run(ctx)
    assert r.status == "FAIL"
    assert r.evidence["max_abs_offset_seconds"] > 5.0


def test_c2_fail_on_naive_timestamps():
    ctx = _ctx(str(FIXTURES / "temporal" / "naive.jsonl"))
    r = C2TemporalQuality().run(ctx)
    assert r.status == "FAIL"
    assert r.evidence["naive_count"] > 0


# --- C3: event location ----------------------------------------------------


def test_c3_pass_on_host_level_granularity():
    ctx = _ctx(str(FIXTURES / "simple" / "records.jsonl"))
    r = C3EventLocation().run(ctx)
    assert r.status == "PASS"
    assert r.evidence["granularity_tier"] == 2


def test_c3_warn_on_site_level_granularity():
    ctx = _ctx(str(FIXTURES / "location_coarse" / "records.jsonl"))
    r = C3EventLocation().run(ctx)
    assert r.status == "WARN"
    assert r.evidence["granularity_tier"] == 1


def test_c3_fail_on_low_presence():
    ctx = _ctx(str(FIXTURES / "broken" / "broken.log"))
    r = C3EventLocation().run(ctx)
    assert r.status == "FAIL"


# --- C4: affected entity (must stay independent of origin resolution) ------


def test_c4_pass_when_distinct_and_fully_present():
    ctx = _ctx(str(FIXTURES / "src_dst" / "records.jsonl"), origin_hints=["src"], affected_hints=["dst"])
    r = C4AffectedEntity().run(ctx)
    assert r.status == "PASS"


def test_c4_warn_on_partial_presence():
    ctx = _ctx(
        str(FIXTURES / "mixed_formats" / "*.log"), origin_hints=["host"], affected_hints=["dst"]
    )
    r = C4AffectedEntity().run(ctx)
    assert r.status == "WARN"


def test_c4_fail_states_origin_c4_distinction_when_origin_is_well_attributed():
    ctx = _ctx(
        str(FIXTURES / "affected_low" / "records.jsonl"),
        origin_hints=["src"],
        affected_hints=["dst"],
        inventory_path=str(FIXTURES / "affected_low" / "inventory.csv"),
        match_fields=["hostname"],
    )
    r = C4AffectedEntity().run(ctx)
    assert r.status == "FAIL"
    assert any("well attributed" in f and "C4 FAIL" in f for f in r.findings)


def test_c4_fail_states_origin_c4_distinction_when_affected_field_is_completely_absent():
    # Regression: the identifier_field-is-None branch must state the
    # distinction too, not only the "field present but thin" branch above --
    # a wholly absent affected-entity field is the canonical case for it.
    ctx = _ctx(
        str(FIXTURES / "attribution" / "records.jsonl"),
        origin_hints=["host"],
        affected_hints=["does_not_exist_in_records"],
        inventory_path=str(FIXTURES / "attribution" / "inventory_full.csv"),
        match_fields=["hostname"],
    )
    r = C4AffectedEntity().run(ctx)
    assert r.status == "FAIL"
    assert r.evidence["identifier_field"] is None
    assert any("well attributed" in f and "C4 FAIL" in f for f in r.findings)


def test_c4_fail_when_origin_and_affected_share_the_same_field():
    ctx = _ctx(
        str(FIXTURES / "attribution" / "records.jsonl"), origin_hints=["host"], affected_hints=["host"]
    )
    r = C4AffectedEntity().run(ctx)
    assert r.status == "FAIL"
    assert r.evidence["distinguishable_from_origin"] is False


# --- C5: outcome -------------------------------------------------------


def test_c5_pass_on_clean_explicit_outcome():
    ctx = _ctx(str(FIXTURES / "simple" / "records.jsonl"))
    r = C5Outcome().run(ctx)
    assert r.status == "PASS"


def test_c5_warn_on_partial_presence():
    ctx = _ctx(str(FIXTURES / "mixed_formats" / "*.log"))
    r = C5Outcome().run(ctx)
    assert r.status == "WARN"


def test_c5_fail_when_no_outcome_field_found():
    ctx = _ctx(str(FIXTURES / "no_outcome" / "records.jsonl"))
    r = C5Outcome().run(ctx)
    assert r.status == "FAIL"


def test_c5_warn_on_state_without_resolution():
    ctx = _ctx(str(FIXTURES / "condition_no_resolution" / "records.jsonl"))
    r = C5Outcome().run(ctx)
    assert r.status == "WARN"
    assert r.evidence["state_without_resolution"] is True


def test_c5_matches_candidate_regardless_of_field_name_casing():
    # Data uses 'Result' (capitalized), no 'action'-like field present, so
    # this isolates the case-insensitive match to the 'result' candidate.
    ctx = _ctx(str(FIXTURES / "mixed_case_outcome" / "records.jsonl"))
    r = C5Outcome().run(ctx)
    assert r.status == "PASS"
    assert r.evidence["field"] == "Result"  # reports the data's actual casing


# --- C6: causality (advisory only, never FAIL) --------------------------


def test_c6_not_assessed_when_absent():
    ctx = _ctx(str(FIXTURES / "simple" / "records.jsonl"))
    r = C6Causality().run(ctx)
    assert r.status == "NOT_ASSESSED"
    assert r.score is None


def test_c6_pass_when_present():
    ctx = _ctx(str(FIXTURES / "causality" / "records.jsonl"))
    r = C6Causality().run(ctx)
    assert r.status == "PASS"


# --- C7: correlatability -------------------------------------------------


def test_c7_pass_on_explicit_key():
    ctx = _ctx(str(FIXTURES / "correlation" / "records.jsonl"))
    r = C7Correlatability().run(ctx)
    assert r.status == "PASS"


def test_c7_warn_on_constructible_composite_key():
    ctx = _ctx(str(FIXTURES / "simple" / "records.jsonl"), origin_hints=["host"])
    r = C7Correlatability().run(ctx)
    assert r.status == "WARN"
    assert "timestamp" in r.evidence["composite_key_fields"]


def test_c7_fail_when_no_key_constructible():
    ctx = _ctx(str(FIXTURES / "high_cardinality" / "records.jsonl"))
    r = C7Correlatability().run(ctx)
    assert r.status == "FAIL"
