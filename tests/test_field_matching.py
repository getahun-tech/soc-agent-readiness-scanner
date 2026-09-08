"""Case-insensitive field-name matching (get_field / find_field_stats).

A field_hints candidate and a source's actual field name routinely
differ only in casing (candidate `host` vs. a source that always emits
`Host`) -- these two helpers are what every check goes through instead
of a raw case-sensitive dict lookup, so this covers the shared mechanism
directly rather than re-testing it once per check.
"""

from scanner.models import get_field
from scanner.profiler import FieldStats, find_field_stats


def test_get_field_matches_exact_case():
    assert get_field({"host": "web01"}, "host") == "web01"


def test_get_field_matches_different_case():
    assert get_field({"Host": "web01"}, "host") == "web01"
    assert get_field({"HOST": "web01"}, "host") == "web01"
    assert get_field({"host": "web01"}, "HOST") == "web01"


def test_get_field_returns_none_when_absent():
    assert get_field({"src": "10.0.0.1"}, "host") is None


def test_get_field_handles_none_or_empty_parsed():
    assert get_field(None, "host") is None
    assert get_field({}, "host") is None


def _stats(presence_count=1) -> FieldStats:
    return FieldStats(
        presence_count=presence_count,
        presence_rate=1.0,
        types={"str": presence_count},
        distinct_value_count=1,
        top_values=["x"],
    )


def test_find_field_stats_matches_different_case_and_reports_actual_key():
    field_stats = {"Host": _stats()}
    found = find_field_stats(field_stats, "host")
    assert found is not None
    actual_key, stats = found
    assert actual_key == "Host"  # the data's real casing, not the candidate's
    assert stats.presence_count == 1


def test_find_field_stats_returns_none_when_absent():
    assert find_field_stats({"src": _stats()}, "host") is None
