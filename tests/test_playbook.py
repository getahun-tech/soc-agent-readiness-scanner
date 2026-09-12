from scanner.checks.base import CheckResult
from scanner.playbook import (
    CONTEXT_FIELDS,
    FIX_PATH_LABELS,
    missing_context_fields,
    remediation_for,
)


def _result(check_id, status="FAIL", evidence=None):
    return CheckResult(
        check_id=check_id,
        name=check_id,
        dimension="completeness",
        status=status,
        score=0.0,
        findings=[],
        evidence=evidence or {},
    )


def test_every_scored_check_has_a_remediation_and_c6_has_none():
    for check_id in ("C1", "C2", "C3", "C4", "C5", "C7", "C8"):
        rem = remediation_for(_result(check_id))
        assert rem is not None, check_id
        assert rem.add_fields and rem.enables and rem.where
        assert all(w in FIX_PATH_LABELS for w in rem.where)
        assert rem.where_labels == [FIX_PATH_LABELS[w] for w in rem.where]
    assert remediation_for(_result("C6", "NOT_ASSESSED")) is None


def test_c2_remediation_is_driven_by_the_evidence():
    naive = remediation_for(_result("C2", evidence={"parseable_rate": 1.0, "field": "ts", "naive_count": 3}))
    assert any("UTC offset" in f for f in naive.add_fields)
    assert not any("NTP" in f for f in naive.add_fields)

    skew = remediation_for(
        _result(
            "C2",
            evidence={
                "parseable_rate": 1.0,
                "field": "ts",
                "naive_count": 0,
                "skew_assessed": True,
                "max_abs_offset_seconds": 9.5,
                "skew_threshold_seconds": 5.0,
            },
        )
    )
    assert any("NTP" in f for f in skew.add_fields)
    assert not any("UTC offset" in f for f in skew.add_fields)

    ambiguous = remediation_for(
        _result("C2", "WARN", evidence={"parseable_rate": 1.0, "field": "ts", "event_ingest_ambiguous": True})
    )
    assert any("ingest_time" in f for f in ambiguous.add_fields)
    assert "pipeline" in ambiguous.where

    # Nothing specific in the evidence -> generic guidance, never empty.
    generic = remediation_for(_result("C2", "WARN", evidence={"parseable_rate": 1.0, "field": "ts"}))
    assert generic.add_fields and generic.where


def test_missing_context_fields_is_case_insensitive_and_names_only_the_gaps():
    assert [n for n, _ in missing_context_fields(set())] == [n for n, _, _ in CONTEXT_FIELDS]
    assert [n for n, _ in missing_context_fields({"Environment", "host"})] == [
        "maintenance_window",
        "asset_criticality",
    ]
    assert missing_context_fields({"in_maintenance", "env", "criticality"}) == []
