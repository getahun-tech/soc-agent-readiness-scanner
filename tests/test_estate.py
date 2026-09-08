from scanner.checks.base import CheckResult
from scanner.config import PrecedenceRule, SourceConfig
from scanner.estate import (
    SourceEntry,
    build_estate_summary,
    build_recommendations,
    detect_conflicts,
)
from scanner.scoring import CompletenessScorer


def _source(name, **overrides) -> SourceConfig:
    defaults = {
        "name": name,
        "adapter": "file",
        "path": "./x.jsonl",
        "owner": f"{name}-ops@example.com",
    }
    defaults.update(overrides)
    return SourceConfig(**defaults)


def _result(check_id, status, findings=None):
    score = {"PASS": 1.0, "WARN": 0.5, "FAIL": 0.0, "NOT_ASSESSED": None}[status]
    return CheckResult(
        check_id=check_id,
        name=check_id,
        dimension="completeness",
        status=status,
        score=score,
        findings=findings or [],
        evidence={},
    )


_COMP_IDS = ["C1", "C2", "C3", "C4", "C5", "C6", "C7"]


def _all_pass_checks(overrides: dict[str, CheckResult] | None = None) -> dict[str, CheckResult]:
    checks = {cid: _result(cid, "PASS") for cid in _COMP_IDS}
    checks.update(overrides or {})
    return checks


def _entry(name, source=None, checks=None, origin_values=None) -> SourceEntry:
    source = source or _source(name)
    checks = checks if checks is not None else _all_pass_checks()
    verdict = CompletenessScorer().score(source, checks)
    return SourceEntry(
        name=name, source=source, checks=checks, verdict=verdict, origin_values=origin_values or set()
    )


# --- Conflicts: missing precedence rule -----------------------------------


def test_flags_overlapping_origins_with_no_precedence_rule():
    a = _entry("solarwinds", origin_values={"switch-01", "switch-02"})
    b = _entry("meraki", origin_values={"switch-02", "switch-03"})
    conflicts = detect_conflicts([a, b], precedence_rules=[])
    missing = [c for c in conflicts if c.category == "missing_precedence_rule"]
    assert len(missing) == 1
    assert set(missing[0].sources) == {"solarwinds", "meraki"}
    assert "switch-02" in missing[0].description


def test_no_missing_precedence_flag_when_rule_declared():
    a = _entry("solarwinds", origin_values={"switch-01", "switch-02"})
    b = _entry("meraki", origin_values={"switch-02", "switch-03"})
    rule = PrecedenceRule(entities=["solarwinds", "meraki"], authoritative="meraki", rationale="live state")
    conflicts = detect_conflicts([a, b], precedence_rules=[rule])
    assert [c for c in conflicts if c.category == "missing_precedence_rule"] == []


def test_no_missing_precedence_flag_when_authoritative_over_declared():
    a = _entry("solarwinds", source=_source("solarwinds", authoritative_over=[]), origin_values={"sw-1"})
    b = _entry("meraki", source=_source("meraki", authoritative_over=["solarwinds"]), origin_values={"sw-1"})
    conflicts = detect_conflicts([a, b], precedence_rules=[])
    assert [c for c in conflicts if c.category == "missing_precedence_rule"] == []


def test_no_flag_when_origins_dont_overlap():
    a = _entry("solarwinds", origin_values={"switch-01"})
    b = _entry("meraki", origin_values={"switch-99"})
    conflicts = detect_conflicts([a, b], precedence_rules=[])
    assert [c for c in conflicts if c.category == "missing_precedence_rule"] == []


# --- Estate summary ---------------------------------------------------------


def test_estate_summary_eligibility_counts():
    eligible = _entry("clean_firewall")
    ineligible_a = _entry("broken_syslog", checks=_all_pass_checks({"C2": _result("C2", "FAIL")}))
    ineligible_b = _entry("origin_only", checks=_all_pass_checks({"C4": _result("C4", "FAIL")}))

    summary = build_estate_summary([eligible, ineligible_a, ineligible_b])

    assert summary.sources_scanned == 3
    assert summary.eligible_count == 1
    assert summary.ineligible_count == 2
    assert ("C2", 1) in summary.top_blocking_gates
    assert ("C4", 1) in summary.top_blocking_gates


def test_estate_summary_all_eligible():
    entry = _entry("src_a")
    summary = build_estate_summary([entry])

    assert summary.eligible_count == 1
    assert summary.ineligible_count == 0
    assert summary.top_blocking_gates == []


# --- Recommendations -------------------------------------------------------


def test_recommendations_ordered_fail_before_warn():
    entry = _entry(
        "src_a",
        source=_source("src_a", owner="device-team@example.com"),
        checks=_all_pass_checks(
            {
                "C1": _result("C1", "WARN", ["C1 warn finding"]),
                "C3": _result("C3", "FAIL", ["C3 fail finding"]),
            }
        ),
    )
    recs = build_recommendations([entry])

    assert [r.check_id for r in recs] == ["C3", "C1"]  # FAIL before WARN
    assert all(r.owner == "device-team@example.com" for r in recs)


def test_recommendations_never_include_c6():
    entry = _entry("src_a", checks=_all_pass_checks({"C6": _result("C6", "NOT_ASSESSED")}))
    recs = build_recommendations([entry])
    assert all(r.check_id != "C6" for r in recs)
