from scanner.checks.base import CheckResult
from scanner.config import SourceConfig
from scanner.scoring import CompletenessScorer, evaluate_eligibility


def _source(**overrides) -> SourceConfig:
    defaults = {
        "name": "src",
        "adapter": "file",
        "path": "./x.jsonl",
        "owner": "ops@example.com",
    }
    defaults.update(overrides)
    return SourceConfig(**defaults)


def _result(check_id, name, status, score, findings=None):
    return CheckResult(
        check_id=check_id,
        name=name,
        dimension="completeness",
        status=status,
        score=score,
        findings=findings or [f"{check_id} finding"],
        evidence={},
    )


_ALL_PASS_COMPLETENESS = {
    "C1": _result("C1", "Event identification", "PASS", 1.0),
    "C2": _result("C2", "Temporal quality", "PASS", 1.0),
    "C3": _result("C3", "Event location", "PASS", 1.0),
    "C4": _result("C4", "Affected entity", "PASS", 1.0),
    "C5": _result("C5", "Outcome", "PASS", 1.0),
    "C6": _result("C6", "Causality", "PASS", 1.0),
    "C7": _result("C7", "Correlatability", "PASS", 1.0),
}


def _all_pass_checks():
    return dict(_ALL_PASS_COMPLETENESS)


# --- CompletenessScorer: dimension score ----------------------------------


def test_completeness_score_excludes_not_assessed():
    checks = dict(_all_pass_checks())
    checks["C2"] = _result("C2", "Temporal quality", "NOT_ASSESSED", None)
    verdict = CompletenessScorer().score(_source(), checks)

    assert verdict.completeness.denominator == 5
    assert "C2" in verdict.completeness.not_assessed_checks
    # C1,C3,C4,C5,C7 PASS (1.0 each) = 5.0 (C6 always excluded)
    assert verdict.completeness.score == 5.0


def test_completeness_percent_is_none_not_zero_when_nothing_assessed():
    checks = {
        check_id: _result(check_id, "x", "NOT_ASSESSED", None)
        for check_id in ("C1", "C2", "C3", "C4", "C5", "C7")
    }
    verdict = CompletenessScorer().score(_source(), checks)
    assert verdict.completeness.denominator == 0
    assert verdict.completeness.percent is None


def test_completeness_score_always_excludes_c6_even_when_c6_passes():
    verdict = CompletenessScorer().score(_source(), _all_pass_checks())
    assert "C6" not in verdict.completeness.assessed_checks
    assert "C6" not in verdict.completeness.not_assessed_checks
    assert verdict.completeness.denominator == 6


def test_score_always_returns_eligibility_too():
    verdict = CompletenessScorer().score(_source(), _all_pass_checks())
    assert verdict.completeness is not None
    assert verdict.eligibility is not None


def test_no_combined_score_api_exists():
    # The scorer must not expose any method returning a single combined
    # score across multiple sources/dimensions. Assert there's nothing on
    # the class whose name suggests one.
    public_methods = [m for m in dir(CompletenessScorer) if not m.startswith("_")]
    assert public_methods == ["score"]


# --- Eligibility gates ----------------------------------------------------


def test_eligible_when_all_gates_pass():
    verdict = evaluate_eligibility(_source(), _all_pass_checks())
    assert verdict.eligible is True
    assert verdict.failed_gates == []


def test_ineligible_when_c4_fails_even_with_near_perfect_completeness():
    checks = dict(_all_pass_checks())
    checks["C4"] = _result("C4", "Affected entity", "FAIL", 0.0, ["affected entity not identifiable"])
    verdict = evaluate_eligibility(_source(), checks)

    assert verdict.eligible is False
    failed_ids = {g.gate_id for g in verdict.failed_gates}
    assert failed_ids == {"C4"}
    c4_gate = next(g for g in verdict.failed_gates if g.gate_id == "C4")
    assert c4_gate.owning_team_email == "ops@example.com"
    assert "affected entity not identifiable" in c4_gate.reason


def test_c5_warn_still_passes_the_gate():
    checks = dict(_all_pass_checks())
    checks["C5"] = _result("C5", "Outcome", "WARN", 0.5)
    verdict = evaluate_eligibility(_source(), checks)
    c5_gate = next(g for g in verdict.gates if g.gate_id == "C5")
    assert c5_gate.passed is True


def test_c5_fail_fails_the_gate():
    checks = dict(_all_pass_checks())
    checks["C5"] = _result("C5", "Outcome", "FAIL", 0.0)
    verdict = evaluate_eligibility(_source(), checks)
    c5_gate = next(g for g in verdict.gates if g.gate_id == "C5")
    assert c5_gate.passed is False


def test_missing_check_treated_as_not_assessed_and_fails_its_gate():
    checks = dict(_all_pass_checks())
    del checks["C2"]
    verdict = evaluate_eligibility(_source(), checks)
    c2_gate = next(g for g in verdict.gates if g.gate_id == "C2")
    assert c2_gate.passed is False
    assert "not run" in c2_gate.reason
