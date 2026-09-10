"""Completeness scoring and automation-eligibility gating.

One score per source, computed from the fixed C1-C8 (minus C6, see below)
check list. Eligibility is a named list of gates, not a threshold on the
score: a source can score 6/6 and still be correctly ineligible if a
specific gate (e.g. C4) fails, because the gate list names C4 specifically.
"""

from __future__ import annotations

from pydantic import BaseModel, computed_field

from scanner.checks.base import CheckResult
from scanner.config import SourceConfig

# C6 is excluded outright -- not just when NOT_ASSESSED, always. C8 is in
# the list but only counts toward the denominator when it was actually
# assessed (its source declared an event_class), since NOT_ASSESSED checks
# are excluded from the denominator dynamically below.
COMPLETENESS_CHECK_IDS = ["C1", "C2", "C3", "C4", "C5", "C7", "C8"]

# (gate_id, description) for the simple "must be PASS" gates. C5 has its
# own special-cased PASS_OR_WARN condition, handled separately. The gate
# set is deliberately frozen at C2/C4/C5 -- C8 never gates.
_STRICT_PASS_GATES: list[tuple[str, str]] = [
    ("C2", "temporal quality sound"),
    ("C4", "affected entity identifiable"),
]


class DimensionScore(BaseModel):
    score: float
    denominator: int
    assessed_checks: list[str]
    not_assessed_checks: list[str]

    @property
    def display(self) -> str:
        suffix = f" ({', '.join(self.not_assessed_checks)} NOT_ASSESSED)" if self.not_assessed_checks else ""
        return f"{self.score:g}/{self.denominator}{suffix}"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def percent(self) -> int | None:
        """None (not 0) when every check was NOT_ASSESSED, so a source with
        no assessable checks isn't misreported as 0%."""
        if self.denominator == 0:
            return None
        return round(100 * self.score / self.denominator)


class EligibilityGate(BaseModel):
    gate_id: str
    description: str
    passed: bool
    reason: str | None
    owning_team_email: str | None


class EligibilityVerdict(BaseModel):
    eligible: bool
    gates: list[EligibilityGate]

    @property
    def failed_gates(self) -> list[EligibilityGate]:
        return [g for g in self.gates if not g.passed]


class SourceVerdict(BaseModel):
    source_name: str
    completeness: DimensionScore
    eligibility: EligibilityVerdict


def _score_completeness(checks: dict[str, CheckResult]) -> DimensionScore:
    assessed: list[str] = []
    not_assessed: list[str] = []
    total = 0.0
    for check_id in COMPLETENESS_CHECK_IDS:
        result = checks.get(check_id)
        if result is None or result.status == "NOT_ASSESSED" or result.score is None:
            not_assessed.append(check_id)
            continue
        assessed.append(check_id)
        total += result.score
    return DimensionScore(
        score=total,
        denominator=len(assessed),
        assessed_checks=assessed,
        not_assessed_checks=not_assessed,
    )


def _gate_reason(check_id: str, result: CheckResult | None, wanted: str) -> str | None:
    if result is None:
        return f"{check_id} was not run"
    if result.status == wanted or (wanted == "PASS_OR_WARN" and result.status in ("PASS", "WARN")):
        return None
    detail = f": {result.findings[0]}" if result.findings else ""
    return f"{check_id} is {result.status}{detail}"


def evaluate_eligibility(source: SourceConfig, checks: dict[str, CheckResult]) -> EligibilityVerdict:
    gates: list[EligibilityGate] = []

    for gate_id, description in _STRICT_PASS_GATES:
        result = checks.get(gate_id)
        reason = _gate_reason(gate_id, result, "PASS")
        gates.append(
            EligibilityGate(
                gate_id=gate_id,
                description=description,
                passed=reason is None,
                reason=reason,
                owning_team_email=None if reason is None else source.owner,
            )
        )

    c5 = checks.get("C5")
    c5_reason = _gate_reason("C5", c5, "PASS_OR_WARN")
    gates.append(
        EligibilityGate(
            gate_id="C5",
            description="outcome determinable",
            passed=c5_reason is None,
            reason=c5_reason,
            owning_team_email=None if c5_reason is None else source.owner,
        )
    )

    return EligibilityVerdict(eligible=all(g.passed for g in gates), gates=gates)


class CompletenessScorer:
    """Aggregates check results into a completeness score plus an
    eligibility verdict.
    """

    def score(self, source: SourceConfig, checks: dict[str, CheckResult]) -> SourceVerdict:
        return SourceVerdict(
            source_name=source.name,
            completeness=_score_completeness(checks),
            eligibility=evaluate_eligibility(source, checks),
        )
