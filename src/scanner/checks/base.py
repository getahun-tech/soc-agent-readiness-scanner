"""Check engine contract.

Every check is a class implementing `run(ctx) -> CheckResult`. New checks
plug in by being added to a registry list (see orchestrator.py); nothing
here needs to change to add one.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, computed_field

from scanner.config import EventClass, FieldHints, ScannerConfig, SourceConfig
from scanner.identifier_resolver import IdentifierResolution
from scanner.models import RawRecord
from scanner.profiler import ProfileResult

Dimension = Literal["completeness"]
Status = Literal["PASS", "WARN", "FAIL", "NOT_ASSESSED"]

_SCORE_BY_STATUS: dict[Status, float | None] = {
    "PASS": 1.0,
    "WARN": 0.5,
    "FAIL": 0.0,
    "NOT_ASSESSED": None,
}


class CheckResult(BaseModel):
    check_id: str
    name: str
    dimension: Dimension
    status: Status
    score: float | None
    findings: list[str]
    evidence: dict[str, Any]
    records_passed: int | None = None
    """How many of the sampled records individually satisfy this check's
    core per-record signal. None for a check with no per-record signal at
    all -- a single fact about the source, not about any individual log."""
    records_total: int | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def records_failed(self) -> int | None:
        if self.records_passed is None or self.records_total is None:
            return None
        return self.records_total - self.records_passed

    @computed_field  # type: ignore[prop-decorator]
    @property
    def records_failed_percent(self) -> float | None:
        """One decimal place, not a whole number: at sample sizes in the
        thousands, rounding 99.62% to a bare 100% next to an explicit
        9962/10000 count reads as contradictory, not just imprecise."""
        if self.records_failed is None or not self.records_total:
            return None
        return round(100 * self.records_failed / self.records_total, 1)


@dataclass(frozen=True)
class CheckContext:
    source: SourceConfig
    config: ScannerConfig
    profile: ProfileResult
    records: list[RawRecord]
    origin_resolution: IdentifierResolution
    """Resolution of the *origin* (reporting device) identifier."""
    affected_resolution: IdentifierResolution
    """Resolution of the *affected entity* (target/subject) identifier -- C4.

    Deliberately a separate IdentifierResolver.resolve() call against
    `field_hints.affected`, never derived from `origin_resolution`. Origin
    and affected-entity resolution answer different questions and must be
    able to disagree (e.g. well-attributed device, unidentifiable target).
    """
    field_hints: FieldHints
    """The candidate lists in effect for *this* source: the config's
    hints, with a matched log-type profile's role hints prepended (see
    profiles.py). Checks read these, not `config.field_hints`."""
    event_class: EventClass | None
    """The source's declared event_class, or the matched profile's when
    the source didn't declare one. C8 reads this, not `source.event_class`."""


def score_for(status: Status) -> float | None:
    return _SCORE_BY_STATUS[status]


class Check(ABC):
    check_id: ClassVar[str]
    name: ClassVar[str]
    dimension: ClassVar[Dimension]

    @abstractmethod
    def run(self, ctx: CheckContext) -> CheckResult:
        raise NotImplementedError

    def result(
        self,
        status: Status,
        findings: list[str],
        evidence: dict[str, Any],
        records_passed: int,
        records_total: int,
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            dimension=self.dimension,
            status=status,
            score=score_for(status),
            findings=findings,
            evidence=evidence,
            records_passed=records_passed,
            records_total=records_total,
        )
