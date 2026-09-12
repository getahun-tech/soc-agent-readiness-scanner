"""Estate-level aggregation: conflicts and owner-routed recommendations.

Everything here needs more than one source's data at once, which is why
it lives outside the per-source Check classes -- see the "deferred to
Phase 5" note in C7.
"""

from __future__ import annotations

from itertools import combinations
from typing import Literal

from pydantic import BaseModel

from scanner.checks.base import CheckResult
from scanner.config import PrecedenceRule, SourceConfig
from scanner.playbook import Remediation, missing_context_fields, remediation_for
from scanner.scoring import SourceVerdict

ConflictCategory = Literal["missing_precedence_rule"]
Severity = Literal["top", "normal"]


class SourceEntry(BaseModel):
    """Everything estate-level aggregation needs about one successfully
    scanned source, gathered once in the orchestrator."""

    name: str
    source: SourceConfig
    checks: dict[str, CheckResult]
    verdict: SourceVerdict
    origin_values: set[str]
    field_names: set[str] = set()
    """Every field observed in the sample (post-flattening). Only the
    context-field advisory reads it."""

    model_config = {"arbitrary_types_allowed": True}


class ConflictFinding(BaseModel):
    category: ConflictCategory
    severity: Severity
    sources: list[str]
    description: str


class Recommendation(BaseModel):
    source: str
    check_id: str
    check_name: str
    status: str
    """FAIL / WARN for a check-backed recommendation; ADVISORY for the
    context-field note, which is never a deficiency."""
    owner: str
    finding: str
    remediation: Remediation | None = None
    """What to add, what it enables, where the fix lives (see playbook.py).
    Additive: never read by scoring or eligibility."""


_CONTEXT_CHECK_ID = "CTX"
_STATUS_ORDER = {"FAIL": 0, "WARN": 1, "ADVISORY": 2}


class EstateSummary(BaseModel):
    sources_scanned: int
    eligible_count: int
    ineligible_count: int
    top_blocking_gates: list[tuple[str, int]]


def detect_conflicts(entries: list[SourceEntry], precedence_rules: list[PrecedenceRule]) -> list[ConflictFinding]:
    findings: list[ConflictFinding] = []

    # Overlapping origins with no declared precedence. Overlap is
    # approximated from the sampled origin identifier values actually observed --
    # the tool only ever sees a bounded sample, so this can miss overlap that
    # didn't happen to appear in either sample, but it never fabricates an
    # overlap that isn't in the data.
    declared_pairs: set[frozenset[str]] = set()
    for rule in precedence_rules:
        for a, b in combinations(rule.entities, 2):
            declared_pairs.add(frozenset((a, b)))

    for a, b in combinations(sorted(entries, key=lambda e: e.name), 2):
        if not a.origin_values or not b.origin_values:
            continue
        pair_key = frozenset((a.name, b.name))
        if pair_key in declared_pairs:
            continue
        if b.name in a.source.authoritative_over or a.name in b.source.authoritative_over:
            continue
        overlap = a.origin_values & b.origin_values
        if overlap:
            examples = sorted(overlap)[:3]
            findings.append(
                ConflictFinding(
                    category="missing_precedence_rule",
                    severity="top",
                    sources=[a.name, b.name],
                    description=(
                        f"'{a.name}' and '{b.name}' share {len(overlap)} overlapping origin "
                        f"value(s) in the sample (e.g. {examples}) but no precedence rule "
                        f"declares which is authoritative"
                    ),
                )
            )

    findings.sort(key=lambda f: 0 if f.severity == "top" else 1)
    return findings


def build_estate_summary(entries: list[SourceEntry]) -> EstateSummary:
    blocking_counts: dict[str, int] = {}
    eligible_count = 0

    for entry in entries:
        if entry.verdict.eligibility.eligible:
            eligible_count += 1
        for gate in entry.verdict.eligibility.failed_gates:
            blocking_counts[gate.gate_id] = blocking_counts.get(gate.gate_id, 0) + 1

    top_blocking = sorted(blocking_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]

    return EstateSummary(
        sources_scanned=len(entries),
        eligible_count=eligible_count,
        ineligible_count=len(entries) - eligible_count,
        top_blocking_gates=top_blocking,
    )


def build_recommendations(entries: list[SourceEntry]) -> list[Recommendation]:
    """Ordered FAIL, then WARN, then ADVISORY; within each, by source name,
    then check ID. Every FAIL/WARN carries the playbook's remediation
    (what to add, what it enables, where the fix lives). A source that
    lacks the agent-context fields gets one ADVISORY entry naming them --
    one line, not one per field, so it can't drown the real findings."""
    recommendations: list[Recommendation] = []

    for entry in entries:
        for check_id, result in entry.checks.items():
            if result.status not in ("FAIL", "WARN"):
                continue
            recommendations.append(
                Recommendation(
                    source=entry.name,
                    check_id=check_id,
                    check_name=result.name,
                    status=result.status,
                    owner=entry.source.owner,
                    finding=result.findings[0] if result.findings else "",
                    remediation=remediation_for(result),
                )
            )

        missing = missing_context_fields(entry.field_names)
        if missing and entry.field_names:
            recommendations.append(
                Recommendation(
                    source=entry.name,
                    check_id=_CONTEXT_CHECK_ID,
                    check_name="Agent context fields",
                    status="ADVISORY",
                    owner=entry.source.owner,
                    finding=(
                        "no agent-context field present: "
                        + ", ".join(name for name, _ in missing)
                        + " -- not a completeness deficiency; these come from the asset "
                        "inventory or change calendar, not the device"
                    ),
                    remediation=Remediation(
                        add_fields=[f"{name} -- {why}" for name, why in missing],
                        enables=(
                            "the agent can tell intended downtime, environment, and impact "
                            "apart *before* acting, instead of discovering them afterwards"
                        ),
                        where=["pipeline", "query"],
                    ),
                )
            )

    def sort_key(rec: Recommendation) -> tuple[int, str, str]:
        return (_STATUS_ORDER.get(rec.status, 9), rec.source, rec.check_id)

    recommendations.sort(key=sort_key)
    return recommendations
