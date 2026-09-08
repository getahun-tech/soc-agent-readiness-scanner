"""C5 -- outcome.

The "state-without-resolution" pattern (a condition like `Node Down`
emitted with no corresponding resolution event anywhere in the sample)
is checked with a plain keyword heuristic here.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.config import DEFAULT_OUTCOME_FIELD_CANDIDATES as _DEFAULT_OUTCOME_CANDIDATES
from scanner.models import get_field
from scanner.profiler import find_field_stats

_CONDITION_KEYWORDS = ("down", "fail", "error", "block", "open", "unreachable", "timeout")
_RESOLUTION_KEYWORDS = ("up", "resolved", "closed", "clear", "success", "allow", "recovered", "ok")


class C5Outcome(Check):
    check_id = "C5"
    name = "Outcome"
    dimension = "completeness"

    def run(self, ctx: CheckContext) -> CheckResult:
        profile = ctx.profile
        record_count = profile.record_count
        if record_count == 0:
            return self.result(
                "NOT_ASSESSED",
                findings=["no records were sampled for this source"],
                evidence={},
                records_passed=0,
                records_total=0,
            )

        candidates = ctx.config.field_hints.outcome or _DEFAULT_OUTCOME_CANDIDATES
        best_field = None
        best_presence = 0
        for candidate in candidates:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_count > best_presence:
                best_field, best_presence = found[0], found[1].presence_count

        if best_field is None:
            return self.result(
                "FAIL",
                findings=[f"no outcome/result/disposition field found among {candidates}"],
                evidence={"candidates_tried": list(candidates), "record_count": record_count},
                records_passed=0,
                records_total=record_count,
            )

        explicit_rate = profile.field_stats[best_field].presence_rate
        distinct_values = {
            str(get_field(r.parsed, best_field)).strip().lower()
            for r in ctx.records
            if get_field(r.parsed, best_field) not in (None, "")
        }
        has_condition = any(any(k in v for k in _CONDITION_KEYWORDS) for v in distinct_values)
        has_resolution = any(any(k in v for k in _RESOLUTION_KEYWORDS) for v in distinct_values)
        state_without_resolution = has_condition and not has_resolution

        if explicit_rate == 0.0:
            status = "FAIL"
        elif explicit_rate < 0.90:
            status = "WARN"
        else:
            status = "PASS"
        if state_without_resolution and status == "PASS":
            status = "WARN"

        findings = [
            (
                f"outcome field '{best_field}' present in {best_presence}/{record_count} "
                f"records ({explicit_rate:.1%})"
            ),
        ]
        if state_without_resolution:
            findings.append(
                f"'{best_field}' contains condition-like value(s) with no corresponding "
                f"resolution value in the sample -- an agent would have to infer whether "
                f"the condition ever cleared"
            )

        return self.result(
            status,
            findings=findings,
            evidence={
                "field": best_field,
                "explicit_rate": explicit_rate,
                "state_without_resolution": state_without_resolution,
                "distinct_value_count": len(distinct_values),
            },
            records_passed=best_presence,
            records_total=record_count,
        )
