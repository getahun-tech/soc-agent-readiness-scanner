"""C6 -- causality, advisory only (SPEC.md sec 5.13).

Must never contribute to a FAIL verdict or block automation eligibility.
Most telemetry records symptoms, not causes; failing sources for lacking
a causal field would fail nearly everything and train users to ignore
the report. This check only ever returns PASS (field present -- reported
as a positive attribute) or NOT_ASSESSED (absent -- informational, not a
deficiency). The dual scorer (Phase 5) must additionally exclude C6 from
the completeness denominator outright, regardless of this status --
"C6 excluded" per SPEC.md sec 6.1 is unconditional, not just when
NOT_ASSESSED.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.profiler import find_field_stats

_CANDIDATES = ["reason", "cause", "error_code", "triggering_rule", "root_cause", "detail"]


class C6Causality(Check):
    check_id = "C6"
    name = "Causality (advisory)"
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

        best_field = None
        best_presence = 0
        for candidate in _CANDIDATES:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_count > best_presence:
                best_field, best_presence = found[0], found[1].presence_count

        if best_field is None:
            return self.result(
                "NOT_ASSESSED",
                findings=[
                    (
                        f"no causal/reason field found among {_CANDIDATES}; this is "
                        f"informational only and does not affect eligibility"
                    )
                ],
                evidence={"candidates_tried": _CANDIDATES},
                records_passed=0,
                records_total=record_count,
            )

        presence_rate = profile.field_stats[best_field].presence_rate
        return self.result(
            "PASS",
            findings=[
                (
                    f"causal field '{best_field}' present in {best_presence}/{record_count} "
                    f"records ({presence_rate:.1%}) -- informational, comparative signal only"
                )
            ],
            evidence={"field": best_field, "presence_rate": presence_rate},
            records_passed=best_presence,
            records_total=record_count,
        )
