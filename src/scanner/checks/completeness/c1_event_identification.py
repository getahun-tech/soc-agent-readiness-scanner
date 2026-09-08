"""C1 -- event identification (SPEC.md sec 5.7).

An event-type field is only useful if it repeats across records to form
a manageable, typed vocabulary. Two failure modes are distinct even
though both look like "no event type": the field being absent, and the
field being present but effectively unique per record (a free-text
message or a per-record ID masquerading as a "type"). We measure both:
`identified_rate` (presence + enum-like shape, over the whole sample)
drives the PASS/WARN/FAIL bands the spec gives; `high_cardinality` is a
separate WARN trigger even when the shape and presence both look fine.
"""

from __future__ import annotations

import re

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.models import get_field
from scanner.profiler import find_field_stats

EVENT_TYPE_FIELD_CANDIDATES = [
    "action",
    "event_type",
    "signature",
    "event",
    "type",
    "name",
    "message_type",
]
_ENUM_LIKE = re.compile(r"^[A-Za-z0-9_\-.:]{1,40}$")
_MIN_RECORDS_FOR_CARDINALITY_CHECK = 10
_HIGH_CARDINALITY_RATIO = 0.5


class C1EventIdentification(Check):
    check_id = "C1"
    name = "Event identification"
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
        for candidate in EVENT_TYPE_FIELD_CANDIDATES:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_count > best_presence:
                best_field, best_presence = found[0], found[1].presence_count

        if best_field is None:
            return self.result(
                "FAIL",
                findings=[
                    (
                        f"no identifiable event-type field found among candidates "
                        f"{EVENT_TYPE_FIELD_CANDIDATES}"
                    )
                ],
                evidence={
                    "candidates_tried": EVENT_TYPE_FIELD_CANDIDATES,
                    "record_count": record_count,
                },
                records_passed=0,
                records_total=record_count,
            )

        identified_count = 0
        distinct_values: set[str] = set()
        for r in ctx.records:
            raw_value = get_field(r.parsed, best_field)
            if raw_value in (None, ""):
                continue
            value = str(raw_value)
            distinct_values.add(value)
            if _ENUM_LIKE.match(value.strip()):
                identified_count += 1

        identified_rate = identified_count / record_count
        cardinality_ratio = len(distinct_values) / record_count
        high_cardinality = (
            record_count >= _MIN_RECORDS_FOR_CARDINALITY_CHECK
            and cardinality_ratio > _HIGH_CARDINALITY_RATIO
        )

        if identified_rate < 0.80:
            status = "FAIL"
        elif identified_rate < 0.95 or high_cardinality:
            status = "WARN"
        else:
            status = "PASS"

        findings = [
            (
                f"event-type field '{best_field}': {identified_count}/{record_count} records "
                f"({identified_rate:.1%}) have a present, bounded-token value"
            ),
            f"{len(distinct_values)} distinct value(s) observed ({cardinality_ratio:.1%} of records)",
        ]
        if high_cardinality:
            findings.append(
                "cardinality is high relative to sample size -- this looks more like a "
                "per-record identifier or free-text message than a typed event vocabulary"
            )

        return self.result(
            status,
            findings=findings,
            evidence={
                "field": best_field,
                "record_count": record_count,
                "identified_count": identified_count,
                "identified_rate": identified_rate,
                "distinct_value_count": len(distinct_values),
                "cardinality_ratio": cardinality_ratio,
                "high_cardinality": high_cardinality,
            },
            records_passed=identified_count,
            records_total=record_count,
        )
