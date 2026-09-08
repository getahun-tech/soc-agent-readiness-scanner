"""C2 -- temporal quality (SPEC.md sec 5.8).

Four required sub-checks. Reads as: "WARN skew detected under a
configurable threshold (default 5s) ... FAIL ... skew above threshold" --
we take that literally: nonzero skew at or below the threshold is a
WARN-level finding (a real but tolerable drift, worth flagging), and
skew *above* the threshold is a FAIL (it actively breaks correlation).

Clock-skew estimate: without a true reference clock, we treat the sample
itself as ground truth by assuming records from different origins in the
same batch describe roughly the same real-world window (a reasonable
assumption for telemetry sampled over a bounded period). Each origin's
*median* timestamp is compared to the pooled median across all origins;
a systematic per-origin offset against that pooled median is what we
report as "skew." When an ingest-time-like field is also present, we
additionally report the event-time/ingest-time delta distribution
(sec 5.8 sub-check 3) -- that delta is not currently folded into the
skew estimate itself, only reported alongside it.
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.models import get_field
from scanner.profiler import find_field_stats
from scanner.timeutil import parse_timestamp, to_comparable

_INGEST_FIELD_CANDIDATES = [
    "ingest_time",
    "index_time",
    "_indextime",
    "received_at",
    "collected_at",
]
CLOCK_SKEW_WARN_THRESHOLD_SECONDS = 5.0
_MIN_PARSEABLE_RATE = 0.99


class C2TemporalQuality(Check):
    check_id = "C2"
    name = "Temporal quality"
    dimension = "completeness"

    def run(self, ctx: CheckContext) -> CheckResult:
        profile = ctx.profile
        field = profile.timestamp_analysis.candidate_field
        record_count = profile.record_count

        if field is None or record_count == 0:
            return self.result(
                "NOT_ASSESSED",
                findings=[profile.timestamp_analysis.note],
                evidence={"candidate_field": None},
                records_passed=0,
                records_total=record_count,
            )

        parseable_count = 0
        naive_count = 0
        by_origin: dict[str, list[float]] = defaultdict(list)
        origin_field = ctx.origin_resolution.identifier_field

        for r in ctx.records:
            ts_value = get_field(r.parsed, field)
            if ts_value is None:
                continue
            dt, has_tz = parse_timestamp(ts_value)
            if dt is None:
                continue
            parseable_count += 1
            if not has_tz:
                naive_count += 1
            origin_value = get_field(r.parsed, origin_field) if origin_field else None
            if origin_value not in (None, ""):
                by_origin[str(origin_value)].append(to_comparable(dt).timestamp())

        parseable_rate = parseable_count / record_count
        explicit_tz_rate = ((parseable_count - naive_count) / parseable_count) if parseable_count else 0.0

        findings = [
            (
                f"timestamp field '{field}' present and parseable in "
                f"{parseable_count}/{record_count} records ({parseable_rate:.1%})"
            ),
            f"explicit timezone/UTC offset present in {explicit_tz_rate:.1%} of parsed timestamps"
            + ("" if parseable_count else " (n/a -- nothing parsed)"),
        ]

        # Sub-check 3: event-time vs ingest-time.
        ingest_field = None
        ingest_best_presence = 0
        for candidate in _INGEST_FIELD_CANDIDATES:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_count > ingest_best_presence:
                ingest_field, ingest_best_presence = found[0], found[1].presence_count

        event_ingest_ambiguous = ingest_field is None
        if ingest_field:
            deltas = []
            for r in ctx.records:
                ts_value = get_field(r.parsed, field)
                ingest_value = get_field(r.parsed, ingest_field)
                if ts_value is None or ingest_value is None:
                    continue
                edt, _ = parse_timestamp(ts_value)
                idt, _ = parse_timestamp(ingest_value)
                if edt is not None and idt is not None:
                    deltas.append((to_comparable(idt) - to_comparable(edt)).total_seconds())
            if deltas:
                findings.append(
                    f"event-time vs ingest-time ('{ingest_field}') delta over {len(deltas)} "
                    f"record(s): min={min(deltas):.1f}s max={max(deltas):.1f}s "
                    f"mean={statistics.fmean(deltas):.1f}s"
                )
            else:
                findings.append(
                    f"ingest-time field '{ingest_field}' present but no records had both "
                    f"fields parseable together"
                )
                event_ingest_ambiguous = True
        else:
            findings.append(
                "no ingest-time field found alongside the event timestamp; event-time vs "
                "ingest-time cannot be distinguished (ambiguous)"
            )

        # Sub-check 4: clock skew across origins.
        skew_assessed = False
        max_abs_offset = 0.0
        if origin_field is None:
            findings.append(
                "no origin identifier field resolved; clock-skew comparison across origins "
                "cannot be assessed"
            )
        elif len(by_origin) < 2:
            findings.append(
                f"only {len(by_origin)} distinct origin(s) with parseable timestamps; skew "
                f"assessment needs at least 2"
            )
        else:
            skew_assessed = True
            pooled = [t for values in by_origin.values() for t in values]
            global_median = statistics.median(pooled)
            for origin in sorted(by_origin):
                origin_median = statistics.median(by_origin[origin])
                offset = origin_median - global_median
                max_abs_offset = max(max_abs_offset, abs(offset))
                if abs(offset) > 0.01:
                    findings.append(
                        f"origin '{origin}': estimated clock offset {offset:+.1f}s from the "
                        f"sample's pooled median (n={len(by_origin[origin])})"
                    )

        findings.append(
            "clock skew across sources is a silent correlation killer: two sources can each "
            "pass every other check and still be uncorrelatable in practice"
        )

        fail_reasons = []
        if parseable_rate < _MIN_PARSEABLE_RATE:
            fail_reasons.append(
                f"only {parseable_rate:.1%} of records have a parseable timestamp (<99%)"
            )
        if parseable_count > 0 and naive_count > 0:
            fail_reasons.append(
                f"{naive_count}/{parseable_count} parsed timestamps have no explicit "
                f"timezone/UTC offset -- naive timestamps are a FAIL, not a WARN"
            )
        if skew_assessed and max_abs_offset > CLOCK_SKEW_WARN_THRESHOLD_SECONDS:
            fail_reasons.append(
                f"estimated clock skew of {max_abs_offset:.1f}s exceeds the "
                f"{CLOCK_SKEW_WARN_THRESHOLD_SECONDS:.0f}s threshold"
            )

        if fail_reasons:
            status = "FAIL"
        else:
            warn = (skew_assessed and max_abs_offset > 0.01) or event_ingest_ambiguous
            status = "WARN" if warn else "PASS"

        return self.result(
            status,
            findings=fail_reasons + findings,
            evidence={
                "field": field,
                "record_count": record_count,
                "parseable_count": parseable_count,
                "parseable_rate": parseable_rate,
                "naive_count": naive_count,
                "explicit_timezone_rate": explicit_tz_rate,
                "ingest_field": ingest_field,
                "event_ingest_ambiguous": event_ingest_ambiguous,
                "skew_assessed": skew_assessed,
                "max_abs_offset_seconds": max_abs_offset,
                "skew_threshold_seconds": CLOCK_SKEW_WARN_THRESHOLD_SECONDS,
            },
            records_passed=parseable_count,
            records_total=record_count,
        )
