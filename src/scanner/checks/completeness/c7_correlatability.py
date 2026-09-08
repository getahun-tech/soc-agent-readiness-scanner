"""C7 -- correlatability.

Only the per-source half of this check: explicit correlation keys, and
whether a composite key is constructible from timestamp + entity fields
already resolved elsewhere in this context (reusing the timestamp
candidate from the profiler and the origin/affected fields already
resolved via `ctx.origin_resolution`/`ctx.affected_resolution` -- no new
field detection needed for that part).

Cross-source correlatability ("can this source's keys join to any other
configured source? report joinable pairs and orphaned sources") needs
every other source's data at once and does not fit a per-source
`Check.run(ctx)`. That half is estate-level and belongs with the other
multi-source work, alongside the conflicts section.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.config import DEFAULT_CORRELATION_FIELD_CANDIDATES as DEFAULT_CORRELATION_CANDIDATES
from scanner.models import get_field
from scanner.profiler import find_field_stats

_EXPLICIT_KEY_MIN_PRESENCE = 0.80
_COMPOSITE_FIELD_MIN_PRESENCE = 0.80


class C7Correlatability(Check):
    check_id = "C7"
    name = "Correlatability"
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

        candidates = ctx.config.field_hints.correlation or DEFAULT_CORRELATION_CANDIDATES
        best_field = None
        best_rate = 0.0
        for candidate in candidates:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_rate > best_rate:
                best_field, best_rate = found[0], found[1].presence_rate

        if best_field and best_rate >= _EXPLICIT_KEY_MIN_PRESENCE:
            return self.result(
                "PASS",
                findings=[
                    f"explicit correlation key '{best_field}' present in {best_rate:.1%} of records"
                ],
                evidence={"explicit_key_field": best_field, "presence_rate": best_rate},
                records_passed=profile.field_stats[best_field].presence_count,
                records_total=record_count,
            )

        timestamp_field = profile.timestamp_analysis.candidate_field
        timestamp_ok = (
            timestamp_field is not None
            and profile.timestamp_analysis.presence_rate >= _COMPOSITE_FIELD_MIN_PRESENCE
        )
        entity_fields = []
        for field in (ctx.origin_resolution.identifier_field, ctx.affected_resolution.identifier_field):
            if field is None:
                continue
            found = find_field_stats(profile.field_stats, field)
            if found and found[1].presence_rate >= _COMPOSITE_FIELD_MIN_PRESENCE:
                entity_fields.append(found[0])

        composite_constructible = timestamp_ok and len(entity_fields) >= 1

        if composite_constructible:
            key_parts = [timestamp_field, *entity_fields]
            composite_present_count = sum(
                1
                for r in ctx.records
                if all(get_field(r.parsed, f) not in (None, "") for f in key_parts)
            )
            return self.result(
                "WARN",
                findings=[
                    (
                        f"no explicit correlation key found among {candidates}, but a stable "
                        f"composite key is constructible from {key_parts}"
                    )
                ],
                evidence={
                    "explicit_key_field": None,
                    "composite_key_fields": key_parts,
                },
                records_passed=composite_present_count,
                records_total=record_count,
            )

        return self.result(
            "FAIL",
            findings=[
                (
                    f"no explicit correlation key found among {candidates}, and no viable "
                    f"composite key (timestamp + an identifiable entity field) could be "
                    f"constructed either"
                )
            ],
            evidence={
                "explicit_key_field": None,
                "candidates_tried": list(candidates),
                "timestamp_field": timestamp_field,
            },
            records_passed=0,
            records_total=record_count,
        )
