"""C3 -- event location (SPEC.md sec 5.9).

Candidates are ranked by granularity tier (interface/port > host/segment
> site/region) because the spec is explicit that a site-level identifier
is materially weaker than an interface-level one -- picking the
highest-*presence* candidate alone would let a coarse but ubiquitous
`site` field outrank a sparser but far more actionable `interface`
field. We pick the best-present candidate at the *highest* tier that
clears a minimal presence bar, falling back to lower tiers only if
nothing finer is usable.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.profiler import find_field_stats

# tier 3 = finest granularity, 1 = coarsest
_CANDIDATES_BY_TIER: dict[int, list[str]] = {
    3: ["interface", "if_name", "port"],
    2: ["host", "hostname", "device", "segment", "subnet", "network_segment"],
    1: ["site", "location", "datacenter", "region", "cloud_region"],
}
_MIN_USABLE_PRESENCE = 0.10


class C3EventLocation(Check):
    check_id = "C3"
    name = "Event location"
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
        best_tier = 0
        best_presence_rate = 0.0
        for tier in (3, 2, 1):
            tier_best_field = None
            tier_best_rate = 0.0
            for candidate in _CANDIDATES_BY_TIER[tier]:
                found = find_field_stats(profile.field_stats, candidate)
                if found and found[1].presence_rate > tier_best_rate:
                    tier_best_field, tier_best_rate = found[0], found[1].presence_rate
            if tier_best_field and tier_best_rate >= _MIN_USABLE_PRESENCE:
                best_field, best_tier, best_presence_rate = tier_best_field, tier, tier_best_rate
                break

        if best_field is None:
            return self.result(
                "FAIL",
                findings=[
                    (
                        "no location identifier field (interface/host/site or equivalent) "
                        "found with usable presence"
                    )
                ],
                evidence={"record_count": record_count},
                records_passed=0,
                records_total=record_count,
            )

        stats = profile.field_stats[best_field]
        type_consistent = len(stats.types) <= 1
        tier_name = {3: "fine (interface/port)", 2: "medium (host/segment)", 1: "coarse (site/region)"}[
            best_tier
        ]

        if best_presence_rate < 0.80:
            status = "FAIL"
        elif best_presence_rate < 0.95 or best_tier == 1 or not type_consistent:
            status = "WARN"
        else:
            status = "PASS"

        findings = [
            (
                f"location field '{best_field}' ({tier_name} granularity) present in "
                f"{stats.presence_count}/{record_count} records ({best_presence_rate:.1%})"
            ),
        ]
        if not type_consistent:
            findings.append(f"inconsistent value types observed for '{best_field}': {stats.types}")
        if best_tier == 1:
            findings.append(
                "only site/region-level granularity is available; this is materially weaker "
                "than an interface- or host-level identifier for network telemetry"
            )

        return self.result(
            status,
            findings=findings,
            evidence={
                "field": best_field,
                "granularity_tier": best_tier,
                "presence_rate": best_presence_rate,
                "type_consistent": type_consistent,
                "record_count": record_count,
            },
            records_passed=stats.presence_count,
            records_total=record_count,
        )
