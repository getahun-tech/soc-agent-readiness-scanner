"""C4 -- affected entity. Flagship completeness check.

Origin resolution (`ctx.origin_resolution`) asks who generated the record;
C4 asks who it happened to. This class must never be a thin wrapper
around origin resolution -- it runs its own `AssetResolver.resolve()`
call against `field_hints.affected` (see `ctx.affected_resolution`),
independent of `ctx.origin_resolution`, so a source can be well-attributed
to its reporting device but still FAIL here (or the reverse).

"Identifiable" for C4's own PASS/WARN/FAIL bands means *present in the
sample*, not *resolved against the inventory* -- inventory resolution is
reported alongside as supplementary evidence (mirroring origin
resolution's match_rate) but does not gate this check, since a
remediation agent needs to know *what* was affected before inventory
lookup is even relevant.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult

_ORIGIN_C4_DISTINCTION = (
    "Records are well attributed to their reporting device but the "
    "affected entity cannot be reliably identified (C4 FAIL). Automated action "
    "requires knowing what to act on, not only what reported it."
)


class C4AffectedEntity(Check):
    check_id = "C4"
    name = "Affected entity"
    dimension = "completeness"

    def run(self, ctx: CheckContext) -> CheckResult:
        res = ctx.affected_resolution
        record_count = res.record_count
        if record_count == 0:
            return self.result(
                "NOT_ASSESSED",
                findings=["no records were sampled for this source"],
                evidence={},
                records_passed=0,
                records_total=0,
            )

        if res.identifier_field is None:
            findings = [
                f"no affected-entity identifier found: {res.inventory_note or 'field not present in sample'}"
            ]
            # A completely absent affected-entity field is the canonical case
            # for the origin/C4 distinction, not a lesser one -- this must
            # fire here too, not only when the field is present-but-thin.
            if ctx.origin_resolution.attributable_rate >= 0.95:
                findings.append(_ORIGIN_C4_DISTINCTION)
            return self.result(
                "FAIL",
                findings=findings,
                evidence={"identifier_field": None, "record_count": record_count},
                records_passed=0,
                records_total=record_count,
            )

        origin_field = ctx.origin_resolution.identifier_field
        distinguishable = origin_field is None or origin_field != res.identifier_field
        identifiable_rate = res.presence_rate

        if identifiable_rate < 0.70 or not distinguishable:
            status = "FAIL"
        elif identifiable_rate < 0.95:
            status = "WARN"
        else:
            status = "PASS"

        findings = [
            (
                f"affected-entity field '{res.identifier_field}' present in "
                f"{res.presence_count}/{record_count} records ({identifiable_rate:.1%})"
            ),
        ]
        if not distinguishable:
            findings.append(
                f"the same field ('{res.identifier_field}') serves as both the origin "
                f"and affected-entity (C4) identifier -- the scanner cannot tell what "
                f"reported the event apart from what it happened to"
            )
        if res.inventory_loaded:
            findings.append(
                f"inventory resolution (separate from origin resolution): "
                f"{res.matched_count}/{res.presence_count} present values matched a known "
                f"asset ({(res.match_rate or 0.0):.1%})"
            )

        # Origin/C4 divergence is the single most commonly misread result in this
        # report -- spell it out whenever it applies.
        if ctx.origin_resolution.attributable_rate >= 0.95 and status == "FAIL":
            findings.append(_ORIGIN_C4_DISTINCTION)

        return self.result(
            status,
            findings=findings,
            evidence={
                "identifier_field": res.identifier_field,
                "record_count": record_count,
                "presence_count": res.presence_count,
                "identifiable_rate": identifiable_rate,
                "distinguishable_from_origin": distinguishable,
                "inventory_loaded": res.inventory_loaded,
                "matched_count": res.matched_count,
                "match_rate": res.match_rate,
            },
            records_passed=res.presence_count,
            records_total=record_count,
        )
