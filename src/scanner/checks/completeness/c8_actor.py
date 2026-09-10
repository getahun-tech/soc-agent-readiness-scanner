"""C8 -- actor / initiator.

Who *performed* the action -- deliberately distinct from both origin
resolution ("who reported it") and C4's affected entity ("who it
happened to"). Reporter, actor, and target are three different entities,
frequently conflated, and for identity-touching automations (disable an
account, kill a process) the actor is often the decision-critical field.

Applicability is declared, never inferred: a missing actor field is
ambiguous between "incomplete log" and "inapplicable concept" (a
node-down event has no actor), and only the source owner knows which
kind of source this is. `event_class` on the source config resolves it:

- "activity"  -> scored PASS/WARN/FAIL on actor-field presence.
- "state"     -> NOT_ASSESSED: there is no actor by definition.
- "mixed"     -> scored, but FAIL is softened to WARN -- partial actor
                 absence is expected when state events are interleaved.
- undeclared  -> NOT_ASSESSED, advisory: findings still report what an
                 actor scan found and how to opt in, but nothing
                 false-fails out of the box.

C8 never gates automation eligibility -- the gate set is deliberately
frozen at C2/C4/C5.
"""

from __future__ import annotations

from scanner.checks.base import Check, CheckContext, CheckResult
from scanner.config import DEFAULT_ACTOR_FIELD_CANDIDATES as _DEFAULT_ACTOR_CANDIDATES
from scanner.profiler import find_field_stats


class C8Actor(Check):
    check_id = "C8"
    name = "Actor / initiator"
    dimension = "completeness"

    def run(self, ctx: CheckContext) -> CheckResult:
        profile = ctx.profile
        record_count = profile.record_count
        event_class = ctx.source.event_class

        if record_count == 0:
            return self.result(
                "NOT_ASSESSED",
                findings=["no records were sampled for this source"],
                evidence={},
                records_passed=0,
                records_total=0,
            )

        if event_class == "state":
            return self.result(
                "NOT_ASSESSED",
                findings=[
                    (
                        "source is declared event_class: state -- state events (down, "
                        "degraded, threshold crossed) have no actor by definition, so "
                        "this check does not apply"
                    )
                ],
                evidence={"event_class": "state"},
                records_passed=0,
                records_total=record_count,
            )

        candidates = ctx.config.field_hints.actor or _DEFAULT_ACTOR_CANDIDATES
        best_field = None
        best_presence = 0
        for candidate in candidates:
            found = find_field_stats(profile.field_stats, candidate)
            if found and found[1].presence_count > best_presence:
                best_field, best_presence = found[0], found[1].presence_count

        presence_rate = (
            profile.field_stats[best_field].presence_rate if best_field is not None else 0.0
        )

        findings: list[str] = []
        if best_field is None:
            findings.append(f"no actor/initiator field found among {candidates}")
        else:
            findings.append(
                f"actor field '{best_field}' present in {best_presence}/{record_count} "
                f"records ({presence_rate:.1%})"
            )
            affected_field = ctx.affected_resolution.identifier_field
            if affected_field is not None and best_field.lower() == affected_field.lower():
                findings.append(
                    f"actor and affected-entity resolution both landed on '{best_field}' -- "
                    f"this source cannot distinguish who performed an action from who it "
                    f"was performed on (informational)"
                )

        evidence = {
            "event_class": event_class,
            "field": best_field,
            "presence_rate": presence_rate,
            "candidates_tried": list(candidates),
        }

        # Undeclared: advisory only. Report what the scan found, but stay
        # NOT_ASSESSED so nothing false-fails before the owner opts in.
        if event_class is None:
            findings.append(
                "event_class is not declared for this source -- C8 is advisory only; "
                "declare event_class: activity (or mixed) to score it, or state to "
                "mark it not applicable"
            )
            return self.result(
                "NOT_ASSESSED",
                findings=findings,
                evidence=evidence,
                records_passed=best_presence,
                records_total=record_count,
            )

        # Declared activity/mixed: scored, same bands as C5.
        if presence_rate == 0.0:
            status = "FAIL"
        elif presence_rate < 0.90:
            status = "WARN"
        else:
            status = "PASS"

        if event_class == "mixed" and status == "FAIL":
            status = "WARN"
            findings.append(
                "softened from FAIL to WARN: event_class is 'mixed', so some records "
                "legitimately have no actor"
            )

        return self.result(
            status,
            findings=findings,
            evidence=evidence,
            records_passed=best_presence,
            records_total=record_count,
        )
