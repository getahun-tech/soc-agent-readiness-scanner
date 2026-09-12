"""Agent-readiness playbook: for a failing check, what field to add, what
decision it enables, and where the fix realistically lives.

The checks say what is missing. This says what to do about it -- and,
critically, *where*: engineers usually can't change a vendor's log
format, so a recommendation that just says "add this field" reads as
naive. Each remediation names its realistic implementation paths, most
likely first. Nothing here affects scores or gates; recommendations are
additive so they never turn into requirements by the back door.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, computed_field

from scanner.checks.base import CheckResult

FixPath = Literal["device", "pipeline", "query"]

FIX_PATH_LABELS: dict[FixPath, str] = {
    "device": "device/application logging configuration (vendor side)",
    "pipeline": "ingest-time enrichment or normalization (SIEM pipeline, Cribl, lookup)",
    "query": "query-time lookup in the SIEM",
}


class Remediation(BaseModel):
    add_fields: list[str]
    """What to add, as candidate names plus the shape that makes them useful."""
    enables: str
    """The decision an automation can make once the field exists."""
    where: list[FixPath]
    """Realistic implementation paths, most likely first."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def where_labels(self) -> list[str]:
        """Serialized alongside `where`, so the report templates (which see
        the JSON form) and JSON consumers both get the human labels."""
        return [FIX_PATH_LABELS[w] for w in self.where]


_STATIC: dict[str, Remediation] = {
    "C1": Remediation(
        add_fields=["event_type / action / signature -- a stable, bounded vocabulary, not free text"],
        enables=(
            "an agent can branch on the event class instead of parsing message text -- "
            "'what happened' becomes a fixed set of values, not a guess"
        ),
        where=["device", "pipeline"],
    ),
    "C3": Remediation(
        add_fields=["interface / site / host -- the finest granularity the device knows"],
        enables="the agent knows *where* to look or act; an interface beats a host beats a site",
        where=["device", "pipeline"],
    ),
    "C4": Remediation(
        add_fields=[
            (
                "dst / target / TargetUserName -- a field naming what the event happened to, "
                "distinct from the device that reported it"
            )
        ],
        enables=(
            "the agent knows what to act on, not only what reported it -- the difference "
            "between remediating the right host and the wrong one"
        ),
        where=["device", "pipeline"],
    ),
    "C5": Remediation(
        add_fields=["status / result / disposition -- a fixed enum (success/failure, allowed/blocked)"],
        enables="success vs. failure is a field test, not an inference from message text",
        where=["device", "pipeline"],
    ),
    "C7": Remediation(
        add_fields=["session_id / transaction_id / correlation_id -- one stable key per unit of work"],
        enables="events link into one incident instead of each line reading as a new one",
        where=["device", "pipeline"],
    ),
    "C8": Remediation(
        add_fields=["user / SubjectUserName / src_user -- the account or process that initiated the action"],
        enables=(
            "identity-touching actions (disable an account, kill a process) have a subject "
            "to act on"
        ),
        where=["device", "pipeline"],
    ),
}


def _c2_remediation(result: CheckResult) -> Remediation:
    """C2 fails for distinct reasons with distinct fixes -- read the
    evidence and recommend only what this source actually needs."""
    ev = result.evidence
    add: list[str] = []
    enables: list[str] = []
    where: list[FixPath] = []

    if ev.get("parseable_rate", 1.0) < 0.99 or ev.get("field") is None:
        add.append("timestamp -- ISO 8601, present on every record")
        enables.append("event order is trustworthy")
        where.append("device")
    if ev.get("naive_count", 0) > 0:
        add.append("an explicit UTC offset on the timestamp (e.g. 2026-01-01T00:00:00-04:00)")
        enables.append("timestamps from different sources compare without guessing the zone")
        if "device" not in where:
            where.append("device")
    if ev.get("event_ingest_ambiguous", False):
        add.append("ingest_time / _indextime -- when the SIEM received the event")
        enables.append("event-time vs. ingest-time lag is measurable (and delayed data is visible)")
        if "pipeline" not in where:
            where.append("pipeline")
    if ev.get("skew_assessed") and ev.get("max_abs_offset_seconds", 0) > ev.get("skew_threshold_seconds", 5):
        add.append("no new field -- synchronize the origins' clocks (NTP)")
        enables.append("cross-source correlation stops silently mis-ordering events")
        if "device" not in where:
            where.append("device")

    if not add:  # a WARN with none of the above named -- keep generic guidance
        add.append("timestamp -- ISO 8601 with explicit UTC offset; plus ingest_time")
        enables.append("event order and event-vs-ingest lag are trustworthy")
        where = ["device", "pipeline"]

    return Remediation(add_fields=add, enables="; ".join(enables), where=where)


def remediation_for(result: CheckResult) -> Remediation | None:
    """None for checks with nothing to recommend (C6 is advisory only)."""
    if result.check_id == "C2":
        return _c2_remediation(result)
    return _STATIC.get(result.check_id)


# Context fields an agent needs to act *safely* that almost never come
# from the device -- they come from the asset inventory or the change
# calendar, and reach the record via enrichment. Checked for presence
# only; never scored.
CONTEXT_FIELDS: list[tuple[str, list[str], str]] = [
    (
        "maintenance_window",
        ["maintenance_window", "in_maintenance", "maintenance"],
        "prevents an agent from 'remediating' a host that is intentionally down",
    ),
    (
        "environment",
        ["environment", "env", "deployment_tier", "stage"],
        "lets an agent calibrate how aggressive to be (prod vs. dev)",
    ),
    (
        "asset_criticality",
        ["asset_criticality", "criticality", "asset_tier", "business_criticality"],
        "lets an agent weigh impact before acting",
    ),
]


def missing_context_fields(field_names: set[str]) -> list[tuple[str, str]]:
    """(canonical name, why) for each context field with no candidate
    present. Case-insensitive, same as every other field match."""
    lowered = {f.lower() for f in field_names}
    return [
        (name, why)
        for name, candidates, why in CONTEXT_FIELDS
        if not any(c.lower() in lowered for c in candidates)
    ]
