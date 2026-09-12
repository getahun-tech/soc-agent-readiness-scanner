"""Resolves which records carry an identifier, given a candidate field list.

Used twice per source, independently: once for origin resolution
(`field_hints.origin` -- who reported the event) and once for C4's
affected-entity resolution (`field_hints.affected` -- who it happened to).
Each call is a fresh `resolve()` with its own candidate list; the two
resolutions must never be conflated.

Presence is the whole signal: a value that is present is assumed to be
truthful. The scanner does not verify identifiers against an external
asset list -- that is a deliberate scope decision, so the tool needs
nothing beyond the log itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.models import RawRecord, get_field


@dataclass(frozen=True)
class IdentifierResolution:
    identifier_field: str | None
    """The single most-common candidate, for display and for the checks
    that group/compare by one field name. None when no candidate is
    present in any record."""
    note: str | None
    """Why `identifier_field` is None, when it is."""
    record_count: int
    presence_count: int
    """Records in which *any* candidate field carries a value."""
    presence_rate: float
    distinct_value_count: int


class IdentifierResolver:
    def resolve(self, records: list[RawRecord], candidate_fields: list[str]) -> IdentifierResolution:
        """A record counts as having an identifier if *any* candidate field
        is present in it -- not just whichever single candidate happens to
        be present in the most records overall, since a source can mix
        field names across records (some `host`, some `src`) and each one
        still answers the question. `identifier_field` is still a single
        representative field (the individually most common), kept for
        display and for C2's clock-skew grouping and C4's
        same-field-as-origin distinguishability check -- it does not gate
        presence, which is computed per record across every candidate.
        """
        record_count = len(records)

        if not candidate_fields:
            return IdentifierResolution(
                identifier_field=None,
                note="no candidate identifier fields configured",
                record_count=record_count,
                presence_count=0,
                presence_rate=0.0,
                distinct_value_count=0,
            )

        per_candidate_counts = dict.fromkeys(candidate_fields, 0)
        present_count = 0
        seen_values: set[str] = set()

        for r in records:
            if not r.parsed:
                continue
            record_values = []
            for candidate in candidate_fields:
                value = get_field(r.parsed, candidate)
                if value not in (None, ""):
                    per_candidate_counts[candidate] += 1
                    record_values.append(str(value))
            if not record_values:
                continue
            present_count += 1
            seen_values.update(record_values)

        best_field = max(per_candidate_counts, key=lambda c: per_candidate_counts[c], default=None)
        if per_candidate_counts.get(best_field, 0) == 0:
            return IdentifierResolution(
                identifier_field=None,
                note=f"none of {candidate_fields} are present in the sample",
                record_count=record_count,
                presence_count=0,
                presence_rate=0.0,
                distinct_value_count=0,
            )

        return IdentifierResolution(
            identifier_field=best_field,
            note=None,
            record_count=record_count,
            presence_count=present_count,
            presence_rate=(present_count / record_count) if record_count else 0.0,
            distinct_value_count=len(seen_values),
        )
