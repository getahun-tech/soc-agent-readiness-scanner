"""Matches record identifiers against a supplied asset inventory.

Used twice per source, independently: once for origin resolution
(`field_hints.origin`) and once for C4's affected-entity resolution
(`field_hints.affected`). Each call is a fresh `resolve()` with its own
candidate field list -- the two resolutions must never be conflated.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanner.models import RawRecord, get_field


@dataclass(frozen=True)
class AttributionResult:
    identifier_field: str | None
    inventory_loaded: bool
    inventory_note: str | None
    record_count: int
    presence_count: int
    presence_rate: float
    matched_count: int | None
    match_rate: float | None
    distinct_value_count: int
    unmatched_examples: list[str] = field(default_factory=list)

    @property
    def attributable_count(self) -> int:
        """Records resolvable to a known asset, out of the full sample.

        Distinct from `match_rate` (which is scoped to records that *had*
        an identifier value at all) -- this is the count-over-record_count
        figure that completeness gates use.
        """
        return self.matched_count or 0

    @property
    def attributable_rate(self) -> float:
        return (self.attributable_count / self.record_count) if self.record_count else 0.0


class AssetResolver:
    def __init__(self, inventory_path: str | None, match_fields: list[str]):
        self._inventory_path = inventory_path
        self._match_fields = match_fields
        self._known_values: set[str] | None = None
        self._load_error: str | None = None
        self._loaded = False
        self._attempted = False

    @staticmethod
    def _normalize(value: Any) -> str:
        return str(value).strip().lower()

    def _ensure_loaded(self) -> None:
        if self._attempted:
            return
        self._attempted = True
        if not self._inventory_path:
            self._load_error = "no inventory file configured"
            return
        path = Path(self._inventory_path)
        if not path.exists():
            self._load_error = f"inventory file not found: {path}"
            return
        known: set[str] = set()
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fields = self._match_fields or list(reader.fieldnames or [])
            for row in reader:
                for column in fields:
                    value = row.get(column)
                    if value:
                        known.add(self._normalize(value))
        self._known_values = known
        self._loaded = True

    def resolve(self, records: list[RawRecord], candidate_fields: list[str]) -> AttributionResult:
        """A record counts as having an identifier if *any* candidate field
        is present in it -- not just whichever single candidate happens to
        be present in the most records overall. `identifier_field` in the
        result is still a single representative field (whichever candidate
        is individually most common), kept only for display and for the
        other checks that group/compare by one field name (C2's clock-skew
        grouping, C4's same-field-as-origin distinguishability check) -- it
        does not gate presence or inventory matching, both of which are
        computed per-record across every candidate at once.
        """
        self._ensure_loaded()
        record_count = len(records)

        if not candidate_fields:
            return AttributionResult(
                identifier_field=None,
                inventory_loaded=self._loaded,
                inventory_note=self._load_error or "no candidate identifier fields configured",
                record_count=record_count,
                presence_count=0,
                presence_rate=0.0,
                matched_count=0 if self._loaded else None,
                match_rate=0.0 if self._loaded else None,
                distinct_value_count=0,
            )

        per_candidate_counts = dict.fromkeys(candidate_fields, 0)
        present_count = 0
        seen_values: set[str] = set()
        matched_count_local = 0
        unmatched_examples: list[str] = []

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
            if self._loaded:
                if any(self._normalize(v) in self._known_values for v in record_values):  # type: ignore[operator]
                    matched_count_local += 1
                elif len(unmatched_examples) < 5:
                    unmatched_examples.append(record_values[0])

        best_field = max(per_candidate_counts, key=lambda c: per_candidate_counts[c], default=None)
        if per_candidate_counts.get(best_field, 0) == 0:
            best_field = None

        if best_field is None:
            return AttributionResult(
                identifier_field=None,
                inventory_loaded=self._loaded,
                inventory_note=self._load_error
                or f"none of {candidate_fields} are present in the sample",
                record_count=record_count,
                presence_count=0,
                presence_rate=0.0,
                matched_count=0 if self._loaded else None,
                match_rate=0.0 if self._loaded else None,
                distinct_value_count=0,
            )

        matched_count: int | None = matched_count_local if self._loaded else None
        match_rate: float | None = None
        if self._loaded:
            match_rate = (matched_count_local / present_count) if present_count else 0.0

        return AttributionResult(
            identifier_field=best_field,
            inventory_loaded=self._loaded,
            inventory_note=self._load_error,
            record_count=record_count,
            presence_count=present_count,
            presence_rate=(present_count / record_count) if record_count else 0.0,
            matched_count=matched_count,
            match_rate=match_rate,
            distinct_value_count=len(seen_values),
            unmatched_examples=unmatched_examples,
        )
