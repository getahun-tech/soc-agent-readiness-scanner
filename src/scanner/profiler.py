"""Statistical profiling of a sample (SPEC.md section 4).

The profiler makes no PASS/WARN/FAIL judgment -- that's the check engine's
job in later phases. It only computes the raw statistics those checks (and
a human skimming --output raw JSON) will need: field presence, type
consistency, cardinality, structural (format) variance, and a best-effort
timestamp presence/parseability/monotonicity read.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from itertools import pairwise
from typing import Any

from pydantic import BaseModel, Field

from scanner.models import RawRecord, get_field
from scanner.timeutil import parse_timestamp, to_comparable

_TIMESTAMP_FIELD_CANDIDATES = [
    "timestamp",
    "@timestamp",
    "time",
    "ts",
    "event_time",
    "datetime",
    "date",
]


class FieldStats(BaseModel):
    presence_count: int
    presence_rate: float
    types: dict[str, int]
    distinct_value_count: int
    top_values: list[Any]


def find_field_stats(field_stats: dict[str, FieldStats], candidate: str) -> tuple[str, FieldStats] | None:
    """Case-insensitive lookup of `candidate` against a profile's
    field_stats keys. Returns the field's actual (originally-observed)
    name alongside its stats -- not the candidate's own casing -- since
    the real field name from the data is what findings should report."""
    if candidate in field_stats:
        return candidate, field_stats[candidate]
    lowered = candidate.lower()
    for key, stats in field_stats.items():
        if key.lower() == lowered:
            return key, stats
    return None


class TimestampAnalysis(BaseModel):
    candidate_field: str | None
    presence_rate: float = 0.0
    parse_rate: float = 0.0
    explicit_timezone_rate: float = 0.0
    out_of_order_pairs: int = 0
    out_of_order_rate: float = 0.0
    note: str


class ProfileResult(BaseModel):
    source_name: str
    record_count: int
    parsed_count: int
    parse_rate: float
    structured_count: int
    structured_rate: float
    distinct_field_sets: int
    dominant_field_set_rate: float
    field_stats: dict[str, FieldStats]
    timestamp_analysis: TimestampAnalysis
    parse_error_examples: list[str] = Field(default_factory=list)


def _value_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    return type(value).__name__


def _hashable_repr(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


class Profiler:
    def profile(self, source_name: str, records: list[RawRecord]) -> ProfileResult:
        record_count = len(records)
        parsed = [r for r in records if r.parse_error is None]
        structured = [r for r in records if r.structured]
        parse_error_examples = [r.parse_error for r in records if r.parse_error][:5]

        field_stats = self._field_stats(records)
        distinct_field_sets, dominant_rate = self._field_set_variance(records)
        timestamp_analysis = self._timestamp_analysis(records)

        return ProfileResult(
            source_name=source_name,
            record_count=record_count,
            parsed_count=len(parsed),
            parse_rate=(len(parsed) / record_count) if record_count else 0.0,
            structured_count=len(structured),
            structured_rate=(len(structured) / record_count) if record_count else 0.0,
            distinct_field_sets=distinct_field_sets,
            dominant_field_set_rate=dominant_rate,
            field_stats=field_stats,
            timestamp_analysis=timestamp_analysis,
            parse_error_examples=[e for e in parse_error_examples if e],
        )

    def _field_stats(self, records: list[RawRecord]) -> dict[str, FieldStats]:
        record_count = len(records)
        presence: Counter[str] = Counter()
        type_counts: dict[str, Counter[str]] = defaultdict(Counter)
        value_counts: dict[str, Counter[str]] = defaultdict(Counter)
        value_examples: dict[str, dict[str, Any]] = defaultdict(dict)

        for r in records:
            if not r.parsed:
                continue
            for key, value in r.parsed.items():
                presence[key] += 1
                type_counts[key][_value_type_name(value)] += 1
                repr_key = _hashable_repr(value)
                value_counts[key][repr_key] += 1
                value_examples[key].setdefault(repr_key, value)

        stats: dict[str, FieldStats] = {}
        for key, count in presence.items():
            top = value_counts[key].most_common(5)
            stats[key] = FieldStats(
                presence_count=count,
                presence_rate=(count / record_count) if record_count else 0.0,
                types=dict(type_counts[key]),
                distinct_value_count=len(value_counts[key]),
                top_values=[value_examples[key][repr_key] for repr_key, _ in top],
            )
        return stats

    def _field_set_variance(self, records: list[RawRecord]) -> tuple[int, float]:
        shapes: Counter[frozenset[str]] = Counter()
        for r in records:
            if r.parsed:
                shapes[frozenset(r.parsed.keys())] += 1
        if not shapes:
            return 0, 0.0
        total = sum(shapes.values())
        dominant = shapes.most_common(1)[0][1]
        return len(shapes), dominant / total

    def _timestamp_analysis(self, records: list[RawRecord]) -> TimestampAnalysis:
        record_count = len(records)
        if record_count == 0:
            return TimestampAnalysis(candidate_field=None, note="no records sampled")

        best_field: str | None = None
        best_count = 0
        for candidate in _TIMESTAMP_FIELD_CANDIDATES:
            count = sum(1 for r in records if get_field(r.parsed, candidate) is not None)
            if count > best_count:
                best_field, best_count = candidate, count

        if best_field is None or best_count == 0:
            return TimestampAnalysis(
                candidate_field=None,
                note=(
                    "no timestamp-like field found among candidates "
                    f"{_TIMESTAMP_FIELD_CANDIDATES}"
                ),
            )

        parsed_values = 0
        tz_explicit = 0
        for r in records:
            value = get_field(r.parsed, best_field)
            if value is None:
                continue
            dt, has_tz = parse_timestamp(value)
            if dt is not None:
                parsed_values += 1
                if has_tz:
                    tz_explicit += 1

        by_origin: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
        for r in records:
            value = get_field(r.parsed, best_field)
            if value is None:
                continue
            dt, _ = parse_timestamp(value)
            if dt is not None:
                by_origin[r.origin_path].append((r.origin_line_no, dt))

        out_of_order = 0
        total_pairs = 0
        for origin_records in by_origin.values():
            origin_records.sort(key=lambda pair: pair[0])
            for (_, prev_dt), (_, next_dt) in pairwise(origin_records):
                total_pairs += 1
                prev_cmp, next_cmp = to_comparable(prev_dt), to_comparable(next_dt)
                if next_cmp < prev_cmp:
                    out_of_order += 1

        return TimestampAnalysis(
            candidate_field=best_field,
            presence_rate=best_count / record_count,
            parse_rate=(parsed_values / best_count) if best_count else 0.0,
            explicit_timezone_rate=(tz_explicit / parsed_values) if parsed_values else 0.0,
            out_of_order_pairs=out_of_order,
            out_of_order_rate=(out_of_order / total_pairs) if total_pairs else 0.0,
            note=(
                f"monotonicity checked within each origin file, ordered by line number "
                f"({total_pairs} adjacent pairs compared)"
            ),
        )
