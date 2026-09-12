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

from scanner.config import DEFAULT_TIMESTAMP_FIELD_CANDIDATES
from scanner.models import RawRecord, get_field
from scanner.timeutil import parse_timestamp, to_comparable

_TIMESTAMP_FIELD_CANDIDATES = DEFAULT_TIMESTAMP_FIELD_CANDIDATES

# An "envelope" is a single nested key holding (nearly) the whole record,
# with only transport metadata beside it -- Splunk's JSON export
# (`preview`/`offset` + `result`), a raw Elastic export (`_source`),
# Windows XML-to-JSON (`Event`). Thresholds: the key must cover this share
# of a record's fields, in this share of records, to be called one.
_ENVELOPE_MIN_FIELD_SHARE = 0.8
_ENVELOPE_MIN_RECORD_SHARE = 0.9


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
    envelope_hint: str | None = None
    """Set when the records look wrapped in one envelope key (see
    _ENVELOPE_* above): the real fields sit one level down under this
    name, so field-hint matching will miss most of them. Reported, never
    acted on -- unwrapping is the source's explicit `record_root` decision."""


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
    def profile(
        self,
        source_name: str,
        records: list[RawRecord],
        timestamp_candidates: list[str] | None = None,
    ) -> ProfileResult:
        record_count = len(records)
        parsed = [r for r in records if r.parse_error is None]
        structured = [r for r in records if r.structured]
        parse_error_examples = [r.parse_error for r in records if r.parse_error][:5]

        field_stats = self._field_stats(records)
        distinct_field_sets, dominant_rate = self._field_set_variance(records)
        timestamp_analysis = self._timestamp_analysis(
            records, timestamp_candidates or _TIMESTAMP_FIELD_CANDIDATES
        )

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
            envelope_hint=self._envelope_hint(records),
        )

    def _envelope_hint(self, records: list[RawRecord]) -> str | None:
        """Adapters flatten nested objects to dotted keys, so an enveloped
        record shows up here as most keys sharing one first segment
        (`result.host`, `result._time`, ...) next to a couple of bare
        transport keys (`preview`, `offset`). A genuinely nested schema
        like ECS spreads keys across many prefixes and never trips this."""
        parsed = [r.parsed for r in records if r.parsed]
        if not parsed:
            return None
        votes: Counter[str] = Counter()
        for fields in parsed:
            keys = list(fields.keys())
            if len(keys) < 2:
                continue
            prefixes = Counter(k.split(".", 1)[0] for k in keys if "." in k)
            for prefix, count in prefixes.items():
                if count / len(keys) >= _ENVELOPE_MIN_FIELD_SHARE:
                    votes[prefix] += 1
        if not votes:
            return None
        prefix, count = votes.most_common(1)[0]
        return prefix if count / len(parsed) >= _ENVELOPE_MIN_RECORD_SHARE else None

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

    def _timestamp_analysis(
        self, records: list[RawRecord], candidates: list[str]
    ) -> TimestampAnalysis:
        record_count = len(records)
        if record_count == 0:
            return TimestampAnalysis(candidate_field=None, note="no records sampled")

        best_field: str | None = None
        best_count = 0
        for candidate in candidates:
            count = sum(1 for r in records if get_field(r.parsed, candidate) is not None)
            if count > best_count:
                best_field, best_count = candidate, count

        if best_field is None or best_count == 0:
            return TimestampAnalysis(
                candidate_field=None,
                note=f"no timestamp-like field found among candidates {list(candidates)}",
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
