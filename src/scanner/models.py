"""Shared data structures passed between adapters, profiler, and checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RawRecord:
    """One sampled record.

    ``parsed`` is the best-effort structured view of the record. Adapters
    populate it via a parse cascade (JSON, then logfmt, then a raw-message
    fallback) so downstream checks always have *something* to inspect, while
    ``parse_error`` and ``structured`` let checks tell a clean parse apart
    from the fallback.
    """

    source_name: str
    index: int
    origin_path: str
    origin_line_no: int
    raw_text: str
    parsed: dict[str, Any] | None
    parse_error: str | None
    structured: bool


def get_field(parsed: dict[str, Any] | None, name: str) -> Any:
    """Case-insensitive lookup of `name` in a record's parsed dict.

    Field-hint candidates and a source's actual field names routinely
    differ only in casing (a candidate list entry `host` vs. a source
    that always emits `Host`) -- every check that matches a candidate
    name against `record.parsed` should go through this rather than a
    raw `.get()`, so that mismatch doesn't silently look like absence.
    """
    if not parsed:
        return None
    if name in parsed:
        return parsed[name]
    lowered = name.lower()
    for key, value in parsed.items():
        if key.lower() == lowered:
            return value
    return None


@dataclass(frozen=True)
class SampleMetadata:
    """Records how a sample was drawn, per SPEC.md 9.2 / 9.7."""

    source_name: str
    strategy: str
    seed: int
    requested_size: int
    population_size: int
    actual_size: int
    files_read: list[str] = field(default_factory=list)
