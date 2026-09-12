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


FLATTEN_MAX_DEPTH = 16
"""Nesting deeper than this is kept as an opaque leaf value rather than
recursed into. Real log documents are 2-4 levels deep; the bound exists so
a pathological or adversarial document can't turn one record into an
unbounded number of keys or exhaust the stack."""


def flatten_record(obj: dict[str, Any], *, max_depth: int = FLATTEN_MAX_DEPTH) -> dict[str, Any]:
    """Flatten nested mappings into dotted-path keys: ``{"a": {"b": 1}}``
    becomes ``{"a.b": 1}``.

    Every check matches field-hint candidates against a record's *top-level*
    keys, and the built-in candidate lists already carry dotted names from
    the nested schemas (ECS ``destination.ip``, ``agent.hostname``,
    CloudTrail ``userIdentity.userName``). Without flattening those names
    never match, because a real ECS document nests them as objects -- so
    every adapter that can produce nested records runs its output through
    this before the profiler sees it.

    Rules, chosen to keep the field set bounded and honest:

    - Lists stay leaf values, never exploded into ``tags.0``/``tags.1`` --
      a multivalue field is one field, not an open-ended set of keys.
    - Empty mappings are dropped; they carry no observable field.
    - Beyond ``max_depth`` the mapping is kept as an opaque leaf.
    - A dotted-key collision (a literal ``"a.b"`` key alongside a nested
      ``a -> b``) resolves to whichever comes later in iteration order.
      Documented rather than defended: real exports don't do this.
    """
    out: dict[str, Any] = {}
    _flatten_into(out, obj, "", 0, max_depth)
    return out


def _flatten_into(
    out: dict[str, Any], obj: dict[str, Any], prefix: str, depth: int, max_depth: int
) -> None:
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and depth < max_depth:
            if value:
                _flatten_into(out, value, f"{path}.", depth + 1, max_depth)
            continue
        out[path] = value


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
