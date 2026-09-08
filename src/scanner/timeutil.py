"""Timestamp parsing shared by the profiler and the C2 temporal-quality check.

Pulled out on its own once a second consumer (C2) needed the exact same
parse behavior -- duplicating it would have let the two drift on what
counts as a parseable or timezone-explicit timestamp.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

_EPOCH_RE = re.compile(r"\d{10,13}(\.\d+)?")


def parse_timestamp(value: object) -> tuple[datetime | None, bool]:
    """Returns (parsed datetime, has_explicit_timezone)."""
    if isinstance(value, bool):
        return None, False
    if isinstance(value, int | float):
        return _epoch_to_datetime(float(value))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None, False
        if _EPOCH_RE.fullmatch(s):
            return _epoch_to_datetime(float(s))
        iso_candidate = re.sub(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:)", r"\1T\2", s)
        try:
            dt = datetime.fromisoformat(iso_candidate)
            return dt, dt.tzinfo is not None
        except ValueError:
            pass
        collapsed = re.sub(r"\s+", " ", s)
        for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                # Naive result is expected and desired here when `fmt` has no %z --
                # that's precisely how we detect a missing timezone.
                dt = datetime.strptime(collapsed, fmt)  # noqa: DTZ007
                return dt, dt.tzinfo is not None
            except ValueError:
                continue
    return None, False


def _epoch_to_datetime(v: float) -> tuple[datetime | None, bool]:
    try:
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=UTC), True
    except (OverflowError, OSError, ValueError):
        return None, False


def to_comparable(dt: datetime) -> datetime:
    """Naive and aware datetimes can't be compared/subtracted directly; treat
    naive as UTC for ordering/arithmetic purposes only (this does not
    fabricate a timezone in any report output)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
