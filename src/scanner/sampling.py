"""Deterministic, bounded sampling strategies (SPEC.md 9.2, 9.7).

Every strategy here is a single pass over its input stream and holds at
most ``limit`` items per group in memory at once -- we never materialize
a full source before sampling from it, and ties are broken by a seeded
RNG so identical input + seed always produces identical output.
"""

from __future__ import annotations

import random
from collections import deque
from collections.abc import Iterable, Iterator
from typing import TypeVar

T = TypeVar("T")


def reservoir_sample(stream: Iterable[T], limit: int, seed: int) -> list[T]:
    """Algorithm R: uniform sample of size <= limit from a stream of unknown length."""
    if limit <= 0:
        return []
    rng = random.Random(seed)
    reservoir: list[T] = []
    for i, item in enumerate(stream):
        if i < limit:
            reservoir.append(item)
        else:
            j = rng.randint(0, i)
            if j < limit:
                reservoir[j] = item
    return reservoir


def recent_sample(stream: Iterable[T], limit: int) -> list[T]:
    """The last `limit` items of the stream, in original order."""
    if limit <= 0:
        return []
    window: deque[T] = deque(maxlen=limit)
    for item in stream:
        window.append(item)
    return list(window)


def stratified_sample_by_group(
    grouped_streams: dict[str, Iterator[T]], limit: int, seed: int
) -> list[T]:
    """Reservoir-sample an even share of `limit` from each group.

    Groups are the file adapter's source files. Quota is split as evenly as
    possible; any remainder (limit % num_groups) goes to the groups that
    sort first by name, so the split is deterministic.
    """
    if limit <= 0 or not grouped_streams:
        return []
    names = sorted(grouped_streams)
    base_quota, remainder = divmod(limit, len(names))
    result: list[T] = []
    for i, name in enumerate(names):
        quota = base_quota + (1 if i < remainder else 0)
        if quota <= 0:
            continue
        # Derive a per-group seed so groups don't all draw the same sequence.
        group_seed = seed ^ hash(name) & 0xFFFFFFFF
        result.extend(reservoir_sample(grouped_streams[name], quota, group_seed))
    return result
