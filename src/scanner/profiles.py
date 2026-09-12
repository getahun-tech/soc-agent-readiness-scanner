"""Log-type profiles: what a known log type carries when it's configured
correctly, and which of its fields play which role.

The generic checks judge every source against one set of expectations:
*some* event-type field, *some* outcome field, from the built-in
candidate lists. That's right when nothing is known about the source.
Usually something is: it's `pan:traffic`, or `WinEventLog:Security`,
and knowing that changes what "complete" means -- a Palo Alto traffic
log without `action` isn't a format limitation, it's a misconfigured
logging profile.

Profiles are **additive**, never authoritative:

- Role hints are *prepended* to the generic candidate lists, so C1-C8
  look in the right place first but still fall back to everything they
  would have tried anyway. A stale profile can misdirect a lookup; it
  cannot hide a field.
- `event_class` from a profile applies only when the source didn't
  declare one.
- Conformance to the profile's expected fields is reported as an
  ADVISORY recommendation with the vendor guidance attached. It never
  scores and never gates. The C1-C8 verdicts are exactly what they would
  be without the profile.

Detection is automatic when the data says what it is (`sourcetype` for
Splunk, `Type` for Sentinel, `event.dataset` for Elastic), explicit via
`profile:` in config otherwise, and off with `profile: none`. A source
mixing several log types gets told so, with the split -- no profile is
guessed from a plurality.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from scanner.config import EventClass, FieldHints, SourceConfig
from scanner.models import RawRecord, get_field
from scanner.profiler import FieldStats, find_field_stats

_BUNDLED_DIR = Path(__file__).parent / "profiles"

# Fields whose value names the log type, in order of preference. Splunk,
# Sentinel/Log Analytics, ECS, then common hand-rolled names.
SOURCETYPE_FIELDS = [
    "sourcetype",
    "Type",
    "event.dataset",
    "data_stream.dataset",
    "event.module",
    "source_type",
    "log_type",
    "logtype",
]
_MIN_SOURCETYPE_PRESENCE = 0.5
"""A sourcetype-like field must be present in at least this share of
records to be trusted as saying what the source is."""
_DOMINANT_SHARE = 0.9
"""One value must account for at least this share of records for a
profile to be applied; below it the source is reported as mixed."""


class ProfileError(Exception):
    """A profile file or directory that can't be used."""


class ExpectedField(BaseModel):
    name: str
    aliases: list[str] = Field(default_factory=list)
    presence: float = Field(default=1.0, ge=0.0, le=1.0)
    """Minimum presence rate a correctly configured source shows."""
    note: str | None = None
    """When the field is legitimately conditional ("session-end records only")."""


class ProfileRoles(BaseModel):
    event_type: list[str] = Field(default_factory=list)
    timestamp: list[str] = Field(default_factory=list)
    origin: list[str] = Field(default_factory=list)
    affected: list[str] = Field(default_factory=list)
    outcome: list[str] = Field(default_factory=list)
    correlation: list[str] = Field(default_factory=list)
    actor: list[str] = Field(default_factory=list)


class ProfileMatch(BaseModel):
    sourcetype: list[str] = Field(default_factory=list)
    """Values (glob patterns, case-insensitive) of a sourcetype-like field."""


class LogProfile(BaseModel):
    id: str
    name: str
    vendor: str | None = None
    match: ProfileMatch
    event_class: EventClass | None = None
    roles: ProfileRoles = Field(default_factory=ProfileRoles)
    expected_fields: list[ExpectedField] = Field(default_factory=list)
    guidance: str | None = None
    """What to do when expected fields are missing -- vendor-specific."""
    notes: str | None = None

    def matches_exactly(self, value: str) -> bool:
        v = value.strip().lower()
        return any(v == p.lower() for p in self.match.sourcetype)

    def matches(self, value: str) -> bool:
        v = value.strip().lower()
        return any(fnmatchcase(v, p.lower()) for p in self.match.sourcetype)


class ProfileRegistry:
    def __init__(self, profiles: dict[str, LogProfile]):
        self._profiles = dict(profiles)

    @classmethod
    def load(cls, extra_dirs: list[str] | tuple[str, ...] = ()) -> ProfileRegistry:
        """Bundled profiles first, then each extra directory in order; a
        later file with the same `id` replaces an earlier one, so an org
        can override a bundled profile by shipping its own copy."""
        profiles: dict[str, LogProfile] = {}
        for directory in [_BUNDLED_DIR, *(Path(d) for d in extra_dirs)]:
            if not directory.is_dir():
                raise ProfileError(f"profile directory not found: {directory}")
            for path in sorted(directory.glob("*.yaml")):
                try:
                    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                    profile = LogProfile.model_validate(raw)
                except (yaml.YAMLError, ValidationError) as exc:
                    raise ProfileError(f"invalid profile {path}: {exc}") from exc
                profiles[profile.id] = profile
        return cls(profiles)

    def get(self, profile_id: str) -> LogProfile | None:
        return self._profiles.get(profile_id)

    def all(self) -> list[LogProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.id)

    def match_sourcetype(self, value: str) -> LogProfile | None:
        """An exact match beats a glob match (`Perfmon:*` must not win over
        a profile that names the exact sourcetype); ties break by id."""
        exact = [p for p in self.all() if p.matches_exactly(value)]
        if exact:
            return exact[0]
        globbed = [p for p in self.all() if p.matches(value)]
        return globbed[0] if globbed else None


@dataclass(frozen=True)
class ProfileSelection:
    profile: LogProfile | None
    summary: str
    """One human-readable line for the report header, whatever happened."""
    sourcetype_field: str | None = None
    distribution: dict[str, float] = field(default_factory=dict)
    mixed: bool = False


def _sourcetype_distribution(records: list[RawRecord]) -> tuple[str | None, dict[str, float]]:
    parsed = [r.parsed for r in records if r.parsed]
    if not parsed:
        return None, {}
    best_field, best_count = None, 0
    for candidate in SOURCETYPE_FIELDS:
        count = sum(1 for p in parsed if get_field(p, candidate) not in (None, ""))
        if count > best_count:
            best_field, best_count = candidate, count
    if best_field is None or best_count / len(parsed) < _MIN_SOURCETYPE_PRESENCE:
        return None, {}
    counter: Counter[str] = Counter(
        str(get_field(p, best_field)) for p in parsed if get_field(p, best_field) not in (None, "")
    )
    total = sum(counter.values())
    return best_field, {value: n / total for value, n in counter.most_common()}


def select_profile(
    source: SourceConfig, records: list[RawRecord], registry: ProfileRegistry
) -> ProfileSelection:
    if source.profile == "none":
        return ProfileSelection(None, "profile detection disabled (profile: none); generic checks only")

    if source.profile:
        profile = registry.get(source.profile)
        if profile is None:
            available = ", ".join(p.id for p in registry.all())
            return ProfileSelection(
                None,
                f"profile '{source.profile}' is not in the registry (available: {available}); "
                f"generic checks only",
            )
        return ProfileSelection(profile, f"{profile.name} ({profile.id}, declared in config)")

    field_name, distribution = _sourcetype_distribution(records)
    if field_name is None:
        return ProfileSelection(
            None,
            "no sourcetype-like field found in the sample (looked for "
            + ", ".join(SOURCETYPE_FIELDS)
            + "); generic checks only -- set profile: to declare the log type",
        )

    top_value, top_share = next(iter(distribution.items()))
    if top_share < _DOMINANT_SHARE:
        shares = "; ".join(f"{v} {s:.0%}" for v, s in list(distribution.items())[:6])
        return ProfileSelection(
            None,
            f"mixed log types in one source -- {field_name}: {shares} -- no profile applied; "
            f"split this source by {field_name} (one query or file per type) so each is "
            f"scored against what it should carry",
            field_name,
            distribution,
            mixed=True,
        )

    profile = registry.match_sourcetype(top_value)
    if profile is None:
        return ProfileSelection(
            None,
            f"{field_name}='{top_value}' has no profile; generic checks only -- see PROFILES.md "
            f"to add one",
            field_name,
            distribution,
        )
    return ProfileSelection(
        profile,
        f"{profile.name} ({profile.id}, auto-detected from {field_name}='{top_value}')",
        field_name,
        distribution,
    )


def _merge(first: list[str], second: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in [*first, *second]:
        if value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


def effective_field_hints(base: FieldHints, profile: LogProfile | None) -> FieldHints:
    """Profile roles first, then everything the config would have tried
    anyway -- so a profile can only add places to look."""
    if profile is None:
        return base
    r = profile.roles
    return FieldHints(
        origin=_merge(r.origin, base.origin),
        affected=_merge(r.affected, base.affected),
        outcome=_merge(r.outcome, base.outcome),
        correlation=_merge(r.correlation, base.correlation),
        actor=_merge(r.actor, base.actor),
        event_type=_merge(r.event_type, base.event_type),
        timestamp=_merge(r.timestamp, base.timestamp),
    )


def conformance(profile: LogProfile, field_stats: dict[str, FieldStats]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for expected in profile.expected_fields:
        observed_field, observed = None, 0.0
        for candidate in [expected.name, *expected.aliases]:
            found = find_field_stats(field_stats, candidate)
            if found and found[1].presence_rate > observed:
                observed_field, observed = found[0], found[1].presence_rate
        rows.append(
            {
                "field": expected.name,
                "expected_presence": expected.presence,
                "observed_presence": observed,
                "observed_field": observed_field,
                "shortfall": observed + 1e-9 < expected.presence,
                "note": expected.note,
            }
        )
    return rows


def describe_selection(selection: ProfileSelection, field_stats: dict[str, FieldStats]) -> dict[str, Any]:
    """The JSON-shaped record of what happened, for the report and the
    estate-level recommendation."""
    profile = selection.profile
    rows = conformance(profile, field_stats) if profile else []
    return {
        "id": profile.id if profile else None,
        "name": profile.name if profile else None,
        "summary": selection.summary,
        "sourcetype_field": selection.sourcetype_field,
        "distribution": selection.distribution,
        "mixed": selection.mixed,
        "expected_fields": rows,
        "shortfalls": [r for r in rows if r["shortfall"]],
        "guidance": profile.guidance if profile else None,
    }
