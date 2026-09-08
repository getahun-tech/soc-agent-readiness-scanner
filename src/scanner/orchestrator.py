"""Wires adapters -> profiler -> check engine -> scoring -> estate aggregation
for a full scan run.

Errors on one source (bad glob, adapter not yet implemented) do not abort
the whole run -- partial results are more useful to an operator than a
single crash, and each source's status is reported individually. Only
sources that completed ("ok") participate in scoring, conflicts, the
estate summary, and recommendations.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from scanner.adapters.elastic import ElasticAdapter
from scanner.adapters.file import FileAdapter
from scanner.adapters.sentinel import SentinelAdapter
from scanner.adapters.splunk import SplunkAdapter
from scanner.asset_resolver import AssetResolver
from scanner.checks.base import CheckContext, CheckResult
from scanner.checks.completeness import COMPLETENESS_CHECKS
from scanner.config import ScannerConfig
from scanner.estate import (
    SourceEntry,
    build_estate_summary,
    build_recommendations,
    detect_conflicts,
)
from scanner.exceptions import AdapterError
from scanner.profiler import Profiler
from scanner.scoring import CompletenessScorer

_ADAPTERS = {
    "file": FileAdapter(),
    "splunk": SplunkAdapter(),
    "sentinel": SentinelAdapter(),
    "elastic": ElasticAdapter(),
}


def run_scan(
    config: ScannerConfig,
    config_path: str,
    source_names: list[str] | None = None,
    *,
    config_hash: str | None = None,
    operator: str | None = None,
) -> dict[str, Any]:
    sources = config.sources
    if source_names:
        wanted = set(source_names)
        unknown = wanted - {s.name for s in sources}
        if unknown:
            raise AdapterError(f"unknown source name(s): {sorted(unknown)}")
        sources = [s for s in sources if s.name in wanted]

    profiler = Profiler()
    scorer = CompletenessScorer()
    # One resolver, reused for both origin and affected-entity (C4) lookups --
    # it caches inventory loading internally; the two resolve() calls stay
    # independent because each takes its own candidate field list.
    asset_resolver = AssetResolver(
        config.inventory.path if config.inventory else None,
        config.inventory.match_fields if config.inventory else [],
    )
    results: dict[str, Any] = {}
    entries: list[SourceEntry] = []

    for source in sources:
        adapter = _ADAPTERS.get(source.adapter)
        if adapter is None:
            results[source.name] = {
                "status": "not_implemented",
                "error": (
                    f"adapter '{source.adapter}' is not configured (no adapter "
                    f"registered for kind '{source.adapter}')"
                ),
                "sample": None,
                "profile": None,
                "checks": None,
                "verdict": None,
            }
            continue
        try:
            records_iter, sample_meta = adapter.fetch_sample(source, config)
            records = list(records_iter)
            profile = profiler.profile(source.name, records)
        except AdapterError as exc:
            results[source.name] = {
                "status": "error",
                "error": str(exc),
                "sample": None,
                "profile": None,
                "checks": None,
                "verdict": None,
            }
            continue

        origin_resolution = asset_resolver.resolve(records, config.field_hints.origin)
        affected_resolution = asset_resolver.resolve(records, config.field_hints.affected)
        ctx = CheckContext(
            source=source,
            config=config,
            profile=profile,
            records=records,
            origin_resolution=origin_resolution,
            affected_resolution=affected_resolution,
        )
        checks: dict[str, CheckResult] = {c.check_id: c.run(ctx) for c in COMPLETENESS_CHECKS}
        verdict = scorer.score(source, checks)

        profile_json = profile.model_dump(mode="json")
        checks_json = {cid: cr.model_dump(mode="json") for cid, cr in checks.items()}

        origin_field = origin_resolution.identifier_field
        origin_values = (
            {
                str(r.parsed[origin_field])
                for r in records
                if r.parsed and r.parsed.get(origin_field) not in (None, "")
            }
            if origin_field
            else set()
        )
        entries.append(
            SourceEntry(
                name=source.name,
                source=source,
                checks=checks,
                verdict=verdict,
                origin_values=origin_values,
            )
        )

        results[source.name] = {
            "status": "ok",
            "error": None,
            "sample": asdict(sample_meta),
            "profile": profile_json,
            "checks": checks_json,
            "verdict": verdict.model_dump(mode="json"),
        }

    conflicts = detect_conflicts(entries, config.precedence_rules)
    estate_summary = build_estate_summary(entries)
    recommendations = build_recommendations(entries)

    return {
        "run_metadata": {
            "config_path": config_path,
            "config_hash": config_hash,
            "operator": operator,
            "config_version": config.version,
            "ruleset_version": config.ruleset_version,
            "generated_at": datetime.now(UTC).isoformat(),
            "sources_scanned": [s.name for s in sources],
        },
        "sources": results,
        "estate_summary": estate_summary.model_dump(mode="json"),
        "conflicts": [c.model_dump(mode="json") for c in conflicts],
        "recommendations": [r.model_dump(mode="json") for r in recommendations],
    }
