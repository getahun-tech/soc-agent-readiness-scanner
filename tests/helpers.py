"""Shared test helper for building a CheckContext directly from a fixture
file, without going through the full orchestrator.
"""

from __future__ import annotations

from scanner.adapters.file import FileAdapter
from scanner.asset_resolver import AssetResolver
from scanner.checks.base import CheckContext
from scanner.config import DefaultsConfig, FieldHints, PrecedenceRule, ScannerConfig, SourceConfig
from scanner.profiler import Profiler


def build_ctx(
    path: str,
    *,
    sample_size: int = 100,
    sample_strategy: str = "random",
    seed: int = 1,
    inventory_path: str | None = None,
    match_fields: list[str] | None = None,
    origin_hints: list[str] | None = None,
    affected_hints: list[str] | None = None,
    outcome_hints: list[str] | None = None,
    correlation_hints: list[str] | None = None,
    authoritative_over: list[str] | None = None,
    precedence_rules: list[PrecedenceRule] | None = None,
    source_name: str = "src",
) -> CheckContext:
    origin_hints = origin_hints or []
    affected_hints = affected_hints or []
    outcome_hints = outcome_hints or []
    correlation_hints = correlation_hints or []
    source = SourceConfig(
        name=source_name,
        adapter="file",
        path=path,
        owner="ops@example.com",
        authoritative_over=authoritative_over or [],
    )
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(
            sample_size=sample_size, sample_strategy=sample_strategy, seed=seed
        ),
        field_hints=FieldHints(
            origin=origin_hints,
            affected=affected_hints,
            outcome=outcome_hints,
            correlation=correlation_hints,
        ),
        sources=[source],
        precedence_rules=precedence_rules or [],
    )
    records_iter, _ = FileAdapter().fetch_sample(source, cfg)
    records = list(records_iter)
    profile = Profiler().profile(source.name, records)
    resolver = AssetResolver(inventory_path, match_fields or [])
    origin_resolution = resolver.resolve(records, origin_hints)
    affected_resolution = resolver.resolve(records, affected_hints)
    return CheckContext(
        source=source,
        config=cfg,
        profile=profile,
        records=records,
        origin_resolution=origin_resolution,
        affected_resolution=affected_resolution,
    )
