"""Shared view-model construction for the Markdown and HTML renderers.

Both templates need the same shape (per-source checks, verdict attached,
estate summary/conflicts/recommendations passed through) -- built once
here so the two renderers can't drift on what a "source view" contains.
"""

from __future__ import annotations

from typing import Any

from scanner.config import ScannerConfig


def _build_source_view(name: str, result: dict[str, Any], config: ScannerConfig) -> dict[str, Any]:
    source_cfg = next(s for s in config.sources if s.name == name)
    checks = list(result["checks"].values()) if result.get("checks") else []
    profile = result.get("profile") or {}
    return {
        "name": name,
        "status": result["status"],
        "error": result["error"],
        "adapter": source_cfg.adapter,
        "owner": source_cfg.owner,
        "sample": result["sample"],
        "verdict": result.get("verdict"),
        "checks": checks,
        "envelope_hint": profile.get("envelope_hint"),
        "parse_error_examples": profile.get("parse_error_examples") or [],
        "log_profile": result.get("log_profile"),
    }


def build_view(run_result: dict[str, Any], config: ScannerConfig) -> dict[str, Any]:
    return {
        "run_metadata": run_result["run_metadata"],
        "sources": [
            _build_source_view(name, result, config) for name, result in run_result["sources"].items()
        ],
        "estate_summary": run_result["estate_summary"],
        "conflicts": run_result["conflicts"],
        "recommendations": run_result["recommendations"],
    }
