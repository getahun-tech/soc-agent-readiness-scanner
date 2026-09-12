"""JSONL renderer: one event per line, shaped for re-ingestion into a SIEM.

The other formats are for a person reading a report once. This one is
for a dashboard: point Splunk or Sentinel at the output file (or pipe it
to `curl` against an HTTP Event Collector / Log Analytics ingestion
endpoint) and completeness becomes something you can trend over time in
the tool the audience already watches, instead of a document that goes
stale the moment it's read.

Every line is a self-contained JSON object -- no line depends on any
other to be parsed -- tagged with `event_type` so one index can hold all
of them and a query can `where event_type="check_result"` to filter:

- `scan`            -- one per run: what ran, against what config.
- `source_summary`  -- one per source: status, score, eligibility, sample.
- `check_result`    -- one per check per completed source: status, score,
                        findings, evidence. This is what a "completeness
                        over time" chart is built from.
- `conflict`         -- one per estate-level conflict finding.
- `recommendation`   -- one per recommendation, remediation attached.

Every line also carries `time` (the run's `generated_at`, so the
consuming system's own time-based indexing works without extra
configuration) and `run_id` (config hash + timestamp) so every line from
one invocation can be grouped back together after ingestion.
"""

from __future__ import annotations

import json
from typing import Any

from scanner.config import ScannerConfig
from scanner.renderers.view_model import build_view


def _run_id(run_metadata: dict[str, Any]) -> str:
    return f"{run_metadata.get('config_hash') or 'nohash'}-{run_metadata['generated_at']}"


def _event(
    event_type: str, *, time: str, run_id: str, config_path: str, ruleset_version: str, **fields: Any
) -> str:
    record = {
        "time": time,
        "run_id": run_id,
        "event_type": event_type,
        "config_path": config_path,
        "ruleset_version": ruleset_version,
        **fields,
    }
    # sort_keys, same as the JSON renderer: two runs over the same input
    # produce byte-identical lines, not just equal-once-parsed ones.
    return json.dumps(record, sort_keys=True)


def render_jsonl(run_result: dict[str, Any], config: ScannerConfig) -> str:
    view = build_view(run_result, config)
    rm = view["run_metadata"]
    common = {
        "time": rm["generated_at"],
        "run_id": _run_id(rm),
        "config_path": rm["config_path"],
        "ruleset_version": rm["ruleset_version"],
    }

    lines: list[str] = [
        _event(
            "scan",
            **common,
            operator=rm.get("operator"),
            config_hash=rm.get("config_hash"),
            config_version=rm.get("config_version"),
            sources_scanned=rm["sources_scanned"],
            sources_scanned_count=len(rm["sources_scanned"]),
        )
    ]

    for s in view["sources"]:
        if s["status"] != "ok":
            lines.append(
                _event("source_summary", **common, source=s["name"], status=s["status"], error=s["error"])
            )
            continue

        comp = s["verdict"]["completeness"]
        elig = s["verdict"]["eligibility"]
        log_profile = s.get("log_profile") or {}
        lines.append(
            _event(
                "source_summary",
                **common,
                source=s["name"],
                status="ok",
                error=None,
                adapter=s["adapter"],
                owner=s["owner"],
                sample_strategy=s["sample"]["strategy"],
                sample_seed=s["sample"]["seed"],
                sample_requested_size=s["sample"]["requested_size"],
                sample_actual_size=s["sample"]["actual_size"],
                sample_population_size=s["sample"]["population_size"],
                completeness_score=comp["score"],
                completeness_denominator=comp["denominator"],
                completeness_percent=comp["percent"],
                eligible=elig["eligible"],
                failed_gates=[g["gate_id"] for g in elig["gates"] if not g["passed"]],
                log_profile_id=log_profile.get("id"),
                log_profile_mixed=log_profile.get("mixed", False),
            )
        )

        for c in s["checks"]:
            lines.append(
                _event(
                    "check_result",
                    **common,
                    source=s["name"],
                    check_id=c["check_id"],
                    check_name=c["name"],
                    status=c["status"],
                    score=c["score"],
                    records_passed=c.get("records_passed"),
                    records_total=c.get("records_total"),
                    records_failed=c.get("records_failed"),
                    records_failed_percent=c.get("records_failed_percent"),
                    findings=c["findings"],
                    evidence=c["evidence"],
                )
            )

    for conflict in view["conflicts"]:
        lines.append(
            _event(
                "conflict",
                **common,
                category=conflict["category"],
                severity=conflict["severity"],
                sources=conflict["sources"],
                description=conflict["description"],
            )
        )

    for rec in view["recommendations"]:
        lines.append(
            _event(
                "recommendation",
                **common,
                source=rec["source"],
                check_id=rec["check_id"],
                check_name=rec["check_name"],
                status=rec["status"],
                owner=rec["owner"],
                finding=rec["finding"],
                remediation=rec.get("remediation"),
            )
        )

    return "\n".join(lines) + "\n"
