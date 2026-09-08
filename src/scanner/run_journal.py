"""Append-only run journal: timestamp, operator identity, config hash,
ruleset version, sources scanned, sample sizes, and verdicts. This makes
the tool's own output defensible to an auditor.

Append-only is structural here, not just a naming convention: the file is
always opened in "a" mode and each entry is one JSON line, so a prior
entry can never be rewritten or truncated by a later run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel


class JournalEntry(BaseModel):
    timestamp: str
    operator: str
    config_path: str
    config_hash: str | None
    ruleset_version: str
    sources_scanned: list[str]
    sample_sizes: dict[str, int]
    verdicts: dict[str, dict[str, Any]]


def build_journal_entry(
    result: dict[str, Any], *, operator: str, config_path: str, config_hash: str | None
) -> JournalEntry:
    sample_sizes = {
        name: r["sample"]["actual_size"] for name, r in result["sources"].items() if r.get("sample")
    }
    verdicts: dict[str, dict[str, Any]] = {}
    for name, r in result["sources"].items():
        v = r.get("verdict")
        if v is None:
            continue
        comp, elig = v["completeness"], v["eligibility"]
        verdicts[name] = {
            "eligible": elig["eligible"],
            "completeness_score": f"{comp['score']}/{comp['denominator']}",
            "failed_gates": [g["gate_id"] for g in elig["gates"] if not g["passed"]],
        }

    return JournalEntry(
        timestamp=result["run_metadata"]["generated_at"],
        operator=operator,
        config_path=config_path,
        config_hash=config_hash,
        ruleset_version=result["run_metadata"]["ruleset_version"],
        sources_scanned=result["run_metadata"]["sources_scanned"],
        sample_sizes=sample_sizes,
        verdicts=verdicts,
    )


def append_journal_entry(path: str | Path, entry: JournalEntry) -> None:
    journal_path = Path(path)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    with journal_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(entry.model_dump_json())
        f.write("\n")
