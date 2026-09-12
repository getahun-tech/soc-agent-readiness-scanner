"""Run-to-run comparison against the journal: what got worse since last time.

A single scan says whether a source is fit to automate against. The
question that keeps a scanner installed is different: *did anything
change?* -- a vendor firmware update that silently dropped the timezone
from every timestamp, a log profile edit that removed the target field.
Per-record checks can't see that; only comparing two runs can.

The baseline is the previous journal entry for the same config path.
Journal entries carry each source's eligibility, failed gates, score,
and (since per-check statuses were added) every check's status, so the
journal alone is enough to diff -- no report files to keep around.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, computed_field

# PASS > WARN > {FAIL, NOT_ASSESSED}. A check that was assessed and now
# isn't (the timestamp field vanished, so C2 can't run) is a regression
# from PASS/WARN; FAIL <-> NOT_ASSESSED is a lateral move -- neither is
# clearly worse than the other, so it never trips a CI gate.
STATUS_RANK: dict[str, int] = {"PASS": 3, "WARN": 2, "FAIL": 1, "NOT_ASSESSED": 1}
Direction = Literal["regression", "improvement", "lateral"]


def _direction(before: str, after: str) -> Direction:
    b, a = STATUS_RANK.get(before, 0), STATUS_RANK.get(after, 0)
    if a < b:
        return "regression"
    if a > b:
        return "improvement"
    return "lateral"


class CheckChange(BaseModel):
    source: str
    check_id: str
    before: str
    after: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direction(self) -> Direction:
        return _direction(self.before, self.after)


class EligibilityChange(BaseModel):
    source: str
    before: bool
    after: bool
    gates_newly_failing: list[str]
    gates_newly_passing: list[str]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direction(self) -> Direction:
        return "regression" if self.before and not self.after else "improvement"


class ScoreChange(BaseModel):
    source: str
    before: str
    after: str


class RunDiff(BaseModel):
    config_path: str
    baseline_timestamp: str | None
    current_timestamp: str
    note: str | None = None
    """Why the comparison is partial or empty, when it is."""
    check_changes: list[CheckChange]
    eligibility_changes: list[EligibilityChange]
    score_changes: list[ScoreChange]
    added_sources: list[str]
    removed_sources: list[str]
    compared_sources: int
    compared_checks: int

    @computed_field  # type: ignore[prop-decorator]
    @property
    def regressions(self) -> list[str]:
        out = [
            f"{e.source}: ELIGIBLE -> NOT ELIGIBLE"
            + (f" (newly failing gates: {', '.join(e.gates_newly_failing)})" if e.gates_newly_failing else "")
            for e in self.eligibility_changes
            if e.direction == "regression"
        ]
        out += [
            f"{c.source} / {c.check_id}: {c.before} -> {c.after}"
            for c in self.check_changes
            if c.direction == "regression"
        ]
        return out

    @computed_field  # type: ignore[prop-decorator]
    @property
    def improvements(self) -> list[str]:
        out = [
            f"{e.source}: NOT ELIGIBLE -> ELIGIBLE"
            for e in self.eligibility_changes
            if e.direction == "improvement"
        ]
        out += [
            f"{c.source} / {c.check_id}: {c.before} -> {c.after}"
            for c in self.check_changes
            if c.direction == "improvement"
        ]
        return out

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_regression(self) -> bool:
        return bool(self.regressions)


def load_journal(path: str | Path) -> list[dict[str, Any]]:
    """Every entry, oldest first. A malformed line is an error, not a
    skip -- an append-only audit file that has been damaged should be
    noticed, not silently read around."""
    entries: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"journal {path}: line {line_no} is not valid JSON: {exc}") from exc
    return entries


def find_baseline(entries: list[dict[str, Any]], config_path: str) -> dict[str, Any] | None:
    """The most recent entry for this config path. Matched as the exact
    string given on the command line -- run from the same directory with
    the same --config to keep a continuous history."""
    for entry in reversed(entries):
        if entry.get("config_path") == config_path:
            return entry
    return None


def diff_entries(baseline: dict[str, Any] | None, current: dict[str, Any]) -> RunDiff:
    config_path = current.get("config_path", "")
    if baseline is None:
        return RunDiff(
            config_path=config_path,
            baseline_timestamp=None,
            current_timestamp=current["timestamp"],
            note="no previous run for this config in the journal -- nothing to compare yet",
            check_changes=[],
            eligibility_changes=[],
            score_changes=[],
            added_sources=sorted(current.get("verdicts", {})),
            removed_sources=[],
            compared_sources=0,
            compared_checks=0,
        )

    before_v: dict[str, dict[str, Any]] = baseline.get("verdicts", {})
    after_v: dict[str, dict[str, Any]] = current.get("verdicts", {})
    common = sorted(set(before_v) & set(after_v))

    check_changes: list[CheckChange] = []
    eligibility_changes: list[EligibilityChange] = []
    score_changes: list[ScoreChange] = []
    compared_checks = 0
    note: str | None = None

    for name in common:
        b, a = before_v[name], after_v[name]

        if b.get("eligible") != a.get("eligible"):
            b_gates, a_gates = set(b.get("failed_gates") or []), set(a.get("failed_gates") or [])
            eligibility_changes.append(
                EligibilityChange(
                    source=name,
                    before=bool(b.get("eligible")),
                    after=bool(a.get("eligible")),
                    gates_newly_failing=sorted(a_gates - b_gates),
                    gates_newly_passing=sorted(b_gates - a_gates),
                )
            )

        if b.get("completeness_score") != a.get("completeness_score"):
            score_changes.append(
                ScoreChange(
                    source=name,
                    before=str(b.get("completeness_score")),
                    after=str(a.get("completeness_score")),
                )
            )

        b_checks, a_checks = b.get("checks"), a.get("checks")
        if b_checks is None:
            note = (
                "baseline entry predates per-check statuses -- only eligibility and "
                "score were compared"
            )
            continue
        for check_id in sorted(set(b_checks) | set(a_checks or {})):
            compared_checks += 1
            before = b_checks.get(check_id, "NOT_ASSESSED")
            after = (a_checks or {}).get(check_id, "NOT_ASSESSED")
            if before != after:
                check_changes.append(
                    CheckChange(source=name, check_id=check_id, before=before, after=after)
                )

    return RunDiff(
        config_path=config_path,
        baseline_timestamp=baseline.get("timestamp"),
        current_timestamp=current["timestamp"],
        note=note,
        check_changes=check_changes,
        eligibility_changes=eligibility_changes,
        score_changes=score_changes,
        added_sources=sorted(set(after_v) - set(before_v)),
        removed_sources=sorted(set(before_v) - set(after_v)),
        compared_sources=len(common),
        compared_checks=compared_checks,
    )


def render_diff_markdown(diff: RunDiff) -> str:
    lines = ["# Completeness diff", ""]
    lines.append(f"- Config: `{diff.config_path}`")
    if diff.baseline_timestamp is None:
        lines.append(f"- Current run: {diff.current_timestamp}")
        lines.append(f"- {diff.note}")
        if diff.added_sources:
            lines.append(f"- Sources in this run: {', '.join(diff.added_sources)}")
        return "\n".join(lines) + "\n"

    lines.append(f"- Baseline: {diff.baseline_timestamp}")
    lines.append(f"- Current: {diff.current_timestamp}")
    lines.append(
        f"- Compared: {diff.compared_sources} source(s), {diff.compared_checks} check result(s)"
    )
    if diff.note:
        lines.append(f"- Note: {diff.note}")
    lines.append("")

    lines.append(f"## Regressions ({len(diff.regressions)})")
    lines.append("")
    lines += [f"- {r}" for r in diff.regressions] or ["None."]
    lines.append("")

    lines.append(f"## Improvements ({len(diff.improvements)})")
    lines.append("")
    lines += [f"- {i}" for i in diff.improvements] or ["None."]
    lines.append("")

    lateral = [c for c in diff.check_changes if c.direction == "lateral"]
    if lateral or diff.score_changes or diff.added_sources or diff.removed_sources:
        lines.append("## Other changes")
        lines.append("")
        lines += [f"- {c.source} / {c.check_id}: {c.before} -> {c.after} (lateral)" for c in lateral]
        lines += [f"- {s.source}: score {s.before} -> {s.after}" for s in diff.score_changes]
        if diff.added_sources:
            lines.append(f"- Sources new in this run: {', '.join(diff.added_sources)}")
        if diff.removed_sources:
            lines.append(
                f"- Sources absent from this run (removed from config, or did not complete): "
                f"{', '.join(diff.removed_sources)}"
            )
        lines.append("")

    return "\n".join(lines) + "\n"
