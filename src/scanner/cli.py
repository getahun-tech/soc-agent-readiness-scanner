from __future__ import annotations

import getpass
import hashlib
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console

from scanner.config import ConfigError, DefaultsConfig, ScannerConfig, SourceConfig, load_config
from scanner.diff import RunDiff, diff_entries, find_baseline, load_journal, render_diff_markdown
from scanner.exceptions import AdapterError
from scanner.orchestrator import run_scan
from scanner.profiles import ProfileError, ProfileRegistry
from scanner.renderers import render_html, render_json, render_markdown
from scanner.run_journal import append_journal_entry, build_journal_entry

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
err_console = Console(stderr=True)

_RENDERERS = {
    "json": lambda result, cfg: render_json(result),
    "markdown": render_markdown,
    "html": render_html,
}
_DEFAULT_JOURNAL_PATH = "./scanner_journal.jsonl"
_QUICKSCAN_OWNER = "unknown (quickscan -- set owner: in a real config)"
_EVENT_CLASSES = ("activity", "state", "mixed")
_GLOB_CHARS = set("*?[")
_FAIL_ON = ("ineligible", "regression")

# Exit codes. 1 is "the scan itself did not complete" (adapter error,
# bad config); 2 is "the scan completed and the data failed a policy you
# asked for" -- distinct so a pipeline can tell a broken job from a real
# finding.
EXIT_INCOMPLETE = 1
EXIT_POLICY = 2


@dataclass
class Outcome:
    failed: list[str] = field(default_factory=list)
    """Sources that did not complete."""
    ineligible: list[str] = field(default_factory=list)
    """Sources that completed and are not automation-eligible."""
    diff: RunDiff | None = None
    """Comparison against the previous journal entry; None when not journaling."""


def _load_config_or_exit(config_path: str):
    try:
        return load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Config error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValidationError as exc:
        err_console.print("[bold red]Config is invalid:[/bold red]")
        for error in exc.errors():
            loc = " -> ".join(str(part) for part in error["loc"])
            err_console.print(f"  [red]{loc}[/red]: {error['msg']}")
        raise typer.Exit(code=1) from exc


def _operator_identity() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 -- identity lookup must never crash the scan
        return "unknown"


def _execute(
    cfg: ScannerConfig,
    *,
    config_path: str,
    config_hash: str | None,
    source_names: list[str] | None,
    output: str | None,
    output_format: str,
    operator: str | None,
    journal: str,
) -> Outcome:
    """Run, diff against the journal, journal, render. Returns what the
    caller needs to decide how to exit."""
    if output_format not in _RENDERERS:
        err_console.print(
            f"[bold red]--format must be one of {sorted(_RENDERERS)}, got '{output_format}'[/bold red]"
        )
        raise typer.Exit(code=EXIT_INCOMPLETE)

    resolved_operator = operator or _operator_identity()
    try:
        result = run_scan(
            cfg,
            config_path=config_path,
            source_names=source_names,
            config_hash=config_hash,
            operator=resolved_operator,
        )
    except (AdapterError, ProfileError) as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=EXIT_INCOMPLETE) from exc

    diff: RunDiff | None = None
    if journal:
        entry = build_journal_entry(
            result,
            operator=resolved_operator,
            config_path=config_path,
            config_hash=config_hash,
        )
        # Baseline is read *before* this run is appended, so the diff is
        # always "this run vs. the previous one for the same config".
        baseline = None
        if Path(journal).exists():
            try:
                baseline = find_baseline(load_journal(journal), config_path)
            except ValueError as exc:
                err_console.print(f"[bold red]{exc}[/bold red]")
                raise typer.Exit(code=EXIT_INCOMPLETE) from exc
        diff = diff_entries(baseline, entry.model_dump())
        append_journal_entry(journal, entry)

    payload = _RENDERERS[output_format](result, cfg)

    if output:
        # newline="\n" pins line endings so output is byte-identical across
        # platforms for the same input (SPEC.md 9.7), not CRLF on Windows.
        Path(output).write_text(payload, encoding="utf-8", newline="\n")
        console.print(f"Wrote report to {output}")
    else:
        print(payload)

    if diff is not None and diff.baseline_timestamp is not None:
        # stderr: informative, never part of the report payload.
        err_console.print(
            f"vs previous run ({diff.baseline_timestamp}): "
            f"{len(diff.regressions)} regression(s), {len(diff.improvements)} improvement(s)"
            + (f" -- {diff.note}" if diff.note else "")
        )
        for line in diff.regressions:
            err_console.print(f"  [red]regression[/red] {line}")

    return Outcome(
        failed=[
            name
            for name, r in result["sources"].items()
            if r["status"] in ("error", "not_implemented")
        ],
        ineligible=[
            name
            for name, r in result["sources"].items()
            if r.get("verdict") and not r["verdict"]["eligibility"]["eligible"]
        ],
        diff=diff,
    )


def _exit_if_incomplete(failed: list[str]) -> None:
    if failed:
        err_console.print(f"[yellow]{len(failed)} source(s) did not complete: {failed}[/yellow]")
        raise typer.Exit(code=EXIT_INCOMPLETE)


def _exit_if_policy_failed(outcome: Outcome, fail_on: list[str]) -> None:
    reasons: list[str] = []
    if "ineligible" in fail_on and outcome.ineligible:
        reasons.append(f"{len(outcome.ineligible)} source(s) not automation-eligible: {outcome.ineligible}")
    if "regression" in fail_on and outcome.diff is not None and outcome.diff.has_regression:
        reasons.append(f"{len(outcome.diff.regressions)} regression(s) vs the previous run")
    if reasons:
        for reason in reasons:
            err_console.print(f"[bold red]--fail-on:[/bold red] {reason}")
        raise typer.Exit(code=EXIT_POLICY)


@app.command(name="validate-config")
def validate_config(
    config: Annotated[str, typer.Option("--config", help="Path to the scanner YAML config")],
) -> None:
    """Validate a config file without running a scan."""
    cfg = _load_config_or_exit(config)
    console.print(f"[bold green]Config valid[/bold green]: {config}")
    console.print(f"  version: {cfg.version}, ruleset_version: {cfg.ruleset_version}")
    console.print(f"  sources: {len(cfg.sources)}")
    console.print(f"  precedence_rules: {len(cfg.precedence_rules)}")


@app.command(name="scan")
def scan(
    config: Annotated[str, typer.Option("--config", help="Path to the scanner YAML config")],
    source: Annotated[
        list[str] | None,
        typer.Option("--source", help="Scan only this source (repeatable). Default: all."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write report here instead of stdout"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: 'json', 'markdown', or 'html'"),
    ] = "json",
    operator: Annotated[
        str | None,
        typer.Option("--operator", help="Operator identity for the run journal. Default: OS user."),
    ] = None,
    journal: Annotated[
        str,
        typer.Option("--journal", help="Append-only run journal path. Set to '' to skip journaling."),
    ] = _DEFAULT_JOURNAL_PATH,
    fail_on: Annotated[
        list[str] | None,
        typer.Option(
            "--fail-on",
            help=(
                "Exit 2 if the data fails a policy (repeatable): 'ineligible' -- any "
                "scanned source is not automation-eligible; 'regression' -- any check or "
                "eligibility got worse than the previous journal entry for this config."
            ),
        ),
    ] = None,
) -> None:
    """Sample configured sources, run every check, score, and report."""
    fail_on = fail_on or []
    bad = [f for f in fail_on if f not in _FAIL_ON]
    if bad:
        err_console.print(f"[bold red]--fail-on must be one of {list(_FAIL_ON)}, got {bad}[/bold red]")
        raise typer.Exit(code=EXIT_INCOMPLETE)
    if "regression" in fail_on and not journal:
        err_console.print(
            "[bold red]--fail-on regression needs the journal[/bold red] -- the baseline is the "
            "previous journal entry for this config; don't pass --journal ''"
        )
        raise typer.Exit(code=EXIT_INCOMPLETE)

    cfg = _load_config_or_exit(config)
    config_hash = None
    config_file = Path(config)
    if config_file.exists():
        config_hash = hashlib.sha256(config_file.read_bytes()).hexdigest()[:16]

    outcome = _execute(
        cfg,
        config_path=config,
        config_hash=config_hash,
        source_names=source,
        output=output,
        output_format=output_format,
        operator=operator,
        journal=journal,
    )
    _exit_if_incomplete(outcome.failed)
    _exit_if_policy_failed(outcome, fail_on)


@app.command(name="profiles")
def profiles(
    profile_dir: Annotated[
        list[str] | None,
        typer.Option("--profile-dir", help="Additional profile directory (repeatable), as `profile_dirs:` in config."),
    ] = None,
) -> None:
    """List the log-type profiles the scanner knows: bundled, plus any extra directories."""
    try:
        registry = ProfileRegistry.load(profile_dir or [])
    except ProfileError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=EXIT_INCOMPLETE) from exc
    for p in registry.all():
        console.print(
            f"[bold]{p.id:<26}[/bold] {p.name}  [dim](event_class={p.event_class or 'undeclared'}; "
            f"matches: {', '.join(p.match.sourcetype)})[/dim]"
        )
    console.print(f"\n{len(registry.all())} profile(s). See PROFILES.md to add your own.")


@app.command(name="diff")
def diff(
    journal: Annotated[
        str,
        typer.Option("--journal", help="Run journal to read"),
    ] = _DEFAULT_JOURNAL_PATH,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            help="Compare only entries for this config path (as given to `scan --config`). "
            "Default: the last two entries in the journal, whatever their config.",
        ),
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: 'markdown' or 'json'")
    ] = "markdown",
    exit_code: Annotated[
        bool,
        typer.Option("--exit-code", help="Exit 2 if there are regressions (like `git diff --exit-code`)."),
    ] = False,
) -> None:
    """Show what changed between the last two journaled runs."""
    if output_format not in ("markdown", "json"):
        err_console.print(f"[bold red]--format must be 'markdown' or 'json', got '{output_format}'[/bold red]")
        raise typer.Exit(code=EXIT_INCOMPLETE)
    if not Path(journal).exists():
        err_console.print(f"[bold red]journal not found:[/bold red] {journal}")
        raise typer.Exit(code=EXIT_INCOMPLETE)
    try:
        entries = load_journal(journal)
    except ValueError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=EXIT_INCOMPLETE) from exc
    if config is not None:
        entries = [e for e in entries if e.get("config_path") == config]
    if len(entries) < 2:
        err_console.print(
            f"[bold red]need at least two journal entries to diff[/bold red] "
            f"(found {len(entries)}{f' for config {config!r}' if config else ''})"
        )
        raise typer.Exit(code=EXIT_INCOMPLETE)

    result = diff_entries(entries[-2], entries[-1])
    print(result.model_dump_json(indent=2) if output_format == "json" else render_diff_markdown(result), end="")
    if exit_code and result.has_regression:
        raise typer.Exit(code=EXIT_POLICY)


def _quickscan_source_name(path: str, used: set[str]) -> str:
    """A concrete file is named after its stem; a glob after its parent
    directory (`./logs/firewall/*.json` -> `firewall`), since the pattern
    itself isn't a name. Deduplicated with a numeric suffix."""
    p = Path(path)
    raw = p.parent.name if _GLOB_CHARS & set(p.name) else p.stem
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("_.") or "source"
    name, n = base, 1
    while name in used:
        n += 1
        name = f"{base}_{n}"
    used.add(name)
    return name


def _quickscan_config(
    paths: list[str], *, record_root: str | None, event_class: str | None, sample_size: int
) -> ScannerConfig:
    used: set[str] = set()
    sources = [
        SourceConfig(
            name=_quickscan_source_name(p, used),
            adapter="file",
            path=p,
            owner=_QUICKSCAN_OWNER,
            record_root=record_root,
            event_class=event_class,  # type: ignore[arg-type]
        )
        for p in paths
    ]
    return ScannerConfig(
        version="quickscan",
        ruleset_version="quickscan",
        defaults=DefaultsConfig(sample_size=sample_size),
        sources=sources,
    )


def _emit_config(cfg: ScannerConfig, path: str) -> None:
    """Write the config this run used, minimally: only what differs from
    the defaults, so the file reads as *your* decisions, not a dump."""
    data = cfg.model_dump(mode="json", by_alias=True, exclude_defaults=True, exclude_none=True)
    header = (
        f"# Generated by `scanner quickscan` on {datetime.now(UTC).date().isoformat()}.\n"
        "# Set each source's owner:, then consider adding field_hints: (your own\n"
        "# field names) and event_class: per source. See CONFIG.md.\n"
    )
    Path(path).write_text(
        header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )


@app.command(name="quickscan")
def quickscan(
    paths: Annotated[
        list[str],
        typer.Argument(help="File path(s) or glob pattern(s). Each one becomes a source."),
    ],
    output: Annotated[
        str | None,
        typer.Option("--output", help="Write report here instead of stdout"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: 'json', 'markdown', or 'html'"),
    ] = "markdown",
    record_root: Annotated[
        str | None,
        typer.Option(
            "--record-root",
            help="Envelope key to unwrap (e.g. 'result' for a Splunk JSON export). "
            "Applied to every path given.",
        ),
    ] = None,
    event_class: Annotated[
        str | None,
        typer.Option(
            "--event-class",
            help="activity | state | mixed -- opts C8 (actor) into scoring. Applied to every path.",
        ),
    ] = None,
    sample_size: Annotated[
        int, typer.Option("--sample-size", help="Records sampled per source")
    ] = 2000,
    emit_config: Annotated[
        str | None,
        typer.Option(
            "--emit-config",
            help="Also write the equivalent YAML config here, so this run can become a "
            "durable, reviewed one (`scanner scan --config <file>`).",
        ),
    ] = None,
    operator: Annotated[
        str | None,
        typer.Option("--operator", help="Operator identity for the run journal. Default: OS user."),
    ] = None,
    journal: Annotated[
        str,
        typer.Option(
            "--journal",
            help="Append-only run journal path. Off by default for quickscan -- it's "
            "exploratory; pass a path to record it.",
        ),
    ] = "",
) -> None:
    """Scan file(s) with no config at all. Same checks, same report;
    defaults for everything else."""
    if event_class is not None and event_class not in _EVENT_CLASSES:
        err_console.print(
            f"[bold red]--event-class must be one of {list(_EVENT_CLASSES)}, got '{event_class}'[/bold red]"
        )
        raise typer.Exit(code=1)
    if sample_size <= 0:
        err_console.print("[bold red]--sample-size must be positive[/bold red]")
        raise typer.Exit(code=1)

    cfg = _quickscan_config(
        paths, record_root=record_root, event_class=event_class, sample_size=sample_size
    )
    if emit_config:
        _emit_config(cfg, emit_config)
        err_console.print(f"Wrote config to {emit_config} -- edit owner:, then `scanner scan --config {emit_config}`")
    else:
        # stderr, so `--format json` stdout stays clean and pipeable.
        err_console.print(
            "[dim]Tip: add --emit-config scanner.yaml to save this run as a reusable config.[/dim]"
        )

    outcome = _execute(
        cfg,
        config_path="quickscan",
        config_hash=None,
        source_names=None,
        output=output,
        output_format=output_format,
        operator=operator,
        journal=journal,
    )
    _exit_if_incomplete(outcome.failed)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
