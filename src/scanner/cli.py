from __future__ import annotations

import getpass
import hashlib
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console

from scanner.config import ConfigError, DefaultsConfig, ScannerConfig, SourceConfig, load_config
from scanner.exceptions import AdapterError
from scanner.orchestrator import run_scan
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
) -> list[str]:
    """Run, journal, render. Returns the names of sources that did not
    complete, so the caller decides how to exit."""
    if output_format not in _RENDERERS:
        err_console.print(
            f"[bold red]--format must be one of {sorted(_RENDERERS)}, got '{output_format}'[/bold red]"
        )
        raise typer.Exit(code=1)

    resolved_operator = operator or _operator_identity()
    try:
        result = run_scan(
            cfg,
            config_path=config_path,
            source_names=source_names,
            config_hash=config_hash,
            operator=resolved_operator,
        )
    except AdapterError as exc:
        err_console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc

    if journal:
        entry = build_journal_entry(
            result,
            operator=resolved_operator,
            config_path=config_path,
            config_hash=config_hash,
        )
        append_journal_entry(journal, entry)

    payload = _RENDERERS[output_format](result, cfg)

    if output:
        # newline="\n" pins line endings so output is byte-identical across
        # platforms for the same input (SPEC.md 9.7), not CRLF on Windows.
        Path(output).write_text(payload, encoding="utf-8", newline="\n")
        console.print(f"Wrote report to {output}")
    else:
        print(payload)

    return [
        name for name, r in result["sources"].items() if r["status"] in ("error", "not_implemented")
    ]


def _exit_if_incomplete(failed: list[str]) -> None:
    if failed:
        err_console.print(f"[yellow]{len(failed)} source(s) did not complete: {failed}[/yellow]")
        raise typer.Exit(code=1)


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
) -> None:
    """Sample configured sources, run every check, score, and report."""
    cfg = _load_config_or_exit(config)
    config_hash = None
    config_file = Path(config)
    if config_file.exists():
        config_hash = hashlib.sha256(config_file.read_bytes()).hexdigest()[:16]

    failed = _execute(
        cfg,
        config_path=config,
        config_hash=config_hash,
        source_names=source,
        output=output,
        output_format=output_format,
        operator=operator,
        journal=journal,
    )
    _exit_if_incomplete(failed)


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

    failed = _execute(
        cfg,
        config_path="quickscan",
        config_hash=None,
        source_names=None,
        output=output,
        output_format=output_format,
        operator=operator,
        journal=journal,
    )
    _exit_if_incomplete(failed)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
