from __future__ import annotations

import getpass
import hashlib
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from scanner.config import ConfigError, load_config
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
    if cfg.inventory is None:
        console.print(
            "  [yellow]no inventory configured[/yellow] -- C4 (affected entity) "
            "inventory resolution will report NOT_ASSESSED / degraded results for "
            "every source"
        )


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
    if output_format not in _RENDERERS:
        err_console.print(
            f"[bold red]--format must be one of {sorted(_RENDERERS)}, got '{output_format}'[/bold red]"
        )
        raise typer.Exit(code=1)

    cfg = _load_config_or_exit(config)
    config_hash = None
    config_file = Path(config)
    if config_file.exists():
        config_hash = hashlib.sha256(config_file.read_bytes()).hexdigest()[:16]
    resolved_operator = operator or _operator_identity()

    try:
        result = run_scan(
            cfg,
            config_path=config,
            source_names=source,
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
            config_path=config,
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

    failed = [
        name for name, r in result["sources"].items() if r["status"] in ("error", "not_implemented")
    ]
    if failed:
        err_console.print(f"[yellow]{len(failed)} source(s) did not complete: {failed}[/yellow]")
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
