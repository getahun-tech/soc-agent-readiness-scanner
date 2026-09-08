"""Markdown report renderer.

Renders: run metadata, estate summary, per-source detail (checks plus the
verdict/eligibility block), conflicts, and owner-routed recommendations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from scanner.config import ScannerConfig
from scanner.renderers.view_model import build_view

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def render_markdown(run_result: dict[str, Any], config: ScannerConfig) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")
    return template.render(**build_view(run_result, config))
