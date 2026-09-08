"""Standalone HTML report renderer (SPEC.md sec 8.1: "no external assets").

All CSS is inlined in the template; no CDN links, fonts, or scripts are
fetched. Autoescaping is on (unlike the Markdown renderer) because
finding text and evidence examples can echo raw values pulled from
sampled log records, which are untrusted input as far as HTML goes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.config import ScannerConfig
from scanner.renderers.view_model import build_view

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def render_html(run_result: dict[str, Any], config: ScannerConfig) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(**build_view(run_result, config))
