"""JSON report renderer (SPEC.md sec 8.1: "machine-readable, stable schema").

The run_result dict from orchestrator.run_scan already *is* that schema --
this renderer's only job is turning it into deterministic (sorted-key)
text, matching the other renderers' `(run_result, config) -> str` shape
even though it doesn't need `config`.
"""

from __future__ import annotations

import json
from typing import Any


def render_json(run_result: dict[str, Any]) -> str:
    return json.dumps(run_result, indent=2, sort_keys=True)
