"""Read-only adapter for file-exported log/telemetry samples.

Supports glob patterns (``./samples/solarwinds/*.log``). Each non-blank
line is one record. Parsing is a three-tier cascade so both JSON exports
and syslog-style text are usable without per-source parser config:

1. JSON object per line.
2. logfmt-style ``key=value`` tokens (quote-aware), if enough of the line's
   tokens look like key=value pairs.
3. Fallback: the whole line as ``{"message": <line>}``, flagged
   ``structured=False`` so C1 can tell a genuine parse from a free-text
   record that merely didn't crash.
"""

from __future__ import annotations

import glob
import json
import re
import shlex
from pathlib import Path

from scanner.adapters.base import Adapter
from scanner.config import ScannerConfig, SourceConfig
from scanner.exceptions import AdapterError
from scanner.models import RawRecord, SampleMetadata
from scanner.sampling import recent_sample, reservoir_sample, stratified_sample_by_group

_KV_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*=.+$")


def _parse_cascade(raw_text: str) -> tuple[dict | None, str | None, bool]:
    stripped = raw_text.strip()
    if not stripped:
        return None, "empty line", False

    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj, None, True
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        tokens = stripped.split()
    kv: dict[str, str] = {}
    matched = 0
    for tok in tokens:
        if _KV_TOKEN.match(tok):
            key, _, value = tok.partition("=")
            kv[key] = value
            matched += 1
    if tokens and matched >= 2 and (matched / len(tokens)) >= 0.6:
        return kv, None, True

    return {"message": stripped}, None, False


class FileAdapter(Adapter):
    def fetch_sample(self, source: SourceConfig, config: ScannerConfig):
        assert source.path is not None  # enforced by SourceConfig validation
        paths = sorted(glob.glob(source.path, recursive=True))
        if not paths:
            raise AdapterError(
                f"source '{source.name}': no files matched pattern '{source.path}'"
            )

        strategy = config.effective_sample_strategy(source)
        limit = config.effective_sample_size(source)
        seed = config.defaults.seed

        file_lines: dict[str, list[tuple[int, str]]] = {}
        total_lines = 0
        for p in paths:
            text = Path(p).read_text(encoding="utf-8", errors="replace")
            lines = [
                (line_no, ln) for line_no, ln in enumerate(text.splitlines(), start=1) if ln.strip()
            ]
            file_lines[p] = lines
            total_lines += len(lines)

        if strategy == "random":
            flat = [(p, line_no, ln) for p in paths for line_no, ln in file_lines[p]]
            chosen = reservoir_sample(flat, limit, seed)
        elif strategy == "recent":
            flat = [(p, line_no, ln) for p in paths for line_no, ln in file_lines[p]]
            chosen = recent_sample(flat, limit)
        elif strategy == "stratified":
            grouped = {
                p: iter((p, line_no, ln) for line_no, ln in file_lines[p]) for p in paths
            }
            chosen = stratified_sample_by_group(grouped, limit, seed)
        else:  # pragma: no cover - config validation already restricts this
            raise AdapterError(f"source '{source.name}': unknown sample_strategy '{strategy}'")

        records = [
            self._build_record(source.name, i, origin, line_no, raw)
            for i, (origin, line_no, raw) in enumerate(chosen)
        ]

        metadata = SampleMetadata(
            source_name=source.name,
            strategy=strategy,
            seed=seed,
            requested_size=limit,
            population_size=total_lines,
            actual_size=len(records),
            files_read=paths,
        )
        return iter(records), metadata

    @staticmethod
    def _build_record(
        source_name: str, index: int, origin_path: str, origin_line_no: int, raw_text: str
    ) -> RawRecord:
        parsed, err, structured = _parse_cascade(raw_text)
        return RawRecord(
            source_name=source_name,
            index=index,
            origin_path=origin_path,
            origin_line_no=origin_line_no,
            raw_text=raw_text,
            parsed=parsed,
            parse_error=err,
            structured=structured,
        )
