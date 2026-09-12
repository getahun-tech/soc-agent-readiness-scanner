"""Read-only adapter for file-exported log/telemetry samples.

Supports glob patterns (``./samples/solarwinds/*.log``). How a file is
read depends on its extension:

- ``.csv`` / ``.tsv``: parsed with the ``csv`` module, header row as field
  names. A row is one record (a quoted cell may span physical lines --
  Windows event messages routinely do). Empty cells are treated as the
  field being *absent* from that row, not present-but-blank, since a CSV
  has no way to say null and presence is what the checks measure.
- Anything else: each non-blank line is one record, parsed through a
  three-tier cascade so both JSON exports and syslog-style text are usable
  without per-source parser config:

  1. JSON object per line. Nested objects are flattened to dotted-path
     keys (``{"destination": {"ip": ...}}`` -> ``destination.ip``) so the
     built-in field-hint candidates that use those names actually match.
     If the source declares ``record_root``, that envelope key is unwrapped
     first (Splunk's JSON export wraps every event in ``result``).
  2. logfmt-style ``key=value`` tokens (quote-aware), if enough of the
     line's tokens look like key=value pairs.
  3. Fallback: the whole line as ``{"message": <line>}``, flagged
     ``structured=False`` so C1 can tell a genuine parse from a free-text
     record that merely didn't crash.

Not supported: RFC3164/5424 syslog headers (they land in the fallback
tier), and CSV/TSV envelopes (``record_root`` applies to JSON only).
"""

from __future__ import annotations

import csv
import glob
import io
import json
import re
import shlex
from pathlib import Path
from typing import Any

from scanner.adapters.base import Adapter
from scanner.config import ScannerConfig, SourceConfig
from scanner.exceptions import AdapterError
from scanner.models import RawRecord, SampleMetadata, flatten_record
from scanner.sampling import recent_sample, reservoir_sample, stratified_sample_by_group

_KV_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*=.+$")
_DELIMITED_EXTENSIONS = {".csv": ",", ".tsv": "\t"}

# (physical line number, raw text, pre-parsed record or None). Delimited
# files arrive pre-parsed because a CSV row can't be parsed in isolation --
# it needs the header from the top of its file.
_Line = tuple[int, str, dict[str, Any] | None]


def _parse_cascade(
    raw_text: str, record_root: str | None = None
) -> tuple[dict | None, str | None, bool]:
    stripped = raw_text.strip()
    if not stripped:
        return None, "empty line", False

    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        if record_root is None:
            return flatten_record(obj), None, True
        inner = obj.get(record_root)
        if isinstance(inner, dict):
            return flatten_record(inner), None, True
        # Keep the record inspectable, but make the misconfiguration
        # visible: it counts against parse_rate and shows up verbatim in
        # the profile's parse_error_examples.
        return (
            flatten_record(obj),
            f"record_root '{record_root}' not found (or not an object) in this record",
            False,
        )

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


def _row_text(row: list[str], delimiter: str) -> str:
    """Canonical re-serialization of one row. The csv module doesn't hand
    back the original bytes of a row, and a quoted cell can span physical
    lines, so this is the deterministic stand-in for ``raw_text``."""
    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter, lineterminator="").writerow(row)
    return buf.getvalue()


def _read_delimited(text: str, delimiter: str) -> list[_Line]:
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    header = next(reader, None)
    if header is None:
        return []
    header = [h.strip() for h in header]
    lines: list[_Line] = []
    for row in reader:
        if not any(cell.strip() for cell in row):
            continue
        record = {name: value for name, value in zip(header, row, strict=False) if name and value != ""}
        lines.append((reader.line_num, _row_text(row, delimiter), record))
    return lines


def _read_lines(text: str) -> list[_Line]:
    return [(n, ln, None) for n, ln in enumerate(text.splitlines(), start=1) if ln.strip()]


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

        file_lines: dict[str, list[_Line]] = {}
        total_lines = 0
        for p in paths:
            # utf-8-sig: silently drops the BOM Excel puts at the front of a
            # CSV, which would otherwise become part of the first header
            # name (and break json.loads on line 1 of a JSONL file).
            text = Path(p).read_text(encoding="utf-8-sig", errors="replace")
            delimiter = _DELIMITED_EXTENSIONS.get(Path(p).suffix.lower())
            lines = _read_delimited(text, delimiter) if delimiter else _read_lines(text)
            file_lines[p] = lines
            total_lines += len(lines)

        if strategy == "random":
            flat = [(p, *line) for p in paths for line in file_lines[p]]
            chosen = reservoir_sample(flat, limit, seed)
        elif strategy == "recent":
            flat = [(p, *line) for p in paths for line in file_lines[p]]
            chosen = recent_sample(flat, limit)
        elif strategy == "stratified":
            grouped = {p: iter((p, *line) for line in file_lines[p]) for p in paths}
            chosen = stratified_sample_by_group(grouped, limit, seed)
        else:  # pragma: no cover - config validation already restricts this
            raise AdapterError(f"source '{source.name}': unknown sample_strategy '{strategy}'")

        records = [
            self._build_record(source.name, i, origin, line_no, raw, pre_parsed, source.record_root)
            for i, (origin, line_no, raw, pre_parsed) in enumerate(chosen)
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
        source_name: str,
        index: int,
        origin_path: str,
        origin_line_no: int,
        raw_text: str,
        pre_parsed: dict[str, Any] | None,
        record_root: str | None,
    ) -> RawRecord:
        if pre_parsed is not None:
            parsed, err, structured = pre_parsed, None, True
        else:
            parsed, err, structured = _parse_cascade(raw_text, record_root)
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
