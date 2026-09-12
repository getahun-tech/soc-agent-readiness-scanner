import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+00:00")


def _normalize(text: str) -> str:
    """Strip the one genuinely nondeterministic field (the wall-clock
    generated_at timestamp) so two runs' raw text output can be compared
    byte-for-byte."""
    return _TIMESTAMP_RE.sub("<TIMESTAMP>", text)


FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path, monkeypatch):
    # `scan`'s default --journal path is relative ("./scanner_journal.jsonl") --
    # without this, every test in this module would write into the real repo
    # directory instead of the test's own tmp_path.
    monkeypatch.chdir(tmp_path)


def _write_config(tmp_path: Path, source_path: str, adapter: str = "file", extra: str = "") -> Path:
    p = tmp_path / "config.yaml"
    splunk_block = 'splunk:\n  host: "splunk.example.com"\n' if adapter == "splunk" else ""
    p.write_text(f"""
version: "1.0"
ruleset_version: "test"
defaults:
  sample_size: 100
  sample_strategy: random
  seed: 1
{splunk_block}sources:
  - name: test_source
    adapter: {adapter}
    {"path: " + source_path if adapter == "file" else "query: 'index=test'"}
    owner: "ops@example.com"
{extra}
""")
    return p


def test_validate_config_success(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["validate-config", "--config", str(cfg_path)])
    assert result.exit_code == 0
    assert "Config valid" in result.stdout


def test_validate_config_failure(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("not: [valid, since, sources, missing]")
    result = runner.invoke(app, ["validate-config", "--config", str(p)])
    assert result.exit_code == 1


def test_validate_config_missing_file():
    result = runner.invoke(app, ["validate-config", "--config", "/no/such/file.yaml"])
    assert result.exit_code == 1


def test_scan_produces_json_report(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["run_metadata"]["config_version"] == "1.0"
    assert payload["sources"]["test_source"]["status"] == "ok"
    assert payload["sources"]["test_source"]["profile"]["record_count"] == 10
    assert payload["sources"]["test_source"]["sample"]["seed"] == 1


def test_scan_writes_to_output_file(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    out_path = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--output", str(out_path)])
    assert result.exit_code == 0
    payload = json.loads(out_path.read_text())
    assert payload["sources"]["test_source"]["status"] == "ok"


def test_scan_splunk_source_without_token_env_var_reports_error(tmp_path, monkeypatch):
    # No live Splunk to test against here -- this exercises the credential
    # guard, not the adapter's happy path (see test_splunk_adapter.py for
    # that, against a fake connection).
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    cfg_path = _write_config(tmp_path, "", adapter="splunk")
    result = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["sources"]["test_source"]["status"] == "error"
    assert "SPLUNK_TOKEN" in payload["sources"]["test_source"]["error"]


def test_scan_unknown_source_name_errors(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--source", "ghost"])
    assert result.exit_code == 1


def test_scan_html_format_produces_standalone_html(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "html"])
    assert result.exit_code == 0
    assert "<!doctype html>" in result.stdout.lower()
    assert "<style>" in result.stdout  # inline CSS, no external assets
    assert "http://" not in result.stdout and "https://" not in result.stdout
    assert "test_source" in result.stdout


def test_scan_invalid_format_errors(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "yaml"])
    assert result.exit_code == 1


def test_scan_writes_journal_entry(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    journal_path = tmp_path / "journal.jsonl"
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--journal", str(journal_path)])
    assert result.exit_code == 0
    entries = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1
    assert entries[0]["sources_scanned"] == ["test_source"]


def test_scan_journal_can_be_disabled(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--journal", ""])
    assert result.exit_code == 0
    assert not (tmp_path / "scanner_journal.jsonl").exists()


def test_scan_deterministic_output(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "mixed_formats" / "*.log"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    p1 = json.loads(r1.stdout)
    p2 = json.loads(r2.stdout)
    # generated_at will differ; strip it before comparing the rest for determinism.
    del p1["run_metadata"]["generated_at"]
    del p2["run_metadata"]["generated_at"]
    assert p1 == p2


def test_scan_json_output_is_byte_identical_across_runs(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "mixed_formats" / "*.log"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    assert _normalize(r1.stdout) == _normalize(r2.stdout)


def test_scan_markdown_output_is_byte_identical_across_runs(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "mixed_formats" / "*.log"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "markdown"])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "markdown"])
    assert _normalize(r1.stdout) == _normalize(r2.stdout)


def test_scan_html_output_is_byte_identical_across_runs(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "mixed_formats" / "*.log"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "html"])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "html"])
    assert _normalize(r1.stdout) == _normalize(r2.stdout)


def test_scan_produces_jsonl_report_one_event_per_line(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    result = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "jsonl"])
    assert result.exit_code == 0, result.output
    lines = [json.loads(line) for line in result.stdout.rstrip("\n").split("\n")]
    assert lines  # at least the 'scan' event
    assert lines[0]["event_type"] == "scan"
    assert any(e["event_type"] == "source_summary" and e["source"] == "test_source" for e in lines)
    assert any(e["event_type"] == "check_result" for e in lines)
    run_ids = {e["run_id"] for e in lines}
    assert len(run_ids) == 1  # every line from this invocation ties together


def test_scan_jsonl_output_is_byte_identical_across_runs(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "mixed_formats" / "*.log"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "jsonl"])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path), "--format", "jsonl"])
    assert _normalize(r1.stdout) == _normalize(r2.stdout)


# --- --fail-on and diff: CI gates against the journal ------------------------


def test_fail_on_ineligible_exits_2_and_still_writes_the_report(tmp_path):
    # The simple fixture WARNs on C2 (small skew), and the C2 gate needs PASS.
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["scan", "--config", str(cfg_path), "--output", str(out), "--fail-on", "ineligible"]
    )
    assert result.exit_code == 2
    assert json.loads(out.read_text())["sources"]["test_source"]["status"] == "ok"


def test_fail_on_rejects_unknown_policy_and_regression_without_journal(tmp_path):
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    assert runner.invoke(app, ["scan", "--config", str(cfg_path), "--fail-on", "bogus"]).exit_code == 1
    assert (
        runner.invoke(
            app, ["scan", "--config", str(cfg_path), "--fail-on", "regression", "--journal", ""]
        ).exit_code
        == 1
    )


def _write_records(path: Path, *, with_action: bool) -> None:
    lines = []
    for i in range(10):
        rec = {"timestamp": f"2026-01-01T00:00:{i:02d}Z", "host": "web01", "user": "alice", "dst": "db01"}
        if with_action:
            rec["action"] = "login"
        lines.append(json.dumps(rec))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_fail_on_regression_compares_against_the_previous_run_of_the_same_config(tmp_path):
    data = tmp_path / "data.jsonl"
    journal = tmp_path / "journal.jsonl"
    _write_records(data, with_action=True)
    cfg_path = _write_config(tmp_path, str(data))
    args = ["scan", "--config", str(cfg_path), "--journal", str(journal), "--fail-on", "regression"]

    # First run: no baseline yet -> nothing to regress from.
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output

    # Same data again: a baseline exists and nothing changed.
    second = runner.invoke(app, args)
    assert second.exit_code == 0, second.output

    # The event-type field disappears (a vendor "update"): C1 and C5 get worse.
    _write_records(data, with_action=False)
    third = runner.invoke(app, args)
    assert third.exit_code == 2, third.output

    # `scanner diff` reads the same journal and shows exactly that.
    shown = runner.invoke(app, ["diff", "--journal", str(journal), "--config", str(cfg_path), "--exit-code"])
    assert shown.exit_code == 2, shown.output
    assert "test_source / C1: PASS -> FAIL" in shown.stdout
    assert "test_source / C5: PASS -> FAIL" in shown.stdout
    assert "## Regressions (2)" in shown.stdout

    as_json = runner.invoke(app, ["diff", "--journal", str(journal), "--format", "json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.stdout)["has_regression"] is True


def test_diff_needs_two_entries_and_an_existing_journal(tmp_path):
    assert runner.invoke(app, ["diff", "--journal", str(tmp_path / "missing.jsonl")]).exit_code == 1
    cfg_path = _write_config(tmp_path, str(FIXTURES / "simple" / "records.jsonl"))
    journal = tmp_path / "journal.jsonl"
    runner.invoke(app, ["scan", "--config", str(cfg_path), "--journal", str(journal)])
    only_one = runner.invoke(app, ["diff", "--journal", str(journal)])
    assert only_one.exit_code == 1


def test_profiles_command_lists_bundled_profiles():
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0, result.output
    assert "pan:traffic" in result.stdout
    assert "windows:security" in result.stdout
    assert "profile(s)" in result.stdout


# --- quickscan: no config at all -------------------------------------------


def test_quickscan_needs_no_config_and_does_not_journal_by_default(tmp_path):
    result = runner.invoke(app, ["quickscan", str(FIXTURES / "simple" / "records.jsonl"), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["run_metadata"]["config_path"] == "quickscan"
    assert list(payload["sources"]) == ["records"]  # named after the file stem
    assert payload["sources"]["records"]["status"] == "ok"
    assert payload["sources"]["records"]["profile"]["record_count"] == 10
    assert not (tmp_path / "scanner_journal.jsonl").exists()


def test_quickscan_defaults_to_markdown():
    result = runner.invoke(app, ["quickscan", str(FIXTURES / "simple" / "records.jsonl")])
    assert result.exit_code == 0, result.output
    assert "# Event Log Completeness Scanner Report" in result.stdout
    assert "### records" in result.stdout


def test_quickscan_names_globs_after_parent_dir_and_dedupes():
    result = runner.invoke(
        app,
        [
            "quickscan",
            str(FIXTURES / "mixed_formats" / "*.log"),
            str(FIXTURES / "simple" / "records.jsonl"),
            str(FIXTURES / "nested" / "records.jsonl"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert list(json.loads(result.stdout)["sources"]) == ["mixed_formats", "records", "records_2"]


def test_quickscan_record_root_and_event_class_apply_to_the_source():
    result = runner.invoke(
        app,
        [
            "quickscan",
            str(FIXTURES / "enveloped" / "splunk_export.jsonl"),
            "--record-root",
            "result",
            "--event-class",
            "activity",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    src = json.loads(result.stdout)["sources"]["splunk_export"]
    assert src["profile"]["envelope_hint"] is None  # unwrapped
    assert src["checks"]["C5"]["status"] == "PASS"
    assert src["checks"]["C8"]["status"] == "PASS"  # scored, since event_class was declared


def test_quickscan_rejects_bad_event_class():
    result = runner.invoke(
        app, ["quickscan", str(FIXTURES / "simple" / "records.jsonl"), "--event-class", "telemetry"]
    )
    assert result.exit_code == 1


def test_quickscan_emit_config_writes_a_minimal_loadable_config(tmp_path):
    from scanner.config import load_config

    cfg_out = tmp_path / "scanner.yaml"
    result = runner.invoke(
        app,
        [
            "quickscan",
            str(FIXTURES / "enveloped" / "splunk_export.jsonl"),
            "--record-root",
            "result",
            "--sample-size",
            "500",
            "--emit-config",
            str(cfg_out),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    import yaml

    text = cfg_out.read_text(encoding="utf-8")
    assert text.startswith("# Generated by `scanner quickscan`")
    data = yaml.safe_load(text)
    assert data["sources"][0]["record_root"] == "result"
    assert data["defaults"] == {"sample_size": 500}
    assert "owner" in data["sources"][0]
    assert "field_hints" not in data  # defaults are not dumped
    assert "schema" not in data["sources"][0]  # unset optionals are not dumped
    assert "event_class" not in data["sources"][0]

    # And it round-trips through the real loader, so `scanner scan --config`
    # on it is the same scan.
    loaded = load_config(cfg_out)
    assert loaded.sources[0].name == "splunk_export"
    assert loaded.sources[0].record_root == "result"
    assert loaded.defaults.sample_size == 500
    rescan = runner.invoke(app, ["scan", "--config", str(cfg_out), "--format", "json", "--journal", ""])
    assert rescan.exit_code == 0, rescan.output
    assert json.loads(rescan.stdout)["sources"]["splunk_export"]["checks"]["C5"]["status"] == "PASS"


def test_scan_random_strategy_output_is_byte_identical_across_runs(tmp_path):
    # sample_strategy defaults to "random" in _write_config -- this is the one
    # path where nondeterminism could sneak in if the seed weren't actually
    # threaded through consistently.
    cfg_path = _write_config(tmp_path, str(FIXTURES / "attribution" / "records.jsonl"))
    r1 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    r2 = runner.invoke(app, ["scan", "--config", str(cfg_path)])
    assert _normalize(r1.stdout) == _normalize(r2.stdout)
