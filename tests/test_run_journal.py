import json

from scanner.run_journal import append_journal_entry, build_journal_entry


def _fake_result():
    return {
        "run_metadata": {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "ruleset_version": "v1",
            "sources_scanned": ["src_a"],
        },
        "sources": {
            "src_a": {
                "sample": {"actual_size": 10},
                "verdict": {
                    "eligibility": {
                        "eligible": False,
                        "gates": [
                            {"gate_id": "C2", "passed": True},
                            {"gate_id": "C4", "passed": False},
                        ],
                    },
                    "completeness": {"score": 5, "denominator": 6},
                },
            },
            "splunk_source": {"sample": None, "verdict": None},
        },
    }


def test_build_journal_entry_extracts_sample_sizes_and_verdicts():
    entry = build_journal_entry(_fake_result(), operator="alice", config_path="cfg.yaml", config_hash="abc123")
    assert entry.sample_sizes == {"src_a": 10}
    assert entry.verdicts["src_a"]["eligible"] is False
    assert entry.verdicts["src_a"]["failed_gates"] == ["C4"]
    assert entry.verdicts["src_a"]["completeness_score"] == "5/6"
    # not_implemented/error sources have no verdict and are skipped, not KeyErrored.
    assert "splunk_source" not in entry.verdicts


def test_append_journal_entry_is_append_only(tmp_path):
    path = tmp_path / "journal.jsonl"
    entry1 = build_journal_entry(_fake_result(), operator="alice", config_path="cfg.yaml", config_hash="abc")
    entry2 = build_journal_entry(_fake_result(), operator="bob", config_path="cfg.yaml", config_hash="abc")
    append_journal_entry(path, entry1)
    append_journal_entry(path, entry2)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["operator"] == "alice"
    assert parsed[1]["operator"] == "bob"


def test_append_journal_entry_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "dir" / "journal.jsonl"
    entry = build_journal_entry(_fake_result(), operator="alice", config_path="cfg.yaml", config_hash=None)
    append_journal_entry(path, entry)
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0])["config_hash"] is None
