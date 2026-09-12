from scanner.diff import diff_entries, find_baseline, load_journal, render_diff_markdown


def _entry(timestamp, verdicts, config_path="cfg.yaml"):
    return {"timestamp": timestamp, "config_path": config_path, "verdicts": verdicts}


def _verdict(eligible, failed_gates, checks, score="5.0/6"):
    return {
        "eligible": eligible,
        "completeness_score": score,
        "failed_gates": failed_gates,
        "checks": checks,
    }


_GOOD = {"C1": "PASS", "C2": "PASS", "C3": "PASS", "C4": "PASS", "C5": "PASS", "C6": "PASS", "C7": "PASS"}


def test_no_baseline_is_an_explicit_note_not_a_regression():
    d = diff_entries(None, _entry("t1", {"a": _verdict(True, [], _GOOD)}))
    assert d.baseline_timestamp is None
    assert "nothing to compare" in d.note
    assert d.has_regression is False
    assert d.added_sources == ["a"]
    assert "nothing to compare" in render_diff_markdown(d)


def test_check_regressions_and_improvements_are_ranked_not_just_different():
    before = _entry("t1", {"a": _verdict(False, ["C2"], {**_GOOD, "C2": "WARN", "C5": "FAIL", "C7": "PASS"})})
    after = _entry("t2", {"a": _verdict(False, ["C2"], {**_GOOD, "C2": "FAIL", "C5": "WARN", "C7": "NOT_ASSESSED"})})
    d = diff_entries(before, after)

    by_id = {c.check_id: c.direction for c in d.check_changes}
    assert by_id == {"C2": "regression", "C5": "improvement", "C7": "regression"}
    assert d.regressions == ["a / C2: WARN -> FAIL", "a / C7: PASS -> NOT_ASSESSED"]
    assert d.improvements == ["a / C5: FAIL -> WARN"]
    assert d.has_regression is True
    assert d.compared_sources == 1
    assert d.compared_checks == 7


def test_fail_to_not_assessed_is_lateral_and_never_a_regression():
    before = _entry("t1", {"a": _verdict(False, ["C4"], {**_GOOD, "C4": "FAIL"})})
    after = _entry("t2", {"a": _verdict(False, ["C4"], {**_GOOD, "C4": "NOT_ASSESSED"})})
    d = diff_entries(before, after)
    assert [c.direction for c in d.check_changes] == ["lateral"]
    assert d.has_regression is False
    assert "(lateral)" in render_diff_markdown(d)


def test_eligibility_flip_names_the_newly_failing_gates():
    before = _entry("t1", {"a": _verdict(True, [], _GOOD)})
    after = _entry("t2", {"a": _verdict(False, ["C2", "C4"], {**_GOOD, "C2": "FAIL", "C4": "FAIL"})})
    d = diff_entries(before, after)

    assert len(d.eligibility_changes) == 1
    e = d.eligibility_changes[0]
    assert e.direction == "regression"
    assert e.gates_newly_failing == ["C2", "C4"]
    assert d.regressions[0] == "a: ELIGIBLE -> NOT ELIGIBLE (newly failing gates: C2, C4)"

    # And the reverse direction reads as an improvement.
    back = diff_entries(after, before)
    assert back.improvements[0] == "a: NOT ELIGIBLE -> ELIGIBLE"
    assert back.has_regression is False


def test_added_and_removed_sources_and_score_changes_are_reported_not_scored():
    before = _entry("t1", {"a": _verdict(True, [], _GOOD, score="6.0/6"), "gone": _verdict(True, [], _GOOD)})
    after = _entry("t2", {"a": _verdict(True, [], _GOOD, score="5.5/6"), "new": _verdict(False, ["C2"], _GOOD)})
    d = diff_entries(before, after)

    assert d.added_sources == ["new"]
    assert d.removed_sources == ["gone"]
    assert [(s.before, s.after) for s in d.score_changes] == [("6.0/6", "5.5/6")]
    assert d.has_regression is False  # nothing comparable got worse
    md = render_diff_markdown(d)
    assert "score 6.0/6 -> 5.5/6" in md
    assert "new in this run: new" in md
    assert "absent from this run" in md


def test_baseline_without_per_check_statuses_degrades_to_eligibility_and_score():
    old_style = {"eligible": True, "completeness_score": "6.0/6", "failed_gates": []}
    before = _entry("t1", {"a": old_style})
    after = _entry("t2", {"a": _verdict(False, ["C2"], {**_GOOD, "C2": "FAIL"})})
    d = diff_entries(before, after)

    assert "predates per-check statuses" in d.note
    assert d.check_changes == []
    assert d.compared_checks == 0
    assert d.regressions == ["a: ELIGIBLE -> NOT ELIGIBLE (newly failing gates: C2)"]


def test_find_baseline_matches_config_path_and_takes_the_latest(tmp_path):
    journal = tmp_path / "j.jsonl"
    journal.write_text(
        '{"timestamp": "t1", "config_path": "a.yaml", "verdicts": {}}\n'
        '{"timestamp": "t2", "config_path": "b.yaml", "verdicts": {}}\n'
        "\n"
        '{"timestamp": "t3", "config_path": "a.yaml", "verdicts": {}}',
        encoding="utf-8",
    )
    entries = load_journal(journal)
    assert [e["timestamp"] for e in entries] == ["t1", "t2", "t3"]  # blank line skipped
    assert find_baseline(entries, "a.yaml")["timestamp"] == "t3"
    assert find_baseline(entries, "b.yaml")["timestamp"] == "t2"
    assert find_baseline(entries, "c.yaml") is None


def test_load_journal_refuses_a_damaged_line(tmp_path):
    import pytest

    journal = tmp_path / "j.jsonl"
    journal.write_text('{"timestamp": "t1"}\n{not json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        load_journal(journal)
