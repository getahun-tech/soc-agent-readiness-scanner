from pathlib import Path

import pytest

from scanner.adapters.file import FileAdapter
from scanner.config import DefaultsConfig, FieldHints, ScannerConfig, SourceConfig
from scanner.profiler import Profiler
from scanner.profiles import (
    ProfileError,
    ProfileRegistry,
    conformance,
    effective_field_hints,
    select_profile,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _source(path: str, **overrides) -> SourceConfig:
    return SourceConfig(name="s", adapter="file", path=path, owner="ops@example.com", **overrides)


def _records(source: SourceConfig):
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=100, sample_strategy="random", seed=1),
        sources=[],
    )
    return list(FileAdapter().fetch_sample(source, cfg)[0])


# --- registry ---------------------------------------------------------------


def test_every_bundled_profile_loads_and_is_well_formed():
    registry = ProfileRegistry.load()
    ids = {p.id for p in registry.all()}
    assert {"pan:traffic", "windows:security", "windows:perfmon", "aws:cloudtrail"} <= ids
    for p in registry.all():
        assert p.match.sourcetype, p.id
        assert p.expected_fields, p.id
        assert p.guidance, p.id


def test_exact_sourcetype_match_beats_glob_and_matching_is_case_insensitive():
    registry = ProfileRegistry.load()
    assert registry.match_sourcetype("wineventlog:security").id == "windows:security"
    assert registry.match_sourcetype("Perfmon:Available Memory").id == "windows:perfmon"
    assert registry.match_sourcetype("pan:threat") is None


def test_extra_profile_dir_overrides_bundled_by_id_and_bad_files_are_loud(tmp_path):
    (tmp_path / "override.yaml").write_text(
        "id: pan:traffic\nname: Our tuned PAN profile\nmatch:\n  sourcetype: ['pan:traffic']\n"
        "expected_fields:\n  - {name: rule, presence: 1.0}\nguidance: internal wiki\n",
        encoding="utf-8",
    )
    registry = ProfileRegistry.load([str(tmp_path)])
    assert registry.get("pan:traffic").name == "Our tuned PAN profile"

    (tmp_path / "broken.yaml").write_text("id: x\nname: no match block\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="broken.yaml"):
        ProfileRegistry.load([str(tmp_path)])
    with pytest.raises(ProfileError, match="not found"):
        ProfileRegistry.load([str(tmp_path / "does_not_exist")])


# --- selection --------------------------------------------------------------


def test_auto_detects_from_the_sourcetype_field_when_one_type_dominates():
    source = _source(str(FIXTURES / "enveloped" / "splunk_export.jsonl"), record_root="result")
    sel = select_profile(source, _records(source), ProfileRegistry.load())
    assert sel.profile.id == "windows:security"
    assert "auto-detected from sourcetype='WinEventLog:Security'" in sel.summary
    assert sel.mixed is False


def test_mixed_sourcetypes_apply_no_profile_and_say_how_to_split():
    source = _source(str(FIXTURES / "mixed_sourcetypes" / "records.jsonl"))
    sel = select_profile(source, _records(source), ProfileRegistry.load())
    assert sel.profile is None
    assert sel.mixed is True
    assert sel.sourcetype_field == "sourcetype"
    assert sel.distribution["WinEventLog:Security"] == pytest.approx(0.6)
    assert "split this source by sourcetype" in sel.summary


def test_declared_profile_wins_and_none_disables_and_unknown_id_is_named():
    registry = ProfileRegistry.load()
    path = str(FIXTURES / "enveloped" / "splunk_export.jsonl")

    declared = _source(path, record_root="result", profile="aws:cloudtrail")
    sel = select_profile(declared, _records(declared), registry)
    assert sel.profile.id == "aws:cloudtrail"
    assert "declared in config" in sel.summary

    off = _source(path, record_root="result", profile="none")
    assert select_profile(off, _records(off), registry).profile is None

    typo = _source(path, record_root="result", profile="pan:trafic")
    sel = select_profile(typo, _records(typo), registry)
    assert sel.profile is None
    assert "not in the registry" in sel.summary and "pan:traffic" in sel.summary


def test_no_sourcetype_like_field_means_generic_checks_only():
    source = _source(str(FIXTURES / "simple" / "records.jsonl"))
    sel = select_profile(source, _records(source), ProfileRegistry.load())
    assert sel.profile is None
    assert "no sourcetype-like field" in sel.summary


# --- what a profile changes -------------------------------------------------


def test_role_hints_are_prepended_never_replacing_the_generic_lists():
    profile = ProfileRegistry.load().get("windows:security")
    base = FieldHints(outcome=["disposition"], actor=["user"])
    hints = effective_field_hints(base, profile)
    assert hints.outcome[0] == "Keywords"  # profile first
    assert "disposition" in hints.outcome  # config's own still there
    assert hints.actor[:2] == ["SubjectUserName", "Account_Name"]
    assert hints.actor.count("user") == 1  # deduped, case-insensitively
    assert effective_field_hints(base, None) is base


def test_conformance_reports_shortfalls_against_expected_presence():
    source = _source(str(FIXTURES / "enveloped" / "splunk_export.jsonl"), record_root="result")
    stats = Profiler().profile("s", _records(source)).field_stats
    rows = conformance(ProfileRegistry.load().get("windows:security"), stats)
    by_field = {r["field"]: r for r in rows}
    # The fixture is labelled WinEventLog:Security but carries none of the
    # Windows field names -- exactly the "mislabelled or unextracted" case.
    assert by_field["EventCode"]["shortfall"] is True
    assert by_field["EventCode"]["observed_presence"] == 0.0
    assert by_field["TargetUserName"]["note"]  # conditional fields keep their note
    assert all(r["shortfall"] for r in rows)
