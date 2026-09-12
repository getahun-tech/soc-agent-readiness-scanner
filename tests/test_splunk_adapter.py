"""Splunk adapter tests. None of these touch a real Splunk instance or
splunklib -- SplunkAdapter depends only on the narrow SplunkConnection
protocol, so a FakeSplunkConnection is enough to exercise all of its
own logic (bounding, sampling, field mapping, credential/capability
guards).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scanner.adapters.splunk import SplunkAdapter, SplunkCredential, _build_spl, _map_parsed_fields
from scanner.config import DefaultsConfig, ScannerConfig, SourceConfig, SplunkConnectionConfig
from scanner.exceptions import AdapterError


class FakeSplunkConnection:
    def __init__(self, records, capabilities=None):
        self._records = records
        self._capabilities = capabilities if capabilities is not None else {"search"}
        self.search_calls: list[tuple[str, int]] = []

    def capabilities(self):
        return self._capabilities

    def search(self, spl: str, count: int):
        self.search_calls.append((spl, count))
        return iter(self._records[:count])


def _fake_events(n: int, *, source_field: str | None = None) -> list[dict]:
    events = []
    for i in range(n):
        event = {
            "_raw": f"raw event {i}",
            "_time": f"2026-01-01T00:00:{i:02d}Z",
            "_indextime": f"176435000{i}",
            "host": f"host{i % 3}",
            "action": "block",
        }
        if source_field:
            event["source"] = source_field if i % 2 == 0 else f"{source_field}-b"
        events.append(event)
    return events


def _config(
    *, sample_size=3, sample_strategy="recent", seed=1, token_env_var="SPLUNK_TOKEN", auth="token"
) -> tuple[ScannerConfig, SourceConfig]:
    source = SourceConfig(
        name="splunk_src",
        adapter="splunk",
        query="index=network sourcetype=firewall",
        owner="ops@example.com",
    )
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=sample_size, sample_strategy=sample_strategy, seed=seed),
        splunk=SplunkConnectionConfig(host="splunk.example.com", token_env_var=token_env_var, auth=auth),
        sources=[source],
    )
    return cfg, source


# --- credential handling (sec 9.4) ----------------------------------------


def test_missing_token_env_var_raises_without_connecting(monkeypatch):
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    cfg, source = _config()
    called = []
    adapter = SplunkAdapter(connection_factory=lambda conn, credential: called.append(credential))

    with pytest.raises(AdapterError, match="SPLUNK_TOKEN"):
        adapter.fetch_sample(source, cfg)
    assert called == []


def test_token_value_never_appears_in_error_message(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "super-secret-token-value")
    cfg, source = _config()

    def _boom(conn, credential):
        # simulate a leaky underlying lib that echoes the raw secret
        raise RuntimeError(f"connect failed for token {credential.token}")

    adapter = SplunkAdapter(connection_factory=_boom)
    with pytest.raises(Exception) as exc_info:
        adapter.fetch_sample(source, cfg)
    assert "super-secret-token-value" not in str(exc_info.value)
    assert "***REDACTED***" in str(exc_info.value)


def test_token_auth_ignores_session_env_vars(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    monkeypatch.setenv("SPLUNK_USERNAME", "should-not-be-read")
    monkeypatch.setenv("SPLUNK_PASSWORD", "should-not-be-read")
    cfg, source = _config()
    seen = []
    fake = FakeSplunkConnection(_fake_events(3))

    def _factory(conn, credential):
        seen.append(credential)
        return fake

    SplunkAdapter(connection_factory=_factory).fetch_sample(source, cfg)
    assert seen[0].kind == "token"
    assert seen[0].token == "tok"
    assert seen[0].username is None and seen[0].password is None


# --- session auth: explicit fallback (sec 9.4) ------------------------------


def test_session_auth_requires_both_env_vars_and_names_the_missing_ones(monkeypatch):
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    cfg, source = _config(auth="session")
    called = []
    adapter = SplunkAdapter(connection_factory=lambda conn, credential: called.append(credential))

    with pytest.raises(AdapterError, match="SPLUNK_USERNAME.*SPLUNK_PASSWORD"):
        adapter.fetch_sample(source, cfg)
    assert called == []

    # Username alone isn't enough either -- and the message names only the gap.
    monkeypatch.setenv("SPLUNK_USERNAME", "scanner_ro")
    with pytest.raises(AdapterError, match="SPLUNK_PASSWORD") as exc_info:
        adapter.fetch_sample(source, cfg)
    assert "SPLUNK_USERNAME" not in str(exc_info.value)
    assert called == []


def test_session_auth_reads_username_and_password_and_proceeds(monkeypatch):
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)  # token must not be required here
    monkeypatch.setenv("SPLUNK_USERNAME", "scanner_ro")
    monkeypatch.setenv("SPLUNK_PASSWORD", "s3cret")
    cfg, source = _config(auth="session", sample_size=2)
    seen = []
    fake = FakeSplunkConnection(_fake_events(5))

    def _factory(conn, credential):
        seen.append(credential)
        return fake

    records, _ = SplunkAdapter(connection_factory=_factory).fetch_sample(source, cfg)
    assert len(list(records)) == 2
    assert seen[0].kind == "session"
    assert seen[0].username == "scanner_ro"
    assert seen[0].password == "s3cret"
    assert seen[0].token is None


def test_session_password_never_appears_in_error_message(monkeypatch):
    monkeypatch.setenv("SPLUNK_USERNAME", "scanner_ro")
    monkeypatch.setenv("SPLUNK_PASSWORD", "super-secret-password")
    cfg, source = _config(auth="session")

    def _boom(conn, credential):
        raise RuntimeError(f"login failed for {credential.username}/{credential.password}")

    with pytest.raises(Exception) as exc_info:
        SplunkAdapter(connection_factory=_boom).fetch_sample(source, cfg)
    assert "super-secret-password" not in str(exc_info.value)
    assert "scanner_ro" in str(exc_info.value)  # the username is not a secret


def test_session_auth_still_refuses_write_capable_accounts(monkeypatch):
    # The read-only gate is auth-agnostic: an admin password gets exactly
    # as far as an admin token, i.e. refused before any search runs.
    monkeypatch.setenv("SPLUNK_USERNAME", "admin")
    monkeypatch.setenv("SPLUNK_PASSWORD", "hunter2")
    cfg, source = _config(auth="session")
    fake = FakeSplunkConnection(_fake_events(5), capabilities={"search", "edit_forwarders"})

    with pytest.raises(AdapterError, match="edit_forwarders"):
        SplunkAdapter(connection_factory=lambda conn, credential: fake).fetch_sample(source, cfg)
    assert fake.search_calls == []


def test_credential_repr_is_redacted():
    cred = SplunkCredential(kind="session", username="scanner_ro", password="s3cret")
    assert "s3cret" not in repr(cred)
    assert "s3cret" not in str(cred)
    assert "scanner_ro" in repr(cred)
    assert SplunkCredential(kind="token", token="tok").secrets() == ["tok"]
    assert cred.secrets() == ["s3cret"]


def test_splunk_auth_rejects_unknown_kinds():
    with pytest.raises(ValidationError):
        SplunkConnectionConfig(host="splunk.example.com", auth="basic")


def test_missing_splunk_connection_config_raises():
    source = SourceConfig(
        name="splunk_src",
        adapter="splunk",
        query="index=network",
        owner="ops@example.com",
    )
    # A config with no splunk-adapter sources bypasses ScannerConfig's own
    # validator; calling fetch_sample directly with a mismatched source
    # still hits the adapter's own defensive check.
    cfg = ScannerConfig(version="1.0", ruleset_version="test", sources=[])
    adapter = SplunkAdapter(connection_factory=lambda conn, token: None)
    with pytest.raises(AdapterError, match="connection block"):
        adapter.fetch_sample(source, cfg)


# --- read-only guarantee (sec 9.1) -----------------------------------------


def test_write_capable_account_is_refused(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config()
    fake = FakeSplunkConnection(_fake_events(5), capabilities={"search", "delete_by_keyword"})
    adapter = SplunkAdapter(connection_factory=lambda conn, token: fake)

    with pytest.raises(AdapterError, match="delete_by_keyword"):
        adapter.fetch_sample(source, cfg)
    assert fake.search_calls == []  # refused before ever searching


def test_read_only_account_proceeds(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config(sample_size=3)
    fake = FakeSplunkConnection(_fake_events(5), capabilities={"search"})
    adapter = SplunkAdapter(connection_factory=lambda conn, token: fake)

    records, _ = adapter.fetch_sample(source, cfg)
    assert len(list(records)) == 3


# --- bounded sampling (sec 9.2) --------------------------------------------


def test_recent_strategy_fetches_exactly_the_configured_limit(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config(sample_size=3, sample_strategy="recent")
    fake = FakeSplunkConnection(_fake_events(10))
    adapter = SplunkAdapter(connection_factory=lambda conn, token: fake)

    records, meta = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert len(records) == 3
    assert meta.requested_size == 3
    assert meta.actual_size == 3
    spl, count = fake.search_calls[0]
    assert "| head 3" in spl
    assert count == 3


def test_random_strategy_never_exceeds_hard_ceiling_and_is_deterministic(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config(sample_size=3, sample_strategy="random", seed=7)
    fake1 = FakeSplunkConnection(_fake_events(20))
    fake2 = FakeSplunkConnection(_fake_events(20))
    adapter1 = SplunkAdapter(connection_factory=lambda conn, token: fake1)
    adapter2 = SplunkAdapter(connection_factory=lambda conn, token: fake2)

    records1, _meta1 = adapter1.fetch_sample(source, cfg)
    records2, _meta2 = adapter2.fetch_sample(source, cfg)
    r1, r2 = list(records1), list(records2)

    assert len(r1) == 3
    # oversample factor 5 * limit 3 = 15, well under the 50_000 hard ceiling
    assert fake1.search_calls[0][1] == 15
    assert "| head 15" in fake1.search_calls[0][0]
    assert [r.raw_text for r in r1] == [r.raw_text for r in r2]  # same seed -> same sample


def test_stratified_strategy_groups_by_splunk_source_field(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config(sample_size=4, sample_strategy="stratified", seed=1)
    fake = FakeSplunkConnection(_fake_events(20, source_field="firewall_log"))
    adapter = SplunkAdapter(connection_factory=lambda conn, token: fake)

    records, meta = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert len(records) == 4
    assert meta.strategy == "stratified"


# --- field mapping -----------------------------------------------------


def test_map_parsed_fields_aliases_splunk_internal_fields():
    item = {
        "_raw": "raw text",
        "_time": "2026-01-01T00:00:00Z",
        "_indextime": "1764350000",
        "host": "fw01",
        "action": "block",
    }
    parsed = _map_parsed_fields(item)
    assert parsed == {"host": "fw01", "action": "block", "timestamp": "2026-01-01T00:00:00Z", "ingest_time": "1764350000"}
    assert "_raw" not in parsed
    assert "_time" not in parsed


def test_fetch_sample_builds_structured_raw_records(monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    cfg, source = _config(sample_size=2, sample_strategy="recent")
    fake = FakeSplunkConnection(_fake_events(5))
    adapter = SplunkAdapter(connection_factory=lambda conn, token: fake)

    records, _ = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert records[0].structured is True
    assert records[0].parse_error is None
    assert records[0].parsed["timestamp"] == "2026-01-01T00:00:00Z"
    assert records[0].parsed["ingest_time"] == "1764350000"
    assert records[0].raw_text == "raw event 0"
    assert records[0].source_name == "splunk_src"


# --- SPL query building -----------------------------------------------------


def test_build_spl_prepends_search_when_missing():
    assert _build_spl("index=network", 100) == "search index=network | head 100"


def test_build_spl_leaves_existing_search_or_pipe_prefix_alone():
    assert _build_spl("search index=network", 50) == "search index=network | head 50"
    assert _build_spl("| tstats count", 50) == "| tstats count | head 50"
