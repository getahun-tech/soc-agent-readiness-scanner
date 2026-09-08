"""Sentinel adapter tests. None of these touch a real Azure tenant or the
azure-identity/azure-monitor-query SDKs -- SentinelAdapter depends only
on the narrow SentinelConnection protocol, so a FakeSentinelConnection is
enough to exercise all of its own logic.
"""

from __future__ import annotations

import pytest

from scanner.adapters.sentinel import SentinelAdapter, _build_kql, _map_parsed_fields
from scanner.config import DefaultsConfig, ScannerConfig, SentinelConnectionConfig, SourceConfig
from scanner.exceptions import AdapterError


class FakeSentinelConnection:
    def __init__(self, records):
        self._records = records
        self.search_calls: list[tuple[str, int]] = []

    def search(self, kql: str, count: int):
        self.search_calls.append((kql, count))
        return iter(self._records[:count])


def _fake_events(n: int) -> list[dict]:
    return [
        {
            "TimeGenerated": f"2026-01-01T00:00:{i:02d}Z",
            "Computer": f"host{i % 3}",
            "EventID": 4625,
            "Activity": "Node Down",
        }
        for i in range(n)
    ]


def _config(*, sample_size=3, sample_strategy="recent", seed=1, secret_env_var="SENTINEL_CLIENT_SECRET"):
    source = SourceConfig(
        name="sentinel_src",
        adapter="sentinel",
        query="SecurityEvent",
        owner="ops@example.com",
    )
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=sample_size, sample_strategy=sample_strategy, seed=seed),
        sentinel=SentinelConnectionConfig(
            workspace_id="ws-1",
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret_env_var=secret_env_var,
        ),
        sources=[source],
    )
    return cfg, source


def test_missing_client_secret_env_var_raises_without_connecting(monkeypatch):
    monkeypatch.delenv("SENTINEL_CLIENT_SECRET", raising=False)
    cfg, source = _config()
    called = []
    adapter = SentinelAdapter(connection_factory=lambda conn, secret: called.append(secret))
    with pytest.raises(AdapterError, match="SENTINEL_CLIENT_SECRET"):
        adapter.fetch_sample(source, cfg)
    assert called == []


def test_secret_value_never_appears_in_error_message(monkeypatch):
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "super-secret-value")

    def _boom(conn, secret):
        raise RuntimeError(f"connect failed for secret {secret}")

    cfg, source = _config()
    adapter = SentinelAdapter(connection_factory=_boom)
    with pytest.raises(Exception) as exc_info:
        adapter.fetch_sample(source, cfg)
    assert "super-secret-value" not in str(exc_info.value)


def test_missing_sentinel_connection_config_raises():
    source = SourceConfig(
        name="sentinel_src", adapter="sentinel", query="SecurityEvent",
        owner="ops@example.com",
    )
    cfg = ScannerConfig(version="1.0", ruleset_version="test", sources=[])
    adapter = SentinelAdapter(connection_factory=lambda conn, secret: None)
    with pytest.raises(AdapterError, match="connection block"):
        adapter.fetch_sample(source, cfg)


def test_recent_strategy_fetches_exactly_the_configured_limit(monkeypatch):
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "tok")
    cfg, source = _config(sample_size=3, sample_strategy="recent")
    fake = FakeSentinelConnection(_fake_events(10))
    adapter = SentinelAdapter(connection_factory=lambda conn, secret: fake)

    records, meta = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert len(records) == 3
    assert meta.requested_size == 3
    kql, count = fake.search_calls[0]
    assert "| take 3" in kql
    assert "sort by TimeGenerated desc" in kql
    assert count == 3


def test_random_strategy_never_exceeds_hard_ceiling_and_is_deterministic(monkeypatch):
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "tok")
    cfg, source = _config(sample_size=3, sample_strategy="random", seed=7)
    fake1 = FakeSentinelConnection(_fake_events(20))
    fake2 = FakeSentinelConnection(_fake_events(20))
    adapter1 = SentinelAdapter(connection_factory=lambda conn, secret: fake1)
    adapter2 = SentinelAdapter(connection_factory=lambda conn, secret: fake2)

    r1 = list(adapter1.fetch_sample(source, cfg)[0])
    r2 = list(adapter2.fetch_sample(source, cfg)[0])

    assert len(r1) == 3
    assert fake1.search_calls[0][1] == 15  # oversample factor 5 * limit 3
    assert [r.raw_text for r in r1] == [r.raw_text for r in r2]


def test_map_parsed_fields_aliases_time_generated():
    item = {"TimeGenerated": "2026-01-01T00:00:00Z", "Computer": "host1"}
    parsed = _map_parsed_fields(item)
    assert parsed["timestamp"] == "2026-01-01T00:00:00Z"
    assert parsed["TimeGenerated"] == "2026-01-01T00:00:00Z"  # original kept too
    assert parsed["Computer"] == "host1"


def test_fetch_sample_builds_structured_raw_records(monkeypatch):
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "tok")
    cfg, source = _config(sample_size=2, sample_strategy="recent")
    fake = FakeSentinelConnection(_fake_events(5))
    adapter = SentinelAdapter(connection_factory=lambda conn, secret: fake)

    records = list(adapter.fetch_sample(source, cfg)[0])
    assert records[0].structured is True
    assert records[0].parse_error is None
    assert records[0].parsed["timestamp"] == "2026-01-01T00:00:00Z"
    assert records[0].source_name == "sentinel_src"


def test_build_kql_appends_take_and_sort_for_recent():
    assert _build_kql("SecurityEvent", "recent", 50) == "SecurityEvent | sort by TimeGenerated desc | take 50"
    assert _build_kql("SecurityEvent", "random", 50) == "SecurityEvent | take 50"
