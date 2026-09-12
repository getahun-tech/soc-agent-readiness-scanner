"""Elastic adapter tests. None of these touch a real cluster or the
`elasticsearch` client library -- ElasticAdapter depends only on the
narrow ElasticConnection protocol, so a FakeElasticConnection is enough
to exercise all of its own logic.
"""

from __future__ import annotations

import pytest

from scanner.adapters.elastic import ElasticAdapter, _build_query
from scanner.config import DefaultsConfig, ElasticConnectionConfig, ScannerConfig, SourceConfig
from scanner.exceptions import AdapterError


class FakeElasticConnection:
    def __init__(self, records, privileges=None):
        self._records = records
        self._privileges = privileges if privileges is not None else set()
        self.search_calls: list[tuple[str, dict, int, int | None]] = []
        self.privileges_calls: list[str] = []

    def privileges(self, index: str):
        self.privileges_calls.append(index)
        return self._privileges

    def search(self, index: str, query: dict, size: int, seed):
        self.search_calls.append((index, query, size, seed))
        return iter(self._records[:size])


def _fake_hits(n: int, *, index_field: str | None = None) -> list[dict]:
    hits = []
    for i in range(n):
        hit = {
            "@timestamp": f"2026-01-01T00:00:{i:02d}Z",
            "host": {"name": f"host{i % 3}"},
            "event": {"action": "block"},
        }
        if index_field:
            hit["_index"] = index_field if i % 2 == 0 else f"{index_field}-b"
        hits.append(hit)
    return hits


def _config(*, sample_size=3, sample_strategy="recent", seed=1, api_key_env_var="ELASTIC_API_KEY"):
    source = SourceConfig(
        name="elastic_src",
        adapter="elastic",
        query="event.action:block",
        index="logs-firewall-*",
        owner="ops@example.com",
    )
    cfg = ScannerConfig(
        version="1.0",
        ruleset_version="test",
        defaults=DefaultsConfig(sample_size=sample_size, sample_strategy=sample_strategy, seed=seed),
        elastic=ElasticConnectionConfig(url="https://elastic.example.com:9200", api_key_env_var=api_key_env_var),
        sources=[source],
    )
    return cfg, source


# --- credential handling (sec 9.4) ------------------------------------


def test_missing_api_key_env_var_raises_without_connecting(monkeypatch):
    monkeypatch.delenv("ELASTIC_API_KEY", raising=False)
    cfg, source = _config()
    called = []
    adapter = ElasticAdapter(connection_factory=lambda conn, key: called.append(key))
    with pytest.raises(AdapterError, match="ELASTIC_API_KEY"):
        adapter.fetch_sample(source, cfg)
    assert called == []


def test_api_key_value_never_appears_in_error_message(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "super-secret-key")

    def _boom(conn, key):
        raise RuntimeError(f"connect failed for key {key}")

    cfg, source = _config()
    adapter = ElasticAdapter(connection_factory=_boom)
    with pytest.raises(Exception) as exc_info:
        adapter.fetch_sample(source, cfg)
    assert "super-secret-key" not in str(exc_info.value)


def test_missing_elastic_connection_config_raises():
    source = SourceConfig(
        name="elastic_src", adapter="elastic", query="*", index="logs-*",
        owner="ops@example.com",
    )
    cfg = ScannerConfig(version="1.0", ruleset_version="test", sources=[])
    adapter = ElasticAdapter(connection_factory=lambda conn, key: None)
    with pytest.raises(AdapterError, match="connection block"):
        adapter.fetch_sample(source, cfg)


# --- read-only guarantee (sec 9.1) -----------------------------------


def test_write_capable_key_is_refused(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config()
    fake = FakeElasticConnection(_fake_hits(5), privileges={"write", "delete"})
    adapter = ElasticAdapter(connection_factory=lambda conn, key: fake)

    with pytest.raises(AdapterError, match="write"):
        adapter.fetch_sample(source, cfg)
    assert fake.search_calls == []  # refused before ever searching


def test_read_only_key_proceeds(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config(sample_size=3)
    fake = FakeElasticConnection(_fake_hits(5), privileges=set())
    adapter = ElasticAdapter(connection_factory=lambda conn, key: fake)

    records, _ = adapter.fetch_sample(source, cfg)
    assert len(list(records)) == 3
    assert fake.privileges_calls == ["logs-firewall-*"]


# --- sampling ----------------------------------------------------------


def test_recent_strategy_requests_exactly_the_configured_limit_no_random_score(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config(sample_size=3, sample_strategy="recent")
    fake = FakeElasticConnection(_fake_hits(10))
    adapter = ElasticAdapter(connection_factory=lambda conn, key: fake)

    records, meta = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert len(records) == 3
    assert meta.requested_size == 3
    _index, _query, size, seed = fake.search_calls[0]
    assert size == 3
    assert seed is None


def test_random_strategy_requests_exactly_the_limit_with_seed_no_local_oversample(monkeypatch):
    # Unlike Splunk/Sentinel, Elastic's random_score is itself seedable
    # server-side, so no oversample-then-locally-resample is needed.
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config(sample_size=3, sample_strategy="random", seed=7)
    fake1 = FakeElasticConnection(_fake_hits(20))
    fake2 = FakeElasticConnection(_fake_hits(20))
    adapter1 = ElasticAdapter(connection_factory=lambda conn, key: fake1)
    adapter2 = ElasticAdapter(connection_factory=lambda conn, key: fake2)

    r1 = list(adapter1.fetch_sample(source, cfg)[0])
    r2 = list(adapter2.fetch_sample(source, cfg)[0])

    assert len(r1) == 3
    assert fake1.search_calls[0][2] == 3  # size == limit, not oversampled
    assert fake1.search_calls[0][3] == 7  # seed passed through
    assert [r.raw_text for r in r1] == [r.raw_text for r in r2]


def test_stratified_strategy_groups_by_elastic_index(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config(sample_size=4, sample_strategy="stratified", seed=1)
    fake = FakeElasticConnection(_fake_hits(20, index_field="logs-firewall-2026.01"))
    adapter = ElasticAdapter(connection_factory=lambda conn, key: fake)

    records, meta = adapter.fetch_sample(source, cfg)
    records = list(records)
    assert len(records) == 4
    assert meta.strategy == "stratified"


# --- record mapping ------------------------------------------------------


def test_fetch_sample_builds_structured_raw_records_and_strips_index_field(monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", "key")
    cfg, source = _config(sample_size=2, sample_strategy="recent")
    fake = FakeElasticConnection(_fake_hits(5, index_field="logs-firewall-2026.01"))
    adapter = ElasticAdapter(connection_factory=lambda conn, key: fake)

    records = list(adapter.fetch_sample(source, cfg)[0])
    assert records[0].structured is True
    assert records[0].parse_error is None
    assert "_index" not in records[0].parsed
    assert records[0].parsed["@timestamp"] == "2026-01-01T00:00:00Z"
    # ECS nesting is flattened so the dotted field-hint candidates match.
    assert records[0].parsed["host.name"] == "host0"
    assert records[0].parsed["event.action"] == "block"
    assert "host" not in records[0].parsed
    assert records[0].origin_path == "logs-firewall-2026.01"
    assert records[0].source_name == "elastic_src"


# --- query building --------------------------------------------------------


def test_build_query_match_all_for_empty_or_star():
    assert _build_query("") == {"match_all": {}}
    assert _build_query("*") == {"match_all": {}}


def test_build_query_query_string_otherwise():
    assert _build_query("event.action:block") == {"query_string": {"query": "event.action:block"}}
