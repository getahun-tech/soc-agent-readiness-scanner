import pytest
from pydantic import ValidationError

from scanner.config import ConfigError, load_config

MINIMAL_VALID = """
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: file
    path: ./samples/a/*.log
    owner: "ops@example.com"
"""


def test_loads_minimal_valid_config(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(MINIMAL_VALID)
    cfg = load_config(p)
    assert cfg.version == "1.0"
    assert len(cfg.sources) == 1
    assert cfg.defaults.sample_size == 10000
    assert cfg.defaults.sample_strategy == "random"


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_empty_file_raises_config_error(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("")
    with pytest.raises(ConfigError):
        load_config(p)


def test_not_a_mapping_raises_config_error(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_file_adapter_requires_path(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: file
    owner: "ops@example.com"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_splunk_adapter_requires_query(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: splunk
    owner: "ops@example.com"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_sentinel_source_requires_top_level_connection_block(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: sentinel
    query: "SecurityEvent"
    owner: "ops@example.com"
""")
    with pytest.raises(ValidationError, match="connection block"):
        load_config(p)


def test_elastic_source_requires_query_and_index(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
elastic:
  url: "https://elastic.example.com:9200"
sources:
  - name: src_a
    adapter: elastic
    owner: "ops@example.com"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_valid_sentinel_and_elastic_config_loads(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sentinel:
  workspace_id: "ws-1"
  tenant_id: "tenant-1"
  client_id: "client-1"
elastic:
  url: "https://elastic.example.com:9200"
sources:
  - name: sentinel_src
    adapter: sentinel
    query: "SecurityEvent"
    owner: "ops@example.com"
  - name: elastic_src
    adapter: elastic
    query: "*"
    index: "logs-*"
    owner: "ops@example.com"
""")
    cfg = load_config(p)
    assert cfg.sentinel.workspace_id == "ws-1"
    assert cfg.elastic.url == "https://elastic.example.com:9200"
    assert len(cfg.sources) == 2


def test_duplicate_source_names_rejected(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: dup
    adapter: file
    path: ./a/*.log
    owner: "ops@example.com"
  - name: dup
    adapter: file
    path: ./b/*.log
    owner: "ops@example.com"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_precedence_rule_must_reference_known_sources(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: file
    path: ./a/*.log
    owner: "ops@example.com"
precedence_rules:
  - entities: [src_a, src_ghost]
    authoritative: src_a
    rationale: "test"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_precedence_rule_authoritative_must_be_in_entities(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
sources:
  - name: src_a
    adapter: file
    path: ./a/*.log
    owner: "ops@example.com"
  - name: src_b
    adapter: file
    path: ./b/*.log
    owner: "ops@example.com"
precedence_rules:
  - entities: [src_a, src_b]
    authoritative: src_c
    rationale: "test"
""")
    with pytest.raises(ValidationError):
        load_config(p)


def test_per_source_overrides_effective_sample_settings(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("""
version: "1.0"
ruleset_version: "2026.07"
defaults:
  sample_size: 500
  sample_strategy: random
sources:
  - name: src_a
    adapter: file
    path: ./a/*.log
    owner: "ops@example.com"
    sample_size: 50
    sample_strategy: recent
""")
    cfg = load_config(p)
    source = cfg.sources[0]
    assert cfg.effective_sample_size(source) == 50
    assert cfg.effective_sample_strategy(source) == "recent"
