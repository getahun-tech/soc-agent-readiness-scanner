"""Read-only adapter for Elastic/OpenSearch (SPEC.md sec 9).

Same shape as the Splunk and Sentinel adapters: ElasticAdapter depends
only on a narrow ElasticConnection protocol, not on the `elasticsearch`
client directly, so every test here runs against a FakeElasticConnection
with no network, no live cluster, and no client library install
required. The real implementation imports `elasticsearch` lazily (inside
RealElasticConnection only) so the core package has no hard dependency
on the 'elastic' optional extra.

Unlike Splunk's job-search API or Sentinel's query-only API, Elastic's
`_search` endpoint sits on the same client as `_bulk`/`_doc`/`_delete` --
so read-only isn't structural here the way it is for Sentinel, and needs
an explicit capability check the same way Splunk does, via the Security
API's "has privileges" endpoint (sec 9.1).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Any, Protocol

from scanner.adapters.base import Adapter
from scanner.config import ElasticConnectionConfig, ScannerConfig, SourceConfig
from scanner.exceptions import AdapterError
from scanner.models import RawRecord, SampleMetadata
from scanner.sampling import stratified_sample_by_group

# Index-level privileges that indicate the connected key can write to or
# delete indexed data -- not exhaustive, but the ones directly relevant
# to "must fail loudly if granted write capability" (sec 9.1).
_DANGEROUS_PRIVILEGES = {"write", "delete", "delete_index", "index"}
_HARD_FETCH_CEILING = 50_000


class ElasticConnection(Protocol):
    def search(self, index: str, query: dict[str, Any], size: int, seed: int | None) -> Iterator[dict[str, Any]]: ...
    def privileges(self, index: str) -> set[str]: ...


class RealElasticConnection:
    # optional extra: pip install -e ".[elastic]"
    def __init__(self, *, url: str, api_key: str, verify_ssl: bool):
        from elasticsearch import Elasticsearch

        try:
            self._client = Elasticsearch(url, api_key=api_key, verify_certs=verify_ssl)
        except Exception as exc:
            # No `str(exc)` interpolation here -- this message never carries
            # anything the underlying client's own exception text might have
            # embedded. ElasticAdapter.fetch_sample's own try/except is the
            # authoritative scrub-and-break-chain layer around this whole
            # call (same pattern as RealSplunkConnection).
            raise AdapterError(f"failed to establish an Elastic connection to {url}") from exc

    def privileges(self, index: str) -> set[str]:
        try:
            response = self._client.security.has_privileges(
                index=[{"names": [index], "privileges": sorted(_DANGEROUS_PRIVILEGES)}]
            )
            granted = response.get("index", {}).get(index, {})
            return {priv for priv, allowed in granted.items() if allowed}
        except Exception as exc:
            raise AdapterError(f"could not verify Elastic API key privileges: {exc}") from exc

    def search(
        self, index: str, query: dict[str, Any], size: int, seed: int | None
    ) -> Iterator[dict[str, Any]]:
        body: dict[str, Any] = {"query": query, "size": size}
        if seed is not None:
            body["query"] = {
                "function_score": {"query": query, "random_score": {"seed": seed, "field": "_seq_no"}}
            }
        response = self._client.search(index=index, body=body)
        for hit in response["hits"]["hits"]:
            source = dict(hit.get("_source", {}))
            source["_index"] = hit.get("_index")
            yield source


ConnectionFactory = Callable[[ElasticConnectionConfig, str], ElasticConnection]


def _default_connection_factory(conn: ElasticConnectionConfig, api_key: str) -> ElasticConnection:
    return RealElasticConnection(url=conn.url, api_key=api_key, verify_ssl=conn.verify_ssl)


def _assert_read_only(connection: ElasticConnection, index: str, source_name: str) -> None:
    granted = connection.privileges(index)
    if granted:
        raise AdapterError(
            f"source '{source_name}': Elastic API key has write-capable privilege(s) "
            f"{sorted(granted)} on index '{index}'; the scanner requires a strictly "
            f"read-only key (SPEC.md sec 9.1) -- refusing to scan"
        )


def _build_query(query: str) -> dict[str, Any]:
    query = query.strip()
    if not query or query == "*":
        return {"match_all": {}}
    return {"query_string": {"query": query}}


class ElasticAdapter(Adapter):
    def __init__(self, connection_factory: ConnectionFactory | None = None):
        self._connection_factory = connection_factory or _default_connection_factory

    def fetch_sample(self, source: SourceConfig, config: ScannerConfig):
        assert source.query is not None  # enforced by SourceConfig validation
        assert source.index is not None  # enforced by SourceConfig validation

        if config.elastic is None:
            raise AdapterError(
                f"source '{source.name}': adapter 'elastic' requires a top-level 'elastic:' "
                f"connection block in config"
            )

        api_key = os.environ.get(config.elastic.api_key_env_var)
        if not api_key:
            raise AdapterError(
                f"source '{source.name}': environment variable '{config.elastic.api_key_env_var}' "
                f"is not set -- Elastic credentials must come from the environment, never from "
                f"config (SPEC.md sec 9.4)"
            )

        try:
            connection = self._connection_factory(config.elastic, api_key)
        except Exception as exc:  # noqa: BLE001 -- must scrub the key before this propagates at all
            message = str(exc).replace(api_key, "***REDACTED***")
            raise AdapterError(
                f"source '{source.name}': failed to establish an Elastic connection: {message}"
            ) from None

        _assert_read_only(connection, source.index, source.name)

        strategy = config.effective_sample_strategy(source)
        limit = config.effective_sample_size(source)
        seed = config.defaults.seed
        query = _build_query(source.query)

        if strategy == "recent":
            chosen = list(connection.search(source.index, query, limit, seed=None))
            population = len(chosen)
        elif strategy == "random":
            # Elastic's random_score is itself seedable server-side -- unlike
            # Splunk/Sentinel, no local oversample-then-resample needed;
            # request exactly `limit` and the seed alone gives determinism.
            chosen = list(connection.search(source.index, query, limit, seed=seed))
            population = len(chosen)
        elif strategy == "stratified":
            fetch_cap = min(limit * 5, _HARD_FETCH_CEILING)
            raw_results = list(connection.search(source.index, query, fetch_cap, seed=seed))
            population = len(raw_results)
            grouped: dict[str, list[dict[str, Any]]] = {}
            for item in raw_results:
                grouped.setdefault(str(item.get("_index", "unknown")), []).append(item)
            chosen = stratified_sample_by_group({k: iter(v) for k, v in grouped.items()}, limit, seed)
        else:  # pragma: no cover - config validation restricts sample_strategy
            raise AdapterError(f"source '{source.name}': unknown sample_strategy '{strategy}'")

        records = [
            RawRecord(
                source_name=source.name,
                index=i,
                origin_path=str(item.get("_index", source.index)),
                origin_line_no=i,
                raw_text=str(item),
                parsed={k: v for k, v in item.items() if k != "_index"},
                parse_error=None,
                structured=True,
            )
            for i, item in enumerate(chosen)
        ]

        metadata = SampleMetadata(
            source_name=source.name,
            strategy=strategy,
            seed=seed,
            requested_size=limit,
            population_size=population,
            actual_size=len(records),
            files_read=[source.index],
        )
        return iter(records), metadata
