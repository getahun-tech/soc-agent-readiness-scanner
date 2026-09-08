"""Read-only adapter for Microsoft Sentinel / Log Analytics (SPEC.md sec 9).

Same shape as the Splunk adapter and for the same reasons: SentinelAdapter
depends only on a narrow SentinelConnection protocol, not on the Azure
SDKs directly, so every test here runs against a FakeSentinelConnection
with no network, no Azure tenant, and no SDK install required. The real
implementation imports azure-identity/azure-monitor-query lazily (inside
RealSentinelConnection only) so the core package has no hard dependency
on the 'sentinel' optional extra.

Read-only guarantee (sec 9.1): unlike Splunk, there is no separate
capability check here. The Log Analytics *query* API
(`api.loganalytics.io` / `LogsQueryClient.query_workspace`) is
structurally query-only -- there is no write or delete operation
reachable through it at all, regardless of what the service principal's
broader Azure RBAC role grants elsewhere in the tenant. RealSentinelConnection
never constructs a client for any other Azure Monitor / Sentinel API
surface, so "fail loudly if granted write capability" reduces to "never
call anything but the query endpoint" -- enforced structurally by this
class only ever exposing `search()`, the same way the base Adapter
interface enforces it for every adapter.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Any, Protocol

from scanner.adapters.base import Adapter
from scanner.config import ScannerConfig, SentinelConnectionConfig, SourceConfig
from scanner.exceptions import AdapterError
from scanner.models import RawRecord, SampleMetadata
from scanner.sampling import reservoir_sample, stratified_sample_by_group

# Same rationale as the Splunk adapter's oversample-then-locally-sample
# approach: KQL has no reliably version-independent server-side seeded
# sampling primitive we can depend on, so "random"/"stratified" fetch a
# bounded superset and apply our own seeded sampling.py functions.
_OVERSAMPLE_FACTOR = 5
_HARD_FETCH_CEILING = 50_000


class SentinelConnection(Protocol):
    def search(self, kql: str, count: int) -> Iterator[dict[str, Any]]: ...


class RealSentinelConnection:
    # optional extra: pip install -e ".[sentinel]"
    def __init__(self, *, workspace_id: str, tenant_id: str, client_id: str, client_secret: str):
        from azure.identity import ClientSecretCredential
        from azure.monitor.query import LogsQueryClient

        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
            )
            self._client = LogsQueryClient(credential)
        except Exception as exc:
            # No `str(exc)` interpolation here -- this message never carries
            # anything the underlying SDK's own exception text might have
            # embedded. SentinelAdapter.fetch_sample's own try/except is the
            # authoritative scrub-and-break-chain layer around this whole
            # call (same pattern as RealSplunkConnection).
            raise AdapterError(
                f"failed to establish a Sentinel connection to workspace {workspace_id} "
                f"(tenant {tenant_id})"
            ) from exc
        self._workspace_id = workspace_id

    def search(self, kql: str, count: int) -> Iterator[dict[str, Any]]:
        from azure.monitor.query import LogsQueryStatus

        response = self._client.query_workspace(self._workspace_id, kql, timespan=None)
        if response.status != LogsQueryStatus.SUCCESS:
            raise AdapterError(
                f"Sentinel query did not complete successfully: "
                f"{getattr(response, 'partial_error', 'unknown error')}"
            )
        for table in response.tables:
            columns = list(table.columns)
            for row in table.rows[:count]:
                yield dict(zip(columns, row, strict=False))


ConnectionFactory = Callable[[SentinelConnectionConfig, str], SentinelConnection]


def _default_connection_factory(conn: SentinelConnectionConfig, client_secret: str) -> SentinelConnection:
    return RealSentinelConnection(
        workspace_id=conn.workspace_id,
        tenant_id=conn.tenant_id,
        client_id=conn.client_id,
        client_secret=client_secret,
    )


def _build_kql(query: str, strategy: str, fetch_cap: int) -> str:
    kql = query.strip()
    if strategy == "recent":
        kql = f"{kql} | sort by TimeGenerated desc"
    return f"{kql} | take {fetch_cap}"


def _map_parsed_fields(item: dict[str, Any]) -> dict[str, Any]:
    """Alias Log Analytics' `TimeGenerated` onto `timestamp` so C2's
    existing field-name heuristics pick it up with no adapter-specific
    check code, same pattern as Splunk's `_time` -> `timestamp` alias."""
    parsed = dict(item)
    if "TimeGenerated" in item:
        parsed["timestamp"] = item["TimeGenerated"]
    return parsed


class SentinelAdapter(Adapter):
    def __init__(self, connection_factory: ConnectionFactory | None = None):
        self._connection_factory = connection_factory or _default_connection_factory

    def fetch_sample(self, source: SourceConfig, config: ScannerConfig):
        assert source.query is not None  # enforced by SourceConfig validation

        if config.sentinel is None:
            raise AdapterError(
                f"source '{source.name}': adapter 'sentinel' requires a top-level 'sentinel:' "
                f"connection block in config"
            )

        client_secret = os.environ.get(config.sentinel.client_secret_env_var)
        if not client_secret:
            raise AdapterError(
                f"source '{source.name}': environment variable "
                f"'{config.sentinel.client_secret_env_var}' is not set -- Sentinel credentials "
                f"must come from the environment, never from config (SPEC.md sec 9.4)"
            )

        try:
            connection = self._connection_factory(config.sentinel, client_secret)
        except Exception as exc:  # noqa: BLE001 -- must scrub the secret before this propagates at all
            message = str(exc).replace(client_secret, "***REDACTED***")
            raise AdapterError(
                f"source '{source.name}': failed to establish a Sentinel connection: {message}"
            ) from None

        strategy = config.effective_sample_strategy(source)
        limit = config.effective_sample_size(source)
        seed = config.defaults.seed
        fetch_cap = limit if strategy == "recent" else min(limit * _OVERSAMPLE_FACTOR, _HARD_FETCH_CEILING)

        kql = _build_kql(source.query, strategy, fetch_cap)
        raw_results = list(connection.search(kql, fetch_cap))

        if strategy == "recent":
            chosen = raw_results[:limit]
        elif strategy == "random":
            chosen = reservoir_sample(raw_results, limit, seed)
        elif strategy == "stratified":
            grouped: dict[str, list[dict[str, Any]]] = {}
            for item in raw_results:
                key = str(item.get("Computer") or item.get("_ResourceId") or "unknown")
                grouped.setdefault(key, []).append(item)
            chosen = stratified_sample_by_group({k: iter(v) for k, v in grouped.items()}, limit, seed)
        else:  # pragma: no cover - config validation restricts sample_strategy
            raise AdapterError(f"source '{source.name}': unknown sample_strategy '{strategy}'")

        records = [
            RawRecord(
                source_name=source.name,
                index=i,
                origin_path=str(item.get("Computer") or item.get("_ResourceId") or kql),
                origin_line_no=i,
                raw_text=str(item),
                parsed=_map_parsed_fields(item),
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
            population_size=len(raw_results),
            actual_size=len(records),
            files_read=[kql],
        )
        return iter(records), metadata
