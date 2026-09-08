"""Read-only adapter for Splunk (SPEC.md sec 9). splunklib is an optional
extra (`pip install -e ".[splunk]"`) -- nothing in this module imports it
at module load time, only inside `RealSplunkConnection`, so the core
package never hard-depends on it (sec 10).

`SplunkAdapter` itself depends only on the narrow `SplunkConnection`
protocol below, not on splunklib directly. That's what lets every test in
this file run against a `FakeSplunkConnection` with no network, no real
Splunk instance, and no splunklib import at all.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Any, Protocol

from scanner.adapters.base import Adapter
from scanner.config import ScannerConfig, SourceConfig, SplunkConnectionConfig
from scanner.exceptions import AdapterError
from scanner.models import RawRecord, SampleMetadata
from scanner.sampling import reservoir_sample, stratified_sample_by_group

# Capabilities that indicate the connected account can write to or delete
# indexed data / configuration -- not an exhaustive list of every Splunk
# capability, but the ones directly relevant to "must fail loudly if
# granted write capability" (sec 9.1). Fails closed: if capabilities can't
# be read at all, that also raises rather than proceeding silently.
_DANGEROUS_CAPABILITIES = {
    "delete_by_keyword",
    "edit_deployment_client",
    "edit_deployment_server",
    "edit_forwarders",
    "edit_indexer_cluster",
    "output_file",
    "input_file",
}

# "random"/"stratified" strategies can't be sampled server-side without a
# Splunk feature we can't rely on existing across versions, so instead we
# fetch a bounded, still-far-from-the-full-index superset and apply our
# own seeded sampling.py functions on it -- same determinism guarantee as
# the file adapter, at the cost of that superset not being the *entire*
# matching result set. "recent" needs no oversampling: `| head` already
# gives the most recent N directly.
_OVERSAMPLE_FACTOR = 5
_HARD_FETCH_CEILING = 50_000


class SplunkConnection(Protocol):
    def search(self, spl: str, count: int) -> Iterator[dict[str, Any]]: ...
    def capabilities(self) -> set[str]: ...


class RealSplunkConnection:
    def __init__(self, *, host: str, port: int, scheme: str, token: str, verify_ssl: bool):
        from splunklib import client  # optional extra: pip install -e ".[splunk]"

        try:
            # `splunkToken`, not `token` -- splunklib sends `token=` as a legacy
            # session key (`Authorization: Splunk <value>`), which Splunk's
            # REST API rejects for a JWT from Settings > Tokens ("Session is
            # not logged in"). `splunkToken` is what routes through the
            # Bearer-auth path (`Authorization: Bearer <value>`) that a JWT
            # authentication token actually needs.
            self._service = client.connect(
                host=host,
                port=port,
                scheme=scheme,
                splunkToken=token,
                verify=verify_ssl,
                autologin=False,
            )
        except Exception as exc:
            # `token` must never appear in this message (SPEC.md sec 9.4).
            raise AdapterError(f"failed to connect to Splunk at {scheme}://{host}:{port}") from exc

    def capabilities(self) -> set[str]:
        import json

        try:
            response = self._service.get("authentication/current-context", output_mode="json")
            body = json.loads(response.body.read())
            return set(body["entry"][0]["content"]["capabilities"])
        except Exception as exc:
            raise AdapterError(f"could not verify Splunk account capabilities: {exc}") from exc

    def search(self, spl: str, count: int) -> Iterator[dict[str, Any]]:
        from splunklib import results

        job = self._service.jobs.create(spl, exec_mode="blocking")
        try:
            for item in results.ResultsReader(job.results(count=count)):
                if isinstance(item, dict):
                    yield dict(item)
        finally:
            job.cancel()


ConnectionFactory = Callable[[SplunkConnectionConfig, str], SplunkConnection]


def _default_connection_factory(conn: SplunkConnectionConfig, token: str) -> SplunkConnection:
    return RealSplunkConnection(
        host=conn.host, port=conn.port, scheme=conn.scheme, token=token, verify_ssl=conn.verify_ssl
    )


def _assert_read_only(connection: SplunkConnection, source_name: str) -> None:
    risky = connection.capabilities() & _DANGEROUS_CAPABILITIES
    if risky:
        raise AdapterError(
            f"source '{source_name}': Splunk account has write-capable permission(s) "
            f"{sorted(risky)}; the scanner requires a strictly read-only account "
            f"(SPEC.md sec 9.1) -- refusing to scan"
        )


def _build_spl(query: str, fetch_cap: int) -> str:
    spl = query.strip()
    if not spl.lower().startswith(("search ", "|")):
        spl = f"search {spl}"
    return f"{spl} | head {fetch_cap}"


def _map_parsed_fields(item: dict[str, Any]) -> dict[str, Any]:
    """Drop Splunk's underscore-prefixed internal fields, but alias the two
    that matter to our checks onto the field names they already look for:
    `_time` -> `timestamp` (C2), `_indextime` -> `ingest_time` (C2's
    event-time-vs-ingest-time sub-check).
    """
    parsed = {k: v for k, v in item.items() if not str(k).startswith("_")}
    if "_time" in item:
        parsed["timestamp"] = item["_time"]
    if "_indextime" in item:
        parsed["ingest_time"] = item["_indextime"]
    return parsed


class SplunkAdapter(Adapter):
    def __init__(self, connection_factory: ConnectionFactory | None = None):
        self._connection_factory = connection_factory or _default_connection_factory

    def fetch_sample(self, source: SourceConfig, config: ScannerConfig):
        assert source.query is not None  # enforced by SourceConfig validation

        if config.splunk is None:
            raise AdapterError(
                f"source '{source.name}': adapter 'splunk' requires a top-level 'splunk:' "
                f"connection block in config"
            )

        token = os.environ.get(config.splunk.token_env_var)
        if not token:
            raise AdapterError(
                f"source '{source.name}': environment variable '{config.splunk.token_env_var}' "
                f"is not set -- Splunk credentials must come from the environment, never from "
                f"config (SPEC.md sec 9.4)"
            )

        try:
            connection = self._connection_factory(config.splunk, token)
        except Exception as exc:  # noqa: BLE001 -- must scrub the token before this propagates at all
            # Scrub defensively and break the exception chain (`from None`):
            # a custom connection_factory's own exception text -- or its
            # traceback via __cause__ -- could otherwise still carry the
            # token even though RealSplunkConnection itself is careful not
            # to (sec 9.4: never log credential values, including debug output).
            message = str(exc).replace(token, "***REDACTED***")
            raise AdapterError(
                f"source '{source.name}': failed to establish a Splunk connection: {message}"
            ) from None

        _assert_read_only(connection, source.name)

        strategy = config.effective_sample_strategy(source)
        limit = config.effective_sample_size(source)
        seed = config.defaults.seed
        fetch_cap = limit if strategy == "recent" else min(limit * _OVERSAMPLE_FACTOR, _HARD_FETCH_CEILING)

        spl = _build_spl(source.query, fetch_cap)
        raw_results = list(connection.search(spl, fetch_cap))

        if strategy == "recent":
            chosen = raw_results[:limit]
        elif strategy == "random":
            chosen = reservoir_sample(raw_results, limit, seed)
        elif strategy == "stratified":
            grouped: dict[str, list[dict[str, Any]]] = {}
            for item in raw_results:
                grouped.setdefault(str(item.get("source", "unknown")), []).append(item)
            chosen = stratified_sample_by_group({k: iter(v) for k, v in grouped.items()}, limit, seed)
        else:  # pragma: no cover - config validation restricts sample_strategy
            raise AdapterError(f"source '{source.name}': unknown sample_strategy '{strategy}'")

        records = [
            RawRecord(
                source_name=source.name,
                index=i,
                origin_path=str(item.get("source", spl)),
                origin_line_no=i,
                raw_text=str(item.get("_raw", "")),
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
            files_read=[spl],
        )
        return iter(records), metadata
