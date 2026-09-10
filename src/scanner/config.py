"""Config loading and validation (YAML, per SPEC.md section 7)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

SampleStrategy = Literal["random", "recent", "stratified"]
AdapterKind = Literal["file", "splunk", "sentinel", "elastic"]
EventClass = Literal["activity", "state", "mixed"]
"""What kind of events a source records, declared by its owner (C8):
- "activity": someone/something performed an action (auth, file ops,
  config changes) -- an actor/initiator field is expected, C8 is scored.
- "state": something happened to a thing (down, degraded, threshold
  crossed) -- there is no actor by definition, C8 is NOT_ASSESSED.
- "mixed": both interleaved -- C8 is scored but FAIL is softened to WARN,
  since partial actor absence is expected.
Undeclared (None) means C8 runs advisory-only: it reports what it found
but stays NOT_ASSESSED, so nothing false-fails out of the box. A missing
actor field is ambiguous between "incomplete log" and "inapplicable
concept" (a node-down event has no actor), and only the source owner
knows which kind of source this is -- that's why this is declared, never
inferred from the data."""


class InventoryConfig(BaseModel):
    path: str | None = None
    match_fields: list[str] = Field(default_factory=list)


# Built-in field_hints defaults, so a config that omits field_hints entirely
# still gets reasonable C4/C5/C7/C8 behavior out of the box -- these are the
# ONLY defaults FieldHints itself carries; C1's event-type candidates are
# intentionally not field_hints-driven. An explicit `field_hints: {origin: []}`
# (etc.) in a real YAML config still overrides these -- they're a starting
# point, not a floor.
#
# Sourced from the field-naming conventions of the major normalization
# standards and log ecosystems, so a source using any of them is recognized
# without per-org tuning: Elastic Common Schema (ECS), Splunk's Common
# Information Model (CIM), Microsoft Sentinel's ASIM, OCSF, ArcSight CEF,
# AWS CloudTrail, Windows Security/Sysmon events, and Linux syslog/auditd.
# Matching is an exact, case-sensitive field-name lookup (plain dict access
# against each sampled record's parsed keys) -- that's why PascalCase
# variants (Windows/ASIM) are listed alongside snake_case/lowercase ones
# (ECS/CIM/CEF) rather than relying on one casing to cover every ecosystem.
# Generic, most-common names come first in each list since ties in presence
# rate are broken by list order.
DEFAULT_ORIGIN_FIELD_CANDIDATES = [
    # generic
    "host",
    "hostname",
    "host_name",
    "device",
    "device_name",
    "computer",
    "reporting_device",
    "source_host",
    # Splunk CIM / CEF
    "src",
    "src_host",
    "src_ip",
    "src_nt_host",
    "srcip",
    "shost",
    "dvc",
    "dvc_host",
    "dvchost",
    # ECS
    "agent.hostname",
    "observer.hostname",
    # Sentinel ASIM
    "Dvc",
    "DvcHostname",
    "SrcHostname",
    # Windows Security / Sysmon
    "Computer",
    "WorkstationName",
    # Linux syslog/auth (SSH etc. -- the connecting/remote host)
    "rhost",
    # AWS CloudTrail (the caller's IP)
    "sourceIPAddress",
    # General enterprise/business data -- for a non-log dataset (CRM export,
    # HR file, financial ledger) origin attribution means who created or is
    # accountable for the record, not which device reported it. These aren't
    # dead weight even though no security log will ever match them, since
    # C4/C7 reuse the same origin resolution as C2's clock-skew grouping.
    "created_by",
    "created_by_id",
    "author",
    "author_id",
    "owner",
    "owner_id",
    "record_owner",
    "data_owner",
    "data_steward",
    # CRM / sales systems (Salesforce, HubSpot, Dynamics)
    "account_owner",
    "opportunity_owner",
    "sales_rep",
    "sales_rep_id",
    # HR / financial systems
    "submitted_by",
    "processed_by",
    "entered_by",
    "hr_admin",
    # Generic actor/system identifiers
    "user_id",
    "employee_id",
    "actor_id",
    "source_system",
    # Last-touch -- weaker signal than created_by (names who last edited a
    # record, not who originated it), so listed last within this group.
    "modified_by",
    "updated_by",
    "last_modified_by",
]
DEFAULT_AFFECTED_FIELD_CANDIDATES = [
    # generic
    "dst",
    "dest",
    "destination",
    "target",
    "subject",
    "user",
    "resource",
    # Splunk CIM / CEF
    "dest_ip",
    "dest_nt_host",
    "dest_user",
    "dstip",
    "dhost",
    "duser",
    # ECS
    "destination.ip",
    "destination.hostname",
    "related.hosts",
    # Sentinel ASIM
    "Dst",
    "DstHostname",
    "DstIpAddr",
    "DstUsername",
    "TargetHostname",
    "TargetUserName",
    "TargetDomainName",
    # Windows Sysmon (network connection events)
    "DestinationIp",
    "DestinationHostname",
    # OCSF
    "dst_endpoint",
]
DEFAULT_OUTCOME_FIELD_CANDIDATES = [
    # generic
    "action",
    "result",
    "status",
    "disposition",
    "outcome",
    "state",
    # CEF
    "act",
    # Sentinel ASIM
    "EventResult",
    "DvcAction",
    # ECS
    "event.outcome",
    "event.action",
    # OCSF
    "status_id",
    "disposition_id",
    # AWS CloudTrail (presence/value indicates failure)
    "errorCode",
]
DEFAULT_ACTOR_FIELD_CANDIDATES = [
    # generic -- the account/identity that performed the action. Deliberately
    # distinct from origin ("who reported it") and affected ("who it happened
    # to"): reporter != actor != target, and C8 exists to keep them apart.
    "user",
    "username",
    "user_name",
    "actor",
    "account",
    "initiated_by",
    "performed_by",
    # Splunk CIM / CEF (suser = source user, sproc = source process)
    "src_user",
    "src_user_id",
    "suser",
    "sproc",
    # ECS
    "user.name",
    "source.user.name",
    "process.name",
    # Sentinel ASIM
    "ActorUsername",
    "SrcUsername",
    # Windows Security -- the *acting* account; TargetUserName is the
    # acted-upon account and belongs in the affected list, not here.
    "SubjectUserName",
    # AWS CloudTrail
    "userIdentity.userName",
    "userIdentity.arn",
    "userName",
    # Linux auditd
    "acct",
    "auid",
    # process-as-actor (endpoint/EDR telemetry)
    "process_name",
    "ProcessName",
]
DEFAULT_CORRELATION_FIELD_CANDIDATES = [
    # generic
    "session_id",
    "transaction_id",
    "trace_id",
    "flow_id",
    "request_id",
    "correlation_id",
    "span_id",
    # Sentinel ASIM
    "SessionId",
    "NetworkSessionId",
    "EventUid",
    # AWS CloudTrail
    "requestID",
    "requestId",
    # Windows/ETW
    "ActivityId",
    "ProcessGuid",
    # CEF
    "externalId",
]


class FieldHints(BaseModel):
    origin: list[str] = Field(default_factory=lambda: list(DEFAULT_ORIGIN_FIELD_CANDIDATES))
    affected: list[str] = Field(default_factory=lambda: list(DEFAULT_AFFECTED_FIELD_CANDIDATES))
    outcome: list[str] = Field(default_factory=lambda: list(DEFAULT_OUTCOME_FIELD_CANDIDATES))
    correlation: list[str] = Field(default_factory=lambda: list(DEFAULT_CORRELATION_FIELD_CANDIDATES))
    actor: list[str] = Field(default_factory=lambda: list(DEFAULT_ACTOR_FIELD_CANDIDATES))


class DefaultsConfig(BaseModel):
    sample_size: int = Field(default=10000, gt=0)
    sample_strategy: SampleStrategy = "random"
    seed: int = 42


class SplunkConnectionConfig(BaseModel):
    """Connection details for every `adapter: splunk` source in this config.

    Never a credential itself -- `token_env_var` names an environment
    variable the token is read from at scan time (SPEC.md sec 9.4). A
    literal token here would be rejected the same way any other field
    would be, but there is deliberately no `token` field to put one in.
    """

    host: str
    port: int = 8089
    scheme: Literal["https", "http"] = "https"
    token_env_var: str = "SPLUNK_TOKEN"
    verify_ssl: bool = True


class SentinelConnectionConfig(BaseModel):
    """Connection details for every `adapter: sentinel` source in this config.

    Auth is Azure AD client-credentials (service principal), the standard
    read-only-capable pattern for querying a Log Analytics workspace.
    `client_secret_env_var` names an environment variable, same "never a
    credential in config" rule as Splunk's `token_env_var`.
    """

    workspace_id: str
    tenant_id: str
    client_id: str
    client_secret_env_var: str = "SENTINEL_CLIENT_SECRET"


class ElasticConnectionConfig(BaseModel):
    """Connection details for every `adapter: elastic` source in this config.

    Auth is an API key (`api_key_env_var` names the environment variable),
    Elastic/OpenSearch's recommended credential type for a scoped,
    revocable, read-only-capable identity -- deliberately not basic auth.
    """

    url: str
    api_key_env_var: str = "ELASTIC_API_KEY"
    verify_ssl: bool = True


class SourceConfig(BaseModel):
    name: str
    adapter: AdapterKind
    path: str | None = None
    query: str | None = None
    index: str | None = None
    schema_: str | None = Field(default=None, alias="schema")
    event_class: EventClass | None = None
    """See EventClass. None (undeclared) keeps C8 advisory-only."""
    authoritative_over: list[str] = Field(default_factory=list)
    owner: str
    sample_size: int | None = None
    sample_strategy: SampleStrategy | None = None

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _adapter_requires_its_location(self) -> SourceConfig:
        if self.adapter == "file" and not self.path:
            raise ValueError(f"source '{self.name}': adapter 'file' requires a 'path'")
        if self.adapter in ("splunk", "sentinel") and not self.query:
            raise ValueError(f"source '{self.name}': adapter '{self.adapter}' requires a 'query'")
        if self.adapter == "elastic":
            if not self.query:
                raise ValueError(f"source '{self.name}': adapter 'elastic' requires a 'query'")
            if not self.index:
                raise ValueError(f"source '{self.name}': adapter 'elastic' requires an 'index'")
        return self


class PrecedenceRule(BaseModel):
    entities: list[str]
    authoritative: str
    rationale: str

    @model_validator(mode="after")
    def _authoritative_must_be_in_entities(self) -> PrecedenceRule:
        if self.authoritative not in self.entities:
            raise ValueError(
                f"precedence rule: authoritative source '{self.authoritative}' "
                f"must be one of the listed entities {self.entities}"
            )
        return self


class ScannerConfig(BaseModel):
    version: str
    ruleset_version: str
    inventory: InventoryConfig | None = None
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    field_hints: FieldHints = Field(default_factory=FieldHints)
    sources: list[SourceConfig]
    precedence_rules: list[PrecedenceRule] = Field(default_factory=list)
    splunk: SplunkConnectionConfig | None = None
    sentinel: SentinelConnectionConfig | None = None
    elastic: ElasticConnectionConfig | None = None

    @model_validator(mode="after")
    def _source_names_unique(self) -> ScannerConfig:
        names = [s.name for s in self.sources]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate source names in config: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _remote_sources_require_connection_config(self) -> ScannerConfig:
        for adapter_kind, connection, block_name in (
            ("splunk", self.splunk, "splunk"),
            ("sentinel", self.sentinel, "sentinel"),
            ("elastic", self.elastic, "elastic"),
        ):
            matching = [s.name for s in self.sources if s.adapter == adapter_kind]
            if matching and connection is None:
                raise ValueError(
                    f"source(s) {matching} use adapter '{adapter_kind}' but no top-level "
                    f"'{block_name}:' connection block is configured"
                )
        return self

    @model_validator(mode="after")
    def _precedence_rules_reference_known_sources(self) -> ScannerConfig:
        known = {s.name for s in self.sources}
        for rule in self.precedence_rules:
            unknown = [e for e in rule.entities if e not in known]
            if unknown:
                raise ValueError(
                    f"precedence rule references unknown source(s) {unknown}; "
                    f"known sources are {sorted(known)}"
                )
        return self

    def effective_sample_size(self, source: SourceConfig) -> int:
        return source.sample_size if source.sample_size is not None else self.defaults.sample_size

    def effective_sample_strategy(self, source: SourceConfig) -> SampleStrategy:
        return (
            source.sample_strategy
            if source.sample_strategy is not None
            else self.defaults.sample_strategy
        )


class ConfigError(Exception):
    """Raised for config file problems that are not pydantic validation errors."""


def load_config(config_path: str | Path) -> ScannerConfig:
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file is not valid YAML: {exc}") from exc
    if raw is None:
        raise ConfigError(f"config file is empty: {path}")
    if not isinstance(raw, dict):
        raise ConfigError(f"config file must be a YAML mapping at the top level: {path}")
    return ScannerConfig.model_validate(raw)
