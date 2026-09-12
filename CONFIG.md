# Configuration reference

YAML is the primary interface. Every field below is validated by
`scanner validate-config --config <path>` before a scan ever runs, and
the full schema lives in `src/scanner/config.py` if you want the exact
pydantic model behind this document.

See [examples/demo.yaml](examples/demo.yaml) for a complete, working
example against the bundled samples.

**Starting without a config:** `scanner quickscan <file-or-glob>` runs
the same scan with defaults for everything below, and `--emit-config
scanner.yaml` writes the equivalent config — only what differs from the
defaults — so a first look becomes a durable, reviewed one. Every
option in this document is then a change to that file.

## Top-level fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `version` | string | yes | Config schema version (informational; recorded in run metadata). |
| `ruleset_version` | string | yes | Your own version label for this ruleset/config generation (informational; recorded in run metadata and the run journal). |
| `defaults` | [DefaultsConfig](#defaults) | no | Default sampling behavior, overridable per source. |
| `field_hints` | [FieldHints](#field_hints) | no | Candidate field names checks use to locate origin/affected/outcome/correlation/actor fields. |
| `sources` | list of [SourceConfig](#sources) | yes | The sources to scan. Names must be unique. |
| `precedence_rules` | list of [PrecedenceRule](#precedence_rules) | no | Declares which source wins when two sources describe the same entities (used by the missing-precedence-rule conflict check). |
| `splunk` | [SplunkConnectionConfig](#splunk) | conditionally | Connection details shared by every `adapter: splunk` source. **Required** if any source uses `adapter: splunk`; the config is rejected at validation time otherwise. |
| `sentinel` | [SentinelConnectionConfig](#sentinel) | conditionally | Connection details shared by every `adapter: sentinel` source. **Required** if any source uses `adapter: sentinel`. |
| `elastic` | [ElasticConnectionConfig](#elastic) | conditionally | Connection details shared by every `adapter: elastic` source. **Required** if any source uses `adapter: elastic`. |

## `defaults`

```yaml
defaults:
  sample_size: 10000
  sample_strategy: random   # random | recent | stratified
  seed: 42
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `sample_size` | int (>0) | `10000` | Hard ceiling on records fetched per source. Overridable per source. |
| `sample_strategy` | `random` \| `recent` \| `stratified` | `random` | How the sample is drawn. `stratified` splits the quota evenly across a source's underlying files (file adapter), its `source` metadata field (Splunk), `Computer`/`_ResourceId` (Sentinel), or its concrete backing index (Elastic, via `_index`). `random` is a true seeded server-side sample for Elastic; Splunk and Sentinel approximate it by oversampling then locally re-sampling (see each adapter's docstring). Overridable per source. |
| `seed` | int | `42` | Seeds every sampling strategy. Same input + same seed = byte-identical output, including for `random`. Always recorded in the report's sample metadata. |

## `field_hints`

```yaml
field_hints:
  origin: [host, device_name, serial, reporting_device]
  affected: [dest, dst, target, subject, user, resource]
  outcome: [action, result, status, disposition]
  correlation: [session_id, trace_id, flow_id, transaction_id]
  actor: [user, src_user, SubjectUserName]
```

Ordered candidate field names. C5's outcome field and C7's correlation
key each pick whichever single candidate is actually present with the
highest presence rate in the sample. Origin/affected-entity resolution
works slightly differently: a record counts as having an identifier if
*any* of the candidate fields is present in it — not just whichever one
candidate happens to be present in the most records overall — since a
source can genuinely mix field names across records (e.g. some records
carrying `host`, others `src`) and each one still answers the question.
A single representative field name is still reported for display and
for other checks that need to group/compare by one field (C2's
clock-skew grouping, C4's same-field-as-origin distinguishability
check). Either way, hints don't force a field to be used — they just
tell each check where to look first.

**All five lists have built-in defaults** (below), so omitting
`field_hints` entirely still gives C4/C5/C7/C8 (and origin resolution
generally) something reasonable to look for on a fresh install, before
you've tuned anything for your own log field names. Specifying
`field_hints` in your config — even just one of the five lists —
**replaces** that list's default outright (it doesn't merge with it),
so include the names you still want alongside your own:

```yaml
field_hints:
  origin: [host, device_name, serial, reporting_device]
  affected: [dest, dst, target, subject, user, resource]
  outcome: [action, result, status, disposition]
  correlation: [session_id, trace_id, flow_id, transaction_id]
  actor: [user, src_user, SubjectUserName]
```

The built-in defaults are drawn from the field-naming conventions of
the major normalization standards and log ecosystems, so a source using
any of them is recognized without per-org tuning: Elastic Common Schema
(ECS), Splunk's Common Information Model (CIM), Microsoft Sentinel's
ASIM, OCSF, ArcSight CEF, AWS CloudTrail, Windows Security/Sysmon
events, and Linux syslog/auditd. Matching is **case-insensitive** (a
candidate like `host` also matches `Host`/`HOST`), which is why the
lists still bother listing both PascalCase variants (Windows/ASIM, e.g.
`DestinationIp`) and snake_case/lowercase ones (ECS/CIM/CEF, e.g.
`dest_ip`) even though casing alone no longer decides a match — some
ecosystems genuinely use different *words*, not just different casing,
for the same concept.

`origin` also includes general enterprise/business-data attribution
terms (`created_by`, `owner`, `data_steward`, `account_owner`, etc.),
not just log-oriented ones, since a non-log dataset's origin question
("who says so") means who created or is accountable for a record, not
which device reported it.

Dotted candidates such as `destination.ip` or `userIdentity.userName`
match **nested** documents too: the file and Elastic adapters flatten
nested objects to dotted-path keys before profiling, so an ECS document
that nests `destination: {ip: ...}` is seen as `destination.ip`. Lists
are kept whole (a multivalue field is one field), and nesting deeper
than 16 levels is left as an opaque value. If instead a whole record is
wrapped inside one key (a Splunk export's `result`), that's an envelope,
not a schema — see `record_root` under [`sources`](#sources).

| List | Built-in default |
| --- | --- |
| `origin` | `host`, `hostname`, `host_name`, `device`, `device_name`, `computer`, `reporting_device`, `source_host`, `src`, `src_host`, `src_ip`, `src_nt_host`, `srcip`, `shost`, `dvc`, `dvc_host`, `dvchost`, `agent.hostname`, `observer.hostname`, `Dvc`, `DvcHostname`, `SrcHostname`, `Computer`, `WorkstationName`, `rhost`, `sourceIPAddress`, `created_by`, `created_by_id`, `author`, `author_id`, `owner`, `owner_id`, `record_owner`, `data_owner`, `data_steward`, `account_owner`, `opportunity_owner`, `sales_rep`, `sales_rep_id`, `submitted_by`, `processed_by`, `entered_by`, `hr_admin`, `user_id`, `employee_id`, `actor_id`, `source_system`, `modified_by`, `updated_by`, `last_modified_by` |
| `affected` | `dst`, `dest`, `destination`, `target`, `subject`, `user`, `resource`, `dest_ip`, `dest_nt_host`, `dest_user`, `dstip`, `dhost`, `duser`, `destination.ip`, `destination.hostname`, `related.hosts`, `Dst`, `DstHostname`, `DstIpAddr`, `DstUsername`, `TargetHostname`, `TargetUserName`, `TargetDomainName`, `DestinationIp`, `DestinationHostname`, `dst_endpoint` |
| `outcome` | `action`, `result`, `status`, `disposition`, `outcome`, `state`, `act`, `EventResult`, `DvcAction`, `event.outcome`, `event.action`, `status_id`, `disposition_id`, `errorCode` |
| `correlation` | `session_id`, `transaction_id`, `trace_id`, `flow_id`, `request_id`, `correlation_id`, `span_id`, `SessionId`, `NetworkSessionId`, `EventUid`, `requestID`, `requestId`, `ActivityId`, `ProcessGuid`, `externalId` |
| `actor` | `user`, `username`, `user_name`, `actor`, `account`, `initiated_by`, `performed_by`, `src_user`, `src_user_id`, `suser`, `sproc`, `user.name`, `source.user.name`, `process.name`, `ActorUsername`, `SrcUsername`, `SubjectUserName`, `userIdentity.userName`, `userIdentity.arn`, `userName`, `acct`, `auid`, `process_name`, `ProcessName` |

(C1's event-type candidates are intentionally *not*
`field_hints`-driven.)

**`origin` and `affected` must name different fields for a source where
that distinction matters** — see C4's design note in the README. If the
same field is the only candidate for both, C4 will correctly report the
source as unable to distinguish what reported an event from what it
happened to.

## `sources`

```yaml
sources:
  - name: palo_alto_threat
    adapter: splunk
    query: 'index=network sourcetype=pan:threat'
    schema: cim:Network_Traffic
    authoritative_over: []
    owner: "network-security@example.com"

  - name: solarwinds_syslog
    adapter: file
    path: ./samples/solarwinds/*.log
    owner: "network-ops@example.com"

  - name: sentinel_signin_logs
    adapter: sentinel
    query: 'SigninLogs | where ResultType != 0'
    owner: "identity-team@example.com"

  - name: elastic_firewall_logs
    adapter: elastic
    query: 'event.action:block'
    index: logs-firewall-*
    owner: "network-ops@example.com"
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | Unique within the config. Used as the key everywhere in output (report sections, journal entries, conflict findings). |
| `adapter` | `file` \| `splunk` \| `sentinel` \| `elastic` | yes | Which adapter fetches this source. |
| `path` | string | if `adapter: file` | Glob pattern, e.g. `./samples/clean_firewall/*.jsonl`. Format is decided per file by extension: `.csv`/`.tsv` are parsed with the header row as field names (a quoted cell may span lines; an empty cell means the field is *absent* from that row). Everything else is one record per line — JSON objects (nested objects flattened to dotted keys like `destination.ip`), then logfmt `key=value`, then a raw-text fallback. Plain syslog headers are not parsed. |
| `query` | string | if `adapter: splunk`, `sentinel`, or `elastic` | The query, in that backend's own language: SPL for Splunk, KQL for Sentinel, a Lucene `query_string` for Elastic. A bounding clause (`\| head N` / `\| take N` / `size`) is appended automatically; you don't need to add one. |
| `index` | string | if `adapter: elastic` | Index or index pattern to search, e.g. `logs-firewall-*`. Not used by other adapters. |
| `schema` | string | no | Declared schema name (e.g. a CIM data model). Informational; not currently enforced by any check. (YAML key is `schema`; the Python field is `schema_` since `schema` collides with pydantic internals — either key works when loading YAML.) |
| `event_class` | `activity` \| `state` \| `mixed` | no | What kind of events this source records, for C8 (actor/initiator). `activity` (auth, file ops, config changes — an actor is expected): C8 is scored. `state` (down, degraded, threshold crossed — no actor exists by definition): C8 reports NOT_ASSESSED. `mixed`: C8 is scored but FAIL softens to WARN. Undeclared: C8 runs advisory-only — it reports what it found but never scores or fails. Declared, never inferred, because a missing actor field is ambiguous between "incomplete log" and "not applicable," and only the source owner knows which. |
| `record_root` | string | no (file adapter only) | Envelope key to unwrap before profiling, for exports that wrap each event in transport metadata. Splunk's JSON export is the canonical case — every line is `{"preview": ..., "offset": ..., "result": {...the event...}}`, so `record_root: result` makes the event's own fields the record. Also `_source` for a raw Elastic export, `Event` for Windows XML-to-JSON. A record lacking the key is kept but flagged with a parse error, so a wrong root is visible. The scanner never unwraps on its own: when records *look* enveloped, the report says so and names the key, and this setting is how you act on it. |
| `authoritative_over` | list of string | no (default `[]`) | Other source names this source is authoritative over, for the missing-precedence-rule conflict check. |
| `owner` | string | yes | Email/identity that owns fixes for this source. Used to route recommendations and eligibility-gate failures. |
| `sample_size` | int | no | Overrides `defaults.sample_size` for this source only. |
| `sample_strategy` | `random` \| `recent` \| `stratified` | no | Overrides `defaults.sample_strategy` for this source only. |

## `precedence_rules`

```yaml
precedence_rules:
  - entities: [solarwinds_syslog, meraki_events]
    authoritative: meraki_events
    rationale: "Cloud controller reflects live device state; SolarWinds polls on an interval."
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `entities` | list of string | yes | Source names covered by this rule. |
| `authoritative` | string | yes | Which of `entities` wins on conflict. Must be one of `entities`. |
| `rationale` | string | yes | Human-readable justification, surfaced in the conflicts section. |

If two sources' *sampled* origin values overlap (the same device shows
up in both) and no `precedence_rules` entry (or `authoritative_over`
declaration) covers both, the estate-level Conflicts section flags it —
see `conflicting_pair_solarwinds` / `conflicting_pair_meraki` in
`examples/demo.yaml` for a worked example.

## `splunk`

```yaml
splunk:
  host: "splunk.example.com"
  port: 8089
  scheme: https
  auth: token                 # token (default, preferred) | session
  token_env_var: SPLUNK_TOKEN
  verify_ssl: true
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | — (required) | Splunk management host. |
| `port` | int | `8089` | Splunk management port. |
| `scheme` | `https` \| `http` | `https` | Connection scheme. |
| `auth` | `token` \| `session` | `token` | How to authenticate. `token` sends a JWT authentication token as a Bearer header. `session` logs in with a username and password and holds the resulting session key. See below for why `token` is the default. |
| `token_env_var` | string | `SPLUNK_TOKEN` | `auth: token` only. Name of the **environment variable** the token is read from at scan time. |
| `username_env_var` | string | `SPLUNK_USERNAME` | `auth: session` only. Environment variable holding the username. |
| `password_env_var` | string | `SPLUNK_PASSWORD` | `auth: session` only. Environment variable holding the password. |
| `verify_ssl` | bool | `true` | TLS certificate verification. |

There is deliberately no `token` or `password` field. Splunk credentials
must come from the environment (or a secrets manager that populates the
environment), never from a config file — see
[SECURITY.md](SECURITY.md#credential-handling).

**Token vs. session.** Prefer `token`: a leaked token is search access
until it expires or you revoke it from *Settings › Tokens*, and revoking
it doesn't touch the account. A leaked password is the whole account —
Splunk Web, password changes, everything that user can do — and rotating
it breaks whatever else uses it. `session` exists as an explicit
fallback for installs where token auth is broken (some Splunk builds
reject tokens they issued themselves). If you use it:

1. Create a **dedicated read-only user** for the scanner, with a role
   that has search on the target indexes and nothing else. Never `admin`
   and never a person's account — the capability check refuses any
   account with write-capable permissions before the first search, so
   `admin` would be rejected anyway, but don't rely on that to protect
   the password.
2. Set both variables in the shell for that session only, e.g. in
   PowerShell `$env:SPLUNK_PASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText`,
   so the password never lands in a file or a shell history.

## `sentinel`

```yaml
sentinel:
  workspace_id: "00000000-0000-0000-0000-000000000000"
  tenant_id: "11111111-1111-1111-1111-111111111111"
  client_id: "22222222-2222-2222-2222-222222222222"
  client_secret_env_var: SENTINEL_CLIENT_SECRET
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `workspace_id` | string | — (required) | Log Analytics workspace ID to query. |
| `tenant_id` | string | — (required) | Azure AD tenant ID. |
| `client_id` | string | — (required) | Service principal (app registration) client ID. |
| `client_secret_env_var` | string | `SENTINEL_CLIENT_SECRET` | Name of the **environment variable** the service principal's client secret is read from at scan time. |

As with Splunk, there is deliberately no `client_secret` field. Requires
the `sentinel` optional extra: `pip install -e ".[sentinel]"`.

## `elastic`

```yaml
elastic:
  url: "https://elastic.example.com:9200"
  api_key_env_var: ELASTIC_API_KEY
  verify_ssl: true
```

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | string | — (required) | Elastic/OpenSearch cluster URL. |
| `api_key_env_var` | string | `ELASTIC_API_KEY` | Name of the **environment variable** the API key is read from at scan time. |
| `verify_ssl` | bool | `true` | TLS certificate verification. |

No `api_key` field, same reasoning as `token_env_var`/`client_secret_env_var`
above. Use a scoped, read-only API key — the adapter checks the key's
privileges before every scan and refuses to proceed if it has any
write/delete privilege on the target index (see
[SECURITY.md](SECURITY.md#read-only-guarantee)). Requires the `elastic`
optional extra: `pip install -e ".[elastic]"`.

## Notes

- `scanner validate-config --config <path>` runs every validation rule
  above without sampling or scanning anything — use it in CI before a
  config change reaches a real scan.
- Config is loaded once per `scan` invocation; there's no live-reload.
- The exact set of fields is enforced by pydantic — an unrecognized key,
  wrong type, or a source missing a required field for its adapter kind
  fails validation with a specific, per-field error message.
