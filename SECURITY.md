# Security commitments

This document states the guarantees this tool makes, as commitments to a
team reviewing it before deployment. Each one maps to a specific,
checkable property of the codebase — not just a policy statement — with
a pointer to where that's enforced and how to verify it yourself.

## Read-only guarantee

**Commitment:** this tool cannot write to, modify, or delete data at any
source it scans.

This is structural, not a runtime check we could accidentally bypass.
The adapter interface (`scanner.adapters.base.Adapter`) declares exactly
one method — `fetch_sample()` — and it returns data; it does not accept
data to persist. There is no write, delete, or update method anywhere on
the interface for a concrete adapter to implement, so a future adapter
literally cannot expose write behavior through this interface without
first changing the interface itself, which is a visible, reviewable
change to `base.py`.

For the Splunk and Elastic adapters specifically: before ever issuing a
search, each fetches the connected identity's capabilities/privileges
and refuses to proceed — raising, not silently downgrading — if any
write-capable one is present (Splunk: `delete_by_keyword`,
`edit_deployment_client`, `edit_forwarders`, and similar; Elastic:
`write`, `delete`, `delete_index`, `index` on the target index). Both
checks fail **closed**: if capabilities can't be read at all, the scan
also refuses to proceed rather than assuming the identity is safe.

The Sentinel adapter has no equivalent capability check, and doesn't
need one: it only ever calls Log Analytics' *query* API
(`LogsQueryClient.query_workspace`), which is structurally read-only —
there is no write or delete operation reachable through it at all,
regardless of what the service principal's broader Azure RBAC role
grants elsewhere in the tenant. `RealSentinelConnection` never
constructs a client for any other Azure Monitor/Sentinel API surface.

**Verify it yourself:** `src/scanner/adapters/base.py` (the interface),
`src/scanner/adapters/splunk.py::_assert_read_only` and
`src/scanner/adapters/elastic.py::_assert_read_only` (the capability
checks), `tests/test_splunk_adapter.py::test_write_capable_account_is_refused`,
`tests/test_elastic_adapter.py::test_write_capable_key_is_refused`.

## Bounded sampling

**Commitment:** this tool never fetches an entire index or dataset, and
every report states exactly how its sample was drawn.

Every adapter enforces a hard ceiling (`sample_size`, configurable, with
a sane default) on records fetched per source. The Splunk and Sentinel
adapters additionally never fetch more than a hard-coded ceiling (50,000
records) even when oversampling for the `random`/`stratified`
strategies, regardless of `sample_size` (Elastic doesn't need this --
its `random` strategy requests exactly `sample_size` directly, server-side
seeded, no oversampling). Every report's per-source
`sample` block records the strategy, seed, requested size, population
size, and actual size used — an unsampled or misrepresented sample is
visible in the output, not hidden.

**Verify it yourself:** `src/scanner/models.py::SampleMetadata` (what's
recorded), `src/scanner/adapters/splunk.py` (`_HARD_FETCH_CEILING`), any
report's per-source `sample` field.

## Credential handling

**Commitment:** no credential value ever appears in a config file, in
tool output, or in a log line — including error/debug output.

All three remote adapters follow the same pattern: a credential read
from an environment variable named by a config field
(`splunk.token_env_var` default `SPLUNK_TOKEN`,
`sentinel.client_secret_env_var` default `SENTINEL_CLIENT_SECRET`,
`elastic.api_key_env_var` default `ELASTIC_API_KEY`), and no field in
any of the three connection config schemas for the credential itself —
there is nothing to accidentally commit.

Each adapter's `fetch_sample()` wraps its call into the connection
factory in a try/except that scrubs the credential out of the exception
text and **breaks exception chaining** (`raise ... from None`) before
re-raising, specifically because a naive `raise ... from exc` would let
Python's default traceback printer surface the original exception's
text — including a credential a less-careful client library might have
embedded in its own error message — even though the top-level message
was clean. This is the authoritative scrub-and-break-chain layer for all
three adapters; the real connection classes' own internal error handling
(`RealSplunkConnection`, `RealSentinelConnection`,
`RealElasticConnection`) additionally avoids interpolating the
credential into their own messages, but don't rely on that alone — the
outer layer is what's actually load-bearing.

**Verify it yourself:** `src/scanner/adapters/{splunk,sentinel,elastic}.py`
(credential read + scrub in each `fetch_sample`),
`tests/test_splunk_adapter.py::test_token_value_never_appears_in_error_message`,
`tests/test_sentinel_adapter.py::test_secret_value_never_appears_in_error_message`,
`tests/test_elastic_adapter.py::test_api_key_value_never_appears_in_error_message`.

## Air-gap capability

**Commitment:** scanning file-based sources requires zero outbound
network calls.

The file adapter and every check operate purely on local data; nothing
in that path makes an HTTP request, resolves a DNS name, or otherwise
reaches outside the process. `examples/demo.yaml` scans entirely offline
against the bundled samples — that's the quickstart in
[README.md](README.md), not a special mode. No LLM-assisted feature
exists in this version; if one is added later, it must be optional and
disabled by default, since it would inherently require an outbound call
and break this guarantee for anyone who enables it.

**Verify it yourself:** run `scanner scan --config examples/demo.yaml`
with your network disabled.

## Audit trail

**Commitment:** every scan invocation is recorded in an append-only
journal, sufficient to answer "what ran, against what, producing what
verdict" after the fact.

Each `scan` invocation appends exactly one JSON line to the journal file
(default `./scanner_journal.jsonl`, configurable via `--journal`,
disableable by passing `--journal ""`) containing: timestamp, operator
identity, config file path and its SHA-256 hash, ruleset version,
sources scanned, sample sizes, and a per-source verdict summary
(eligibility and failed gates). The file is only ever opened in append
mode — a prior entry can't be rewritten or truncated by a later run
short of directly editing the file outside this tool.

**Verify it yourself:** `src/scanner/run_journal.py`, `tests/test_run_journal.py::test_append_journal_entry_is_append_only`.

## Determinism

**Commitment:** given the same input sample and ruleset version, output
is byte-for-byte identical across runs — including for the `random`
sampling strategy.

Every source of nondeterminism is seeded (`defaults.seed`, recorded in
the report's sample metadata) and every downstream aggregation step
(conflict detection, recommendation ordering) sorts or otherwise fixes
its output order rather than relying on incidental dict/set iteration
order. This is checked by comparing **raw output text** across two
runs — not just parsed-object equality, which can mask ordering
differences — for JSON, Markdown, and HTML output, plus a dedicated
check on the `random` strategy specifically.

**Verify it yourself:**
`tests/test_cli.py::test_scan_json_output_is_byte_identical_across_runs`
and its Markdown/HTML/random-strategy siblings.

## What's explicitly out of scope

This tool does not do detection, alerting, or auto-remediation, and
never judges whether an alert is a true positive — see
[README.md](README.md#what-this-tool-does-not-do). Scope discipline here
is itself a security property: a tool that only ever reads and reports
has a categorically smaller blast radius than one that also acts.

## Reporting a concern

If you find a gap between a commitment above and actual behavior, that's
exactly the kind of finding this document exists to make checkable —
please treat it as a bug against the specific guarantee it breaks.
