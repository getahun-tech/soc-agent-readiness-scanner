# Event Log Completeness Scanner

Before a security or IT operations team lets a log source drive an
automated decision — an auto-remediation, an auto-suppression, a
compliance finding — someone has to answer: *does this data actually
carry enough information to act on safely?* Today that judgment is
tribal knowledge. This tool answers it repeatably, against a bounded,
read-only sample of each source, and produces a report with concrete
evidence behind every finding.

It scores every source against eight completeness checks (C1–C8; C6 is
advisory-only, and C8 is scored only when a source declares its
`event_class` — see below) and derives automation eligibility from a
small, explicit set of gates — never a threshold on the overall score.

## What this tool does not do

- It does not fix data quality problems, or modify/delete anything at
  any source. Every adapter is read-only by construction — there is no
  write method on the adapter interface to call in the first place.
- It does not do threat detection, alerting, or judge whether any given
  alert is a true positive. It only asks whether the *data* is fit to
  drive automation, not what the automation should do.
- It does not analyze full datasets. Every source is sampled, with a
  hard ceiling on records fetched, and the sampling strategy and seed
  are always recorded in the output.
- It does not stream or run in real time — batch sampling only.

See [SECURITY.md](SECURITY.md) for the full list of security
commitments and [§ roadmap](#roadmap--explicitly-deferred) for what's
intentionally not built yet.

## Quickstart

```bash
pip install -e .
scanner scan --config examples/demo.yaml --format markdown
```

This runs entirely offline against the synthetic sample data bundled in
`./samples/` — no network calls, no credentials, nothing outside this
repo. `--format json` (the default) or `--format html` work the same
way. Try `scanner validate-config --config examples/demo.yaml` first if
you just want to check the config parses.

## Example output

This is the `origin_only_logs` sample — a source that is well attributed
to its reporting device but never records who or what the event actually
happened to:

```
**Score:** 1.5/6 (25%) (C8 not assessed) (C6 excluded)

**Automation eligibility:** NOT ELIGIBLE
- C4 (affected entity identifiable): C4 is FAIL: no affected-entity
  identifier found: none of ['target', 'dst'] are present in the sample
  -- owner: network-ops@example.com

**Completeness (C1-C8)**

- C4 -- Affected entity: FAIL
  - no affected-entity identifier found: none of ['target', 'dst'] are
    present in the sample
  - Records are well attributed to their reporting device but the
    affected entity cannot be reliably identified (C4 FAIL). Automated
    action requires knowing what to act on, not only what reported it.
```

A remediation agent that only knows *what reported* an event, not *what
it happened to*, has nothing to act on — that's exactly the class of gap
this check exists to catch, and it catches it even when origin
attribution is flawless.

## The checks

**Completeness (C1–C8)** — does each record carry enough information to
be useful? (C6 excluded from scoring — advisory only)

| # | Name | What it checks |
| --- | --- | --- |
| C1 | Event identification | Is there a stable, enum-like event-type field? |
| C2 | Temporal quality | Timestamp present/parseable, explicit timezone, event-time vs. ingest-time distinguishable, clock skew across origins. |
| C3 | Event location | Is there an interface/host/site-level location field, ranked by granularity (finer beats coarser)? |
| C4 | Affected entity | Who/what did the event happen to — deliberately independent of origin resolution's "who reported it." The flagship completeness check. |
| C5 | Outcome | Is there a result/status/disposition field? |
| C6 | Causality *(advisory, not scored)* | Is there a reason/cause field? Can never FAIL or block eligibility — only PASS or NOT_ASSESSED. |
| C7 | Correlatability | Is there an explicit correlation key, or a composite key constructible from timestamp + an identifiable entity field? |
| C8 | Actor / initiator *(scored only when `event_class` is declared)* | Who *performed* the action — the third entity alongside "who reported it" (origin) and "who it happened to" (C4). |

A few checks carry design decisions worth knowing about beyond the table above:

- **C4 (affected entity)** is deliberately never a variant of origin
  resolution. Origin resolution asks who generated the record; C4 asks
  who it happened to. These are different entities, frequently confused,
  and conflating them is exactly the mistake that makes an automated
  remediation act on the wrong host.
- **C6 (causality)** is advisory only and can never fail a source or
  block eligibility — most telemetry records symptoms, not causes, and
  failing sources for lacking a causal field would fail nearly
  everything and train operators to ignore the report.
- **C8 (actor/initiator)** completes the entity triad: *reporter ≠
  actor ≠ target*. For identity-touching automations (disable an
  account, kill a process) the actor is often the decision-critical
  field — but a state event ("node down", "disk failed") has no actor
  by definition, and no amount of sampling can distinguish "incomplete
  log" from "inapplicable concept." So applicability is declared, never
  inferred: set `event_class: activity` (scored), `state` (not
  applicable), or `mixed` (scored, FAIL softened to WARN) per source.
  Undeclared sources get an advisory-only C8 that reports what it found
  without scoring — nothing false-fails out of the box. C8 never gates
  eligibility; the gate set stays frozen at C2/C4/C5.
- Every check evidences its findings with concrete counts, percentages,
  or examples. "Attribution could be improved" is not acceptable output
  from this tool; "67% of records could not be attributed to a known
  asset (6,712 of 10,000 sampled)" is the bar.

## Automation eligibility

Eligibility is **not** a threshold on the overall score. It's an
explicit, named list of gates: C2 PASS, C4 PASS, C5 PASS-or-WARN. A
source can score 5/6 (83%) overall and still be correctly ineligible if
the one miss is a gated check — `skewed_clocks` in the bundled demo
scores 5.0/6 but is ineligible on C2 alone, proving this is possible,
not just permitted.

## Configuration

See [CONFIG.md](CONFIG.md) for the full reference. `scanner
validate-config --config <path>` checks a config without running a scan.

## Limitations

- File inputs are read as JSON-per-line (nested objects flattened to
  dotted keys, with `record_root` to unwrap enveloped exports such as
  Splunk's), logfmt `key=value` lines, or CSV/TSV with a header row.
  There is no RFC3164/5424 syslog header parser yet — plain syslog lands
  in the raw-text fallback and will score as unstructured. Point the
  scanner at the SIEM (Splunk/Sentinel/Elastic adapters) for such
  sources instead, where the fields are already extracted.
- Sampling is bounded and, for `random`/`stratified` strategies against
  Splunk or Sentinel, an oversample-then-locally-sample approximation —
  not a query against the full matching result set, since neither has a
  version-independent server-side seeded sampling primitive to rely on.
  See each adapter's own docstring for the exact tradeoff. Elastic is
  the exception: its `random_score` query is itself seedable
  server-side, so its `random` strategy requests exactly the configured
  sample size directly, no oversampling needed.
- C2's cross-origin clock-skew detection is a statistical heuristic
  (per-origin median timestamp vs. the sample's pooled median). With
  few records per origin, sampling noise itself can look like skew;
  with enough records per origin it converges on genuine skew. It is
  not a substitute for NTP monitoring.
- The missing-precedence-rule conflict detection can only see overlap
  that shows up in the *sampled* records from both sources — it can
  miss real overlap that didn't happen to appear in either sample,
  though it never fabricates an overlap that isn't in the data.

## Roadmap / explicitly deferred

Not built in this version:

- LLM-assisted finding summarization (would be optional and off by
  default even if added, since it breaks air-gap capability)
- Streaming/real-time analysis (batch sampling only, by design)
- Auto-remediation of data quality issues (this tool diagnoses, it does
  not fix — see "What this tool does not do" above)
- A web UI

Adapters beyond file + Splunk were out of the original scope, but
Microsoft Sentinel and Elastic/OpenSearch adapters are included as a
follow-on addition, built the same way the Splunk adapter is: a narrow
connection protocol the adapter depends on, a real implementation that
lazily imports its client library as an optional extra
(`pip install -e ".[sentinel]"` / `".[elastic]"`), and tests that run
against a fake connection with no live server required. See
[CONFIG.md](CONFIG.md) for the `sentinel:`/`elastic:` connection blocks.
