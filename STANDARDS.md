# Standards mapping

Most logging standards say the same thing in different words: every
audit record must say **what** happened, **when**, **where**, to **what**
or **whom**, by **whom**, and with what **outcome**. That list is the
C1–C8 completeness checks. This document maps each check to the
requirement it evidences, so a scan report can be filed as supporting
evidence in an assessment instead of being re-explained every time.

Read the last section before using this in an audit. The scanner
measures the *content* of a bounded sample of records. It does not
assess retention, integrity, protection, or review of logs — and every
framework below requires those too.

## Per-check mapping

| Check | NIST SP 800-53 Rev. 5, AU-3 *Content of Audit Records* | PCI DSS v4.0, Req. 10.2.2 *audit log elements* | OMB M-21-31 (federal event logging) | NIST SP 800-92 (log management) |
| --- | --- | --- | --- | --- |
| **C1** Event identification | "what type of event occurred" | "type of event" | Required logging data: event type | Log entries should carry an event type/ID — the basis for any analysis |
| **C2** Temporal quality | "when the event occurred"; AU-8 *Time Stamps* (mappable to UTC, sufficient granularity); clock synchronization (SC-45 / AU-8(1) in Rev. 4) | "date and time"; Req. 10.6 time-synchronization | Required logging data: accurate timestamp; EL1 *Time Standard* (consistent UTC timestamps) | Recommendation that all hosts synchronize clocks so events can be correlated |
| **C3** Event location | "where the event occurred" | "origination of event" (system component) | Required logging data: source | Log entries should identify the originating system/interface |
| **C4** Affected entity | "identity of any … objects/entities associated with the event" | "identity or name of affected data, system component, or resource" | Required logging data: destination / affected resource | — (implied by "sufficient detail to reconstruct events") |
| **C5** Outcome | "outcome of the event" | "success and failure indication" | Required logging data: outcome / status | Log entries should record success or failure |
| **C6** Causality *(advisory)* | — | — | — | Reason/cause detail aids reconstruction; not a stated requirement anywhere, which is why C6 never scores |
| **C7** Correlatability | Supports AU-6(3) *Correlate Audit Record Repositories* — needs a key to correlate on | Supports Req. 10.4 review/correlation | Supports EL2/EL3 correlation and orchestration goals | Correlation across sources is the stated purpose of centralized log management |
| **C8** Actor / initiator | "identity of any individuals, subjects … associated with the event" | "user identification" | Required logging data: user/application identity | Log entries should identify the user or process that initiated the action |
| **Origin resolution** *(used by C2, C4, C7)* | "source of the event" | "origination of event" | Required logging data: source system | Identify the reporting host |

Two rows deserve a note:

- **C4 and C8 are two requirements, not one.** AU-3 and PCI both list
  the *subject* (who acted) and the *object* (what was acted on) as
  separate elements. Sources that carry only "who reported it" satisfy
  neither, which is exactly the case C4's origin/target distinction
  exists to catch.
- **C2 evidences three requirements at once:** timestamp presence and
  parseability (the "when"), explicit UTC offset (AU-8's "mappable to
  UTC"; M-21-31's time standard), and cross-origin clock skew (the
  synchronization requirements). The C2 findings list which of the three
  a source fails, so the evidence stays specific.

## MITRE ATT&CK data sources

ATT&CK's data components describe *what telemetry a detection needs*.
The scanner doesn't map to techniques; it tells you whether a source's
records carry the fields that make a data component usable at all:

| Data component (data source) | Fields that make it usable | Checks that evidence them |
| --- | --- | --- |
| Logon Session Creation (Logon Session) | account, source host, target host, outcome, time | C8, origin, C4, C5, C2 |
| Process Creation (Process) | process name, parent, user, host, time | C8 (process-as-actor), C3, C2, C7 |
| Network Traffic Flow (Network Traffic) | source, destination, action/outcome, time, flow id | origin, C4, C5, C2, C7 |
| User Account Modification (User Account) | subject account, target account, outcome | C8, C4, C5 |

A source that FAILs C4 can still be used to *count* events but not to
*attribute* them to a target — which is the difference between a
detection that fires and one that can be acted on. That framing is
usually what a detection-engineering team needs from this report.

## Cross-cutting properties

| Property | Where it helps |
| --- | --- |
| Append-only run journal (timestamp, operator, config hash, verdicts) | Evidence of *continuous* assessment, not a one-off: AU-6 review cadence, PCI Req. 10.4 periodic review, M-21-31 EL2+ ongoing validation |
| `--fail-on regression` on a schedule | Turns the assessment into a control with an alert, rather than a document |
| Read-only by construction; bounded sampling; credentials from the environment only | Least-privilege access to log stores (AU-9 *Protection of Audit Information* is about the logs themselves; this is about not becoming a risk to them) |
| Byte-for-byte deterministic output | Two assessors get the same report from the same sample — reproducible evidence |

## What this tool does not cover

Do not present a scan report as evidence for any of the following. Each
framework requires them; the scanner deliberately measures none:

- **Retention and disposal** (AU-11; PCI Req. 10.5; M-21-31's 30-month
  requirement; 800-92 §4 planning). The scanner doesn't know how long
  logs are kept.
- **Integrity and protection** (AU-9; PCI Req. 10.3; M-21-31 log
  integrity). It reads a sample; it doesn't verify hashes, WORM storage,
  or access controls on the log store.
- **Review, alerting, and response** (AU-6; PCI Req. 10.4; M-21-31 EL2/EL3
  orchestration). It assesses whether records *could* support analysis,
  not whether anyone analyses them.
- **Coverage** — whether every system that should log actually does.
  The scanner inspects records that arrived; a silent host produces no
  records to inspect.
- **Data classification, ownership, and usage authorization.** These
  were the governance dimension of the parent project and are out of
  scope here by design.

## Using a report as evidence

1. Run the scan with journaling on (the default) and keep the journal
   with the reports; the journal's config hash ties each report to the
   exact configuration that produced it.
2. Cite the per-check findings, not the score: "C2: explicit timezone
   present in 100% of 10,000 sampled timestamps" is evidence; "5.5/6" is
   a summary.
3. State the sample: strategy, seed, requested and actual size are in
   every report's per-source `sample` block. An assessor will ask.
4. Pair it with the evidence this tool doesn't produce (retention,
   integrity, review) from wherever those controls actually live.
