# Log-type profiles

A profile describes one known log type: what identifies it, which of
its fields play which role, what kind of events it records, which
fields a correctly configured source carries, and what to do when they
are missing. With a profile, a finding stops being "no outcome field
found" and becomes "`pan:traffic` normally carries `action` in every
record; it's present in 0% — check the security policy's *Log at
Session End* setting."

Run `scanner profiles` to list the ones the scanner knows.

## The one rule: profiles add, they never overrule

The C1–C8 verdicts are exactly what they would be without a profile.
Specifically:

- **Role hints are prepended** to the generic candidate lists for that
  source. C5 looks at `Keywords` first for a Windows Security log, but
  still falls back to `action`, `result`, `status`, … as it always did.
  A stale profile can send a lookup to the wrong place first; it cannot
  hide a field.
- **`event_class` from a profile applies only if the source didn't
  declare one.** Your config wins.
- **Conformance is advisory.** Expected fields below their expected
  presence produce one `[ADVISORY] <source> / PROFILE` recommendation,
  with the vendor guidance attached. It never scores, never gates.

That is what makes a wrong or outdated profile a bounded problem rather
than a confident, wrong verdict.

## How a profile is chosen

1. `profile: <id>` on the source — that profile, no detection.
2. `profile: none` — no profile, generic checks only.
3. Otherwise, **auto-detection**: the scanner looks for a field whose
   value names the log type — `sourcetype` (Splunk), `Type` (Sentinel /
   Log Analytics), `event.dataset` / `data_stream.dataset` / `event.module`
   (Elastic), then `source_type`, `log_type`, `logtype` — present in at
   least half the sampled records. If one value accounts for at least
   90% of records and a profile matches it, that profile applies.

A source that mixes log types gets no profile and a report line saying
so, with the split:

> mixed log types in one source — sourcetype: WinEventLog:Security 34%;
> Perfmon:CPU Load 20%; … — no profile applied; split this source by
> sourcetype (one query or file per type) so each is scored against what
> it should carry

Nothing is guessed from a plurality. The report header always says what
happened ("auto-detected from sourcetype='…'", "declared in config",
"no sourcetype-like field found", "… has no profile").

## Writing one

Put `*.yaml` files in a directory and list it under `profile_dirs:` in
your config (or `scanner profiles --profile-dir <dir>` to check they
load). A file whose `id` matches a bundled profile replaces it — the
way to tune a bundled one is to copy it and edit.

```yaml
id: pan:traffic                          # unique; what `profile:` refers to
name: Palo Alto Networks firewall traffic log
vendor: Palo Alto Networks               # optional
match:
  sourcetype: ["pan:traffic", "pan_traffic"]   # glob patterns, case-insensitive
event_class: mixed                       # activity | state | mixed; optional
roles:                                   # each list is prepended to the generic candidates
  event_type: [log_subtype, type]
  timestamp: [_time, generated_time]
  origin: [dvc_name, dvc, host]
  affected: [dest_ip, dest]
  outcome: [action, session_end_reason]
  correlation: [session_id]
  actor: [src_user, user]
expected_fields:                         # what a correctly configured source carries
  - {name: dest_port, presence: 0.99}
  - {name: session_end_reason, presence: 0.50, note: session-end records only}
  - {name: src_user, aliases: [user], presence: 0.10, note: requires User-ID}
guidance: >                              # shown with the ADVISORY recommendation
  Check each security policy rule's "Log at Session End" setting ...
notes: >                                 # optional, for humans reading the file
  Sessions are activity, but src_user only exists with User-ID.
```

Field-by-field:

| Key | Meaning |
| --- | --- |
| `match.sourcetype` | Values of the sourcetype-like field that identify this type. Globs allowed (`Perfmon:*`). An exact match always beats a glob match, so a specific profile wins over a family one. |
| `event_class` | Applied when the source didn't declare its own. `state` marks C8 not-applicable (counters have no actor). |
| `roles.*` | Field names for each role, most specific first. Matching is case-insensitive; nested JSON is flattened to dotted names (`userIdentity.arn`). |
| `expected_fields[].presence` | Minimum presence rate (0–1) in a correctly configured source. Use `note` for fields that are legitimately conditional, so the recommendation says why they're allowed to be sparse. |
| `guidance` | Where the fix lives for *this* vendor: the logging profile, the audit policy, the add-on that does the field extraction. This is the sentence an engineer acts on. |

Keep `expected_fields` to what the vendor documents as always present
plus a few conditional ones with notes. The point is to catch a
misconfigured source, not to enumerate the schema.

## Bundled profiles

| id | Log type | event_class |
| --- | --- | --- |
| `pan:traffic` | Palo Alto Networks firewall traffic log | mixed |
| `windows:security` | Windows Security event log (classic and XML sourcetypes) | activity |
| `windows:eventlog` | Windows System / Application event logs | mixed |
| `windows:perfmon` | Windows performance counters (`Perfmon:*`) | state |
| `sentinel:signinlogs` | Microsoft Entra ID sign-in logs (Sentinel) | activity |
| `sentinel:securityevent` | Windows Security events in Sentinel's `SecurityEvent` table | activity |
| `aws:cloudtrail` | AWS CloudTrail | activity |
| `cisco:asa` | Cisco ASA firewall syslog | mixed |
| `linux:secure` | Linux authentication log (`/var/log/secure`, `auth.log`) | activity |

Field names follow the Splunk add-ons' (CIM) and Sentinel tables'
conventions, since that is where these sourcetypes come from. If a
bundled profile disagrees with what your add-on version emits, copy it
into your `profile_dirs` and fix the names there — that override is the
intended maintenance path, and a pull request with the corrected file is
welcome.
