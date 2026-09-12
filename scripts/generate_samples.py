#!/usr/bin/env python3
"""Generates the synthetic sample data bundled in ./samples (SPEC.md sec 13).

Deterministic (each generator seeds its own random.Random), so re-running
this script reproduces byte-identical output -- it's checked in for
maintainability, not run at install/scan time. These are synthetic
records only; nothing here is or resembles real captured log data.

Run from the repo root:  python scripts/generate_samples.py
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _naive(dt: datetime) -> str:
    return dt.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def _rand_ip(rng: random.Random, prefix: str) -> str:
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True))
            f.write("\n")


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write(line)
            f.write("\n")


# --- 1. clean_firewall: high completeness -----------------------------------


def gen_clean_firewall(n: int = 1000) -> list[dict]:
    rng = random.Random("clean_firewall")
    hosts = [f"fw{i:02d}" for i in range(1, 11)]
    interfaces = ["eth0/1", "eth0/2", "eth0/3", "eth0/4"]
    records = []
    for i in range(n):
        action = rng.choice(["allow", "block"])
        # Batched tick (i // len(hosts)), not i: every host reports at the
        # exact same set of ticks, just interleaved -- so every origin's
        # median timestamp is identical (true zero cross-origin skew), not
        # merely small. A plain round-robin at a 1-second cadence still
        # leaves a small deterministic per-origin phase offset (see the
        # other generators below, where that residual is harmless).
        event_time = BASE_TIME + timedelta(seconds=i // len(hosts))
        records.append(
            {
                "timestamp": _iso(event_time),
                "ingest_time": _iso(event_time + timedelta(seconds=2)),
                "host": hosts[i % len(hosts)],
                "interface": rng.choice(interfaces),
                "action": action,
                "src": _rand_ip(rng, "10.1"),
                "dst": _rand_ip(rng, "10.2"),
                "result": "blocked" if action == "block" else "allowed",
                "session_id": f"sess-{i:06d}",
                "severity": rng.choice(["low", "medium", "high"]),
            }
        )
    return records


# --- 2. broken_syslog: low on both -----------------------------------------


def gen_broken_syslog(n: int = 1000) -> list[str]:
    rng = random.Random("broken_syslog")
    hosts = [f"sys{i:02d}" for i in range(1, 6)]
    free_text_messages = [
        "unexpected reboot detected, investigating",
        "disk usage warning threshold crossed",
        "service restarted after crash",
        "unknown error code encountered during startup",
        "watchdog timer expired, resetting subsystem",
    ]
    lines: list[str] = []
    for i in range(n):
        fmt = i % 3
        has_host = rng.random() >= 0.65  # ~65% missing device identifiers
        if fmt == 0:
            # Sparse JSON, timestamp field named differently, host often absent.
            rec: dict = {"ts": _iso(BASE_TIME + timedelta(seconds=i)), "msg": rng.choice(free_text_messages)}
            if has_host:
                rec["host"] = rng.choice(hosts)
            lines.append(json.dumps(rec, sort_keys=True))
        elif fmt == 1:
            # logfmt, no timestamp field at all.
            parts = [f'msg="{rng.choice(free_text_messages)}"']
            if has_host:
                parts.insert(0, f"host={rng.choice(hosts)}")
            lines.append(" ".join(parts))
        else:
            # Pure free text, no structure, no host.
            lines.append(rng.choice(free_text_messages).capitalize())
    return lines


# --- 3. ambiguous_nodedown: high completeness, well attributed to origin ---


def gen_ambiguous_nodedown(n: int = 1000) -> list[dict]:
    rng = random.Random("ambiguous_nodedown")
    pollers = [f"poller{i:02d}" for i in range(1, 4)]
    nodes = [f"node{i:03d}" for i in range(1, 51)]
    records = []
    for i in range(n):
        records.append(
            {
                "timestamp": _iso(BASE_TIME + timedelta(seconds=i * 3)),
                "reporting_device": pollers[i % len(pollers)],  # round-robin: see gen_clean_firewall
                "target": rng.choice(nodes),
                "interface": "mgmt0",
                "action": "Node Down",
            }
        )
    return records


# --- 4. pii_proxy_logs: high completeness despite uninventoried proxy hosts -


def gen_pii_proxy_logs(n: int = 1000) -> list[dict]:
    rng = random.Random("pii_proxy_logs")
    proxy_hosts = [f"proxy{i:02d}" for i in range(1, 4)]
    users = ["alice.chen", "bmartin", "carol.diaz", "dwatson", "efong", "grace.lee", "hpatel"]
    domains = [
        "mail.example.com",
        "news.example.net",
        "banking.example.org",
        "socialhub.example.com",
        "streaming.example.tv",
    ]
    records = []
    for i in range(n):
        user = rng.choice(users)
        action = rng.choice(["allow", "block"])
        records.append(
            {
                "timestamp": _iso(BASE_TIME + timedelta(seconds=i * 2)),
                "proxy_host": proxy_hosts[i % len(proxy_hosts)],  # round-robin: see gen_clean_firewall
                "user": user,
                "email": f"{user}@example.com",
                "url": f"https://{rng.choice(domains)}/path/{rng.randint(1, 9999)}",
                "action": action,
                "result": "blocked" if action == "block" else "allowed",
                "bytes_sent": rng.randint(200, 50000),
                "session_id": f"proxysess-{i:06d}",
            }
        )
    return records


# --- 5. conflicting_pair: two sources, same devices, contradictory state, --
# --- no precedence rule -- demonstrates missing_precedence_rule ------------


def gen_conflicting_pair(n: int = 500) -> tuple[list[dict], list[dict]]:
    switches = [f"sw{i:02d}" for i in range(1, 11)]

    solarwinds = []
    for i in range(n):
        solarwinds.append(
            {
                "timestamp": _iso(BASE_TIME + timedelta(seconds=i * 5)),
                "host": switches[i % len(switches)],  # round-robin: see gen_clean_firewall
                "action": "Node Down",
                "status": "down",
                "poll_interval_sec": 30,
            }
        )

    meraki = []
    for i in range(n):
        meraki.append(
            {
                "timestamp": _iso(BASE_TIME + timedelta(seconds=i * 5 + 2)),
                "host": switches[i % len(switches)],  # round-robin: see gen_clean_firewall
                "eventType": "device_status",
                "status": "online",
                "uplink": "wan1",
            }
        )
    return solarwinds, meraki


# --- 6. origin_only_logs: well attributed to origin, fails C4. Flagship ----
# --- completeness/eligibility divergence sample -----------------------------


def gen_origin_only_logs(n: int = 1000) -> list[dict]:
    hosts = [f"origin{i:02d}" for i in range(1, 21)]
    records = []
    for i in range(n):
        records.append(
            {
                "timestamp": _iso(BASE_TIME + timedelta(seconds=i)),
                "host": hosts[i % len(hosts)],  # round-robin: see gen_clean_firewall
            }
        )
    return records


# --- 7. skewed_clocks: passes most checks, fails C2 -------------------------


def gen_skewed_clocks(n: int = 1000) -> list[dict]:
    rng = random.Random("skewed_clocks")
    origins = {
        "dc1-poller": timedelta(seconds=0),
        "dc2-poller": timedelta(seconds=35),
        "dc3-poller": timedelta(seconds=-40),
    }
    actions = ["heartbeat", "poll_success", "config_backup_completed"]
    origin_names = list(origins)
    records = []
    for i in range(n):
        origin = origin_names[i % len(origin_names)]  # round-robin: see gen_clean_firewall
        event_time = BASE_TIME + timedelta(seconds=i) + origins[origin]
        records.append(
            {
                # Naive, no timezone -- this alone fails C2 (sec 5.8 sub-check 2).
                "timestamp": _naive(event_time),
                "host": origin,
                "target": f"device{rng.randint(1, 30):02d}",
                "action": rng.choice(actions),
                "result": "success",
                "session_id": f"skew-{i:06d}",
            }
        )
    return records


def main() -> None:
    write_jsonl(SAMPLES / "clean_firewall" / "firewall.jsonl", gen_clean_firewall())
    write_lines(SAMPLES / "broken_syslog" / "syslog.log", gen_broken_syslog())
    write_jsonl(SAMPLES / "ambiguous_nodedown" / "nodedown.jsonl", gen_ambiguous_nodedown())
    write_jsonl(SAMPLES / "pii_proxy_logs" / "proxy.jsonl", gen_pii_proxy_logs())

    solarwinds, meraki = gen_conflicting_pair()
    write_jsonl(SAMPLES / "conflicting_pair" / "solarwinds.jsonl", solarwinds)
    write_jsonl(SAMPLES / "conflicting_pair" / "meraki.jsonl", meraki)

    write_jsonl(SAMPLES / "origin_only_logs" / "origin_only.jsonl", gen_origin_only_logs())
    write_jsonl(SAMPLES / "skewed_clocks" / "skewed.jsonl", gen_skewed_clocks())
    print("Sample data generated under", SAMPLES)


if __name__ == "__main__":
    main()
