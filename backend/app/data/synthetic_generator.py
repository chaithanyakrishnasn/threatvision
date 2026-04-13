"""
Synthetic event generator for ThreatVision.

Four baked-in attack scenarios + benign baseline, all producing events
conforming to the unified event schema.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Optional

import structlog

logger = structlog.get_logger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

IST_OFFSET = timedelta(hours=5, minutes=30)

# 50 simulated employee workstations
EMPLOYEE_HOSTS = [
    f"DESKTOP-{a}{b}{c}{d}"
    for a, b, c, d in [
        ("A", "1", "B", "2"), ("C", "3", "D", "4"), ("E", "5", "F", "6"),
        ("G", "7", "H", "8"), ("I", "9", "J", "0"), ("K", "2", "L", "3"),
        ("M", "4", "N", "5"), ("O", "6", "P", "7"), ("Q", "8", "R", "9"),
        ("S", "1", "T", "2"), ("U", "3", "V", "4"), ("W", "5", "X", "6"),
        ("Y", "7", "Z", "8"), ("A", "9", "B", "1"), ("C", "2", "D", "3"),
        ("E", "4", "F", "5"), ("G", "6", "H", "7"), ("I", "8", "J", "9"),
        ("K", "1", "L", "2"), ("M", "3", "N", "4"), ("O", "5", "P", "6"),
        ("Q", "7", "R", "8"), ("S", "9", "T", "1"), ("U", "2", "V", "3"),
        ("W", "4", "X", "5"), ("Y", "6", "Z", "7"), ("A", "8", "B", "9"),
        ("C", "1", "D", "2"), ("E", "3", "F", "4"), ("G", "5", "H", "6"),
        ("I", "7", "J", "8"), ("K", "9", "L", "1"), ("M", "2", "N", "3"),
        ("O", "4", "P", "5"), ("Q", "6", "R", "7"), ("S", "8", "T", "9"),
        ("U", "1", "V", "2"), ("W", "3", "X", "4"), ("Y", "5", "Z", "6"),
        ("A", "7", "B", "8"), ("C", "9", "D", "1"), ("E", "2", "F", "3"),
        ("G", "4", "H", "5"), ("I", "6", "J", "7"), ("K", "8", "L", "9"),
        ("M", "1", "N", "2"), ("O", "3", "P", "4"), ("Q", "5", "R", "6"),
        ("S", "7", "T", "8"), ("U", "9", "V", "1"),
    ]
]
EMPLOYEE_USERS = [f"user{i:03d}" for i in range(1, 51)]
EMPLOYEE_IPS = [f"10.0.{r}.{h}" for r in range(3, 6) for h in range(10, 20)]

# Attack-scenario specific addresses
BRUTE_FORCE_SOURCES = [f"185.220.101.{i}" for i in range(1, 255)]
C2_HOST = "10.0.2.87"
C2_SERVER = "91.108.4.55"
LATERAL_TARGETS = ["10.0.1.100", "10.0.1.101", "10.0.1.102"]
AUTH_SERVER = "10.0.1.50"
ADMIN_WS = "10.0.1.25"
NAS = "10.0.50.100"

BENIGN_PORTS = [53, 80, 443, 25, 123, 8080, 8443, 21]
BENIGN_PROTOCOLS = ["DNS", "HTTP", "HTTPS", "SMTP", "NTP", "FTP"]
BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Microsoft-CryptoAPI/10.0",
    "Windows-Update-Agent/10.0",
]

# ── Schema factory ─────────────────────────────────────────────────────────────

def _base_event(
    *,
    layer: str,
    source_ip: str,
    dest_ip: str,
    source_port: int,
    dest_port: int,
    protocol: str,
    bytes_sent: int = 0,
    bytes_recv: int = 0,
    duration_ms: int = 0,
    process_name: Optional[str] = None,
    parent_process: Optional[str] = None,
    user: Optional[str] = None,
    http_method: Optional[str] = None,
    http_endpoint: Optional[str] = None,
    http_status: Optional[int] = None,
    user_agent: Optional[str] = None,
    geo_country: Optional[str] = None,
    flags: Optional[list[str]] = None,
    scenario: Optional[str] = None,
    severity: str = "LOW",
    confidence: float = 0.1,
    raw_payload: Optional[dict] = None,
    timestamp: Optional[datetime] = None,
) -> dict:
    ts = timestamp or datetime.now(timezone.utc)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "layer": layer,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "duration_ms": duration_ms,
        "process_name": process_name,
        "parent_process": parent_process,
        "user": user,
        "http_method": http_method,
        "http_endpoint": http_endpoint,
        "http_status": http_status,
        "user_agent": user_agent,
        "geo_country": geo_country,
        "flags": flags or [],
        "scenario": scenario,
        "severity": severity,
        "confidence": confidence,
        "raw_payload": raw_payload or {},
    }


# ── Scenario A: Brute Force + Credential Stuffing ────────────────────────────

def _brute_force_events(timestamp: datetime, window_index: int) -> list[dict]:
    """
    10-window cycle: 10-15 failed logins per window from rotating Tor exit IPs,
    then one success followed by a malicious PowerShell spawn.
    """
    events: list[dict] = []
    src_ip = random.choice(BRUTE_FORCE_SOURCES)
    fail_count = random.randint(10, 15)
    ts = timestamp

    for i in range(fail_count):
        events.append(_base_event(
            layer="network",
            source_ip=src_ip,
            dest_ip=AUTH_SERVER,
            source_port=random.randint(32000, 65000),
            dest_port=443,
            protocol="HTTPS",
            bytes_sent=random.randint(400, 900),
            bytes_recv=random.randint(200, 400),
            duration_ms=random.randint(80, 400),
            user=f"admin{random.randint(1, 5)}",
            http_method="POST",
            http_endpoint="/api/v1/auth/login",
            http_status=401,
            user_agent="python-requests/2.28.0",
            geo_country="Russia/Tor",
            flags=["tor_exit_node", "brute_force_pattern", "credential_stuffing"],
            scenario="brute_force",
            severity="CRITICAL",
            confidence=0.95,
            timestamp=ts + timedelta(milliseconds=i * 600),
            raw_payload={
                "attempt_number": i + 1,
                "window": window_index,
                "tor_exit": True,
                "fail_reason": "invalid_credentials",
            },
        ))

    # Successful auth at end of window
    success_ts = ts + timedelta(seconds=9, milliseconds=random.randint(0, 900))
    events.append(_base_event(
        layer="network",
        source_ip=src_ip,
        dest_ip=AUTH_SERVER,
        source_port=random.randint(32000, 65000),
        dest_port=443,
        protocol="HTTPS",
        bytes_sent=420,
        bytes_recv=1840,
        duration_ms=random.randint(120, 300),
        user="admin1",
        http_method="POST",
        http_endpoint="/api/v1/auth/login",
        http_status=200,
        user_agent="python-requests/2.28.0",
        geo_country="Russia/Tor",
        flags=["tor_exit_node", "brute_force_pattern", "credential_stuffing", "auth_success_after_brute"],
        scenario="brute_force",
        severity="CRITICAL",
        confidence=0.97,
        timestamp=success_ts,
        raw_payload={
            "attempt_number": fail_count + 1,
            "window": window_index,
            "tor_exit": True,
            "auth_result": "success",
            "session_token_issued": True,
        },
    ))

    # Endpoint layer: PowerShell spawn after successful auth
    encoded_cmd = "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA="
    events.append(_base_event(
        layer="endpoint",
        source_ip=AUTH_SERVER,
        dest_ip=AUTH_SERVER,
        source_port=0,
        dest_port=0,
        protocol="N/A",
        process_name="powershell.exe",
        parent_process="w3wp.exe",
        user="admin1",
        bytes_sent=0,
        bytes_recv=0,
        duration_ms=random.randint(200, 800),
        geo_country="Internal",
        flags=["tor_exit_node", "brute_force_pattern", "credential_stuffing", "encoded_powershell", "post_auth_execution"],
        scenario="brute_force",
        severity="CRITICAL",
        confidence=0.95,
        timestamp=success_ts + timedelta(milliseconds=random.randint(500, 2000)),
        raw_payload={
            "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}",
            "pid": random.randint(3000, 9000),
            "parent_pid": random.randint(1000, 3000),
            "integrity_level": "High",
        },
    ))

    return events


# ── Scenario B: C2 Beaconing ──────────────────────────────────────────────────

def _c2_beacon_event(timestamp: datetime, beacon_number: int) -> dict:
    """Single C2 beacon — 47-53 second jitter, 200-800 bytes outbound."""
    return _base_event(
        layer="network",
        source_ip=C2_HOST,
        dest_ip=C2_SERVER,
        source_port=random.randint(32768, 60000),
        dest_port=443,
        protocol="HTTPS",
        bytes_sent=random.randint(200, 800),
        bytes_recv=random.randint(50, 200),
        duration_ms=random.randint(150, 600),
        process_name="svchost.exe",
        parent_process="services.exe",
        user="SYSTEM",
        user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        geo_country="Netherlands",
        flags=["c2_beacon", "self_signed_cert", "periodic_connection"],
        scenario="c2_beacon",
        severity="HIGH",
        confidence=0.91,
        timestamp=timestamp,
        raw_payload={
            "beacon_number": beacon_number,
            "jitter_seconds": random.uniform(47, 53),
            "ssl_cert_self_signed": True,
            "ssl_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
            "dns_query": f"update{beacon_number % 10}.microsoftupdate-cdn.com",
            "bytes_ratio": round(random.uniform(200, 800) / random.uniform(50, 200), 2),
        },
    )


# ── Scenario C: False Positive (legitimate bulk transfer) ────────────────────

def _false_positive_event(timestamp: datetime, transfer_num: int) -> dict:
    """Bulk transfer that looks like exfil but is a scheduled backup."""
    size_mb = random.uniform(50, 500)
    bytes_sent = int(size_mb * 1024 * 1024)

    return _base_event(
        layer="network",
        source_ip=ADMIN_WS,
        dest_ip=NAS,
        source_port=random.randint(1024, 65000),
        dest_port=random.choice([445, 2049, 873]),  # SMB / NFS / rsync
        protocol=random.choice(["SMB", "NFS", "RSYNC"]),
        bytes_sent=bytes_sent,
        bytes_recv=random.randint(1000, 5000),
        duration_ms=int(size_mb * random.uniform(1000, 3000)),
        process_name="robocopy.exe",
        parent_process="taskeng.exe",
        user="backup_svc",
        geo_country="Internal",
        flags=["known_asset", "internal_destination", "business_hours", "backup_schedule"],
        scenario="false_positive",
        severity="LOW",
        confidence=0.15,
        timestamp=timestamp,
        raw_payload={
            "transfer_num": transfer_num,
            "size_mb": round(size_mb, 2),
            "scheduled_task": "DailyBackup",
            "destination_share": "\\\\10.0.50.100\\backup",
            "asset_tag": "ADMIN-WS-001",
            "change_journal": True,
        },
    )


# ── Scenario D: Lateral Movement ─────────────────────────────────────────────

_LATERAL_PAYLOADS = [
    # SMB
    {
        "technique": "SMB_LATERAL",
        "dest_port": 445,
        "protocol": "SMB",
        "process_name": "net.exe",
        "parent_process": "cmd.exe",
        "raw_payload": {
            "share": "ADMIN$",
            "command": "net use \\\\TARGET\\ADMIN$ /user:CORP\\svc_backup P@ssw0rd!",
            "mitre": "T1021.002",
        },
    },
    # WMI
    {
        "technique": "WMI_EXEC",
        "dest_port": 135,
        "protocol": "WMI",
        "process_name": "wmic.exe",
        "parent_process": "cmd.exe",
        "raw_payload": {
            "command": "wmic /node:TARGET process call create 'cmd.exe /c whoami > C:\\output.txt'",
            "mitre": "T1047",
        },
    },
    # RDP
    {
        "technique": "RDP_PIVOT",
        "dest_port": 3389,
        "protocol": "RDP",
        "process_name": "mstsc.exe",
        "parent_process": "explorer.exe",
        "raw_payload": {
            "mitre": "T1021.001",
            "nla": False,
            "clipboard_redirection": True,
        },
    },
    # Credential Dump
    {
        "technique": "LSASS_DUMP",
        "dest_port": 0,
        "protocol": "N/A",
        "process_name": "lsass.exe",
        "parent_process": "mimikatz.exe",
        "raw_payload": {
            "command": "mimikatz.exe sekurlsa::logonpasswords",
            "mitre": "T1003.001",
            "lsass_handle": True,
        },
    },
]


def _lateral_movement_events(timestamp: datetime, step: int) -> list[dict]:
    target = LATERAL_TARGETS[step % len(LATERAL_TARGETS)]
    payload_def = _LATERAL_PAYLOADS[step % len(_LATERAL_PAYLOADS)]
    events = []

    events.append(_base_event(
        layer="network" if payload_def["dest_port"] != 0 else "endpoint",
        source_ip=C2_HOST,
        dest_ip=target,
        source_port=random.randint(32768, 60000),
        dest_port=payload_def["dest_port"],
        protocol=payload_def["protocol"],
        bytes_sent=random.randint(500, 8000),
        bytes_recv=random.randint(200, 4000),
        duration_ms=random.randint(200, 2000),
        process_name=payload_def["process_name"],
        parent_process=payload_def["parent_process"],
        user=random.choice(["CORP\\svc_backup", "CORP\\Administrator", "NT AUTHORITY\\SYSTEM"]),
        geo_country="Internal",
        flags=["lateral_movement", "credential_dumping", "smb_traversal"],
        scenario="lateral_movement",
        severity="CRITICAL",
        confidence=0.93,
        timestamp=timestamp,
        raw_payload={
            **payload_def["raw_payload"],
            "target": target,
            "step": step,
            "technique": payload_def["technique"],
        },
    ))

    # Follow-up: net.exe enum after each pivot
    if payload_def["technique"] in ("SMB_LATERAL", "WMI_EXEC"):
        events.append(_base_event(
            layer="endpoint",
            source_ip=target,
            dest_ip=target,
            source_port=0,
            dest_port=0,
            protocol="N/A",
            process_name="net.exe",
            parent_process="cmd.exe",
            user="CORP\\Administrator",
            bytes_sent=0,
            bytes_recv=0,
            duration_ms=random.randint(50, 200),
            geo_country="Internal",
            flags=["lateral_movement", "discovery", "net_command"],
            scenario="lateral_movement",
            severity="CRITICAL",
            confidence=0.93,
            timestamp=timestamp + timedelta(milliseconds=random.randint(300, 1500)),
            raw_payload={
                "command": "net localgroup administrators",
                "mitre": "T1087.001",
                "target": target,
            },
        ))

    return events


# ── Benign baseline ────────────────────────────────────────────────────────────

def _benign_event(timestamp: datetime) -> dict:
    host = random.choice(EMPLOYEE_HOSTS)
    user = random.choice(EMPLOYEE_USERS)
    src_ip = random.choice(EMPLOYEE_IPS)
    port = random.choice(BENIGN_PORTS)
    protocol = {53: "DNS", 80: "HTTP", 443: "HTTPS", 25: "SMTP",
                123: "NTP", 8080: "HTTP", 8443: "HTTPS", 21: "FTP"}.get(port, "TCP")

    is_web = port in (80, 443, 8080, 8443)
    endpoints = ["/", "/index.html", "/api/status", "/health", "/login",
                 "/dashboard", "/api/v1/users", "/static/app.js", "/favicon.ico"]

    return _base_event(
        layer=random.choice(["network", "application"]) if is_web else "network",
        source_ip=src_ip,
        dest_ip=random.choice(["8.8.8.8", "1.1.1.1", "10.0.1.1", "10.0.1.50", "172.16.0.1"]),
        source_port=random.randint(1024, 65535),
        dest_port=port,
        protocol=protocol,
        bytes_sent=random.randint(64, 8192),
        bytes_recv=random.randint(64, 65536),
        duration_ms=random.randint(10, 500),
        process_name=random.choice(["chrome.exe", "firefox.exe", "outlook.exe", "teams.exe", "svchost.exe"]),
        parent_process="explorer.exe",
        user=user,
        http_method=random.choice(["GET", "POST"]) if is_web else None,
        http_endpoint=random.choice(endpoints) if is_web else None,
        http_status=random.choices([200, 301, 304, 404], weights=[70, 10, 15, 5])[0] if is_web else None,
        user_agent=random.choice(BENIGN_UAS) if is_web else None,
        geo_country="Internal",
        flags=[],
        scenario="benign",
        severity="LOW",
        confidence=0.05,
        timestamp=timestamp,
        raw_payload={
            "hostname": host,
            "dns_query": f"internal.corp" if port == 53 else None,
        },
    )


# ── Public API ────────────────────────────────────────────────────────────────

def _ist_business_hours_weight(ts: datetime) -> float:
    """Weight for IST 09:00-18:00 being peak traffic."""
    ist_hour = (ts + IST_OFFSET).hour
    if 9 <= ist_hour < 18:
        return 3.0
    if 18 <= ist_hour < 22:
        return 1.0
    return 0.3


def generate_event_batch(
    count: int = 100,
    scenario_mix: bool = True,
    base_time: Optional[datetime] = None,
) -> list[dict]:
    """
    Generate `count` events.

    Scenario mix (when scenario_mix=True):
      - 80% benign
      - 5% brute_force (Scenario A)
      - 5% c2_beacon (Scenario B)
      - 5% false_positive (Scenario C)
      - 5% lateral_movement (Scenario D, injected after first 20% of events)
    """
    events: list[dict] = []
    now = base_time or datetime.now(timezone.utc)

    if not scenario_mix:
        for i in range(count):
            ts = now + timedelta(milliseconds=i * 10)
            events.append(_benign_event(ts))
        return events

    # Allocate exact slots so total == count
    n_brute   = max(1, int(count * 0.05))
    n_c2      = max(1, int(count * 0.05))
    n_fp      = max(1, int(count * 0.05))
    n_lateral = max(1, int(count * 0.05))
    n_benign  = count - n_brute - n_c2 - n_fp - n_lateral  # fills remainder

    all_events: list[dict] = []

    # Benign baseline
    for i in range(n_benign):
        ts = now + timedelta(milliseconds=i * 10)
        all_events.append(_benign_event(ts))

    # Brute force: distribute across up to 3 windows, top-up if needed
    collected: list[dict] = []
    w = 0
    while len(collected) < n_brute:
        ts = now + timedelta(seconds=w * 15)
        collected.extend(_brute_force_events(ts, w))
        w += 1
    all_events.extend(collected[:n_brute])

    # C2 beacons
    for i in range(n_c2):
        ts = now + timedelta(seconds=i * random.uniform(47, 53))
        all_events.append(_c2_beacon_event(ts, i))

    # False positives (business hours only)
    ist_now = now + IST_OFFSET
    bh_start = ist_now.replace(hour=9, minute=0, second=0, microsecond=0) - IST_OFFSET
    for i in range(n_fp):
        ts = bh_start + timedelta(minutes=i * 30)
        all_events.append(_false_positive_event(ts, i))

    # Lateral movement (starts after 20% index)
    lateral_start = now + timedelta(seconds=count * 0.2 * 0.01)
    lm_collected: list[dict] = []
    step = 0
    while len(lm_collected) < n_lateral:
        ts = lateral_start + timedelta(seconds=step * 5)
        lm_collected.extend(_lateral_movement_events(ts, step))
        step += 1
    all_events.extend(lm_collected[:n_lateral])

    # Shuffle to interleave scenarios, then return exact count
    random.shuffle(all_events)
    return all_events[:count]


async def generate_continuous_stream(
    events_per_second: int = 100,
    duration_seconds: int = 30,
) -> AsyncGenerator[dict, None]:
    """Async generator yielding events at the target rate."""
    interval = 1.0 / events_per_second
    deadline = asyncio.get_event_loop().time() + duration_seconds
    batch_size = max(1, min(events_per_second // 10, 50))
    i = 0
    while asyncio.get_event_loop().time() < deadline:
        batch = generate_event_batch(count=batch_size, scenario_mix=True)
        for ev in batch:
            yield ev
            i += 1
        await asyncio.sleep(interval * batch_size)


async def seed_database(db_session, event_count: int = 2000) -> None:
    """Insert synthetic ThreatEvent rows into Postgres."""
    from app.models import ThreatEvent

    logger.info("seed_start", count=event_count)
    batch = generate_event_batch(count=event_count, scenario_mix=True)

    model_keys = {c.name for c in ThreatEvent.__table__.columns}
    FIELD_MAP = {
        "event_type": "layer",
        "source_ip":  "source_ip",
        "dest_ip":    "dest_ip",
        "process_name": "process_name",
        "username":   "user",
        "severity":   None,  # needs lower-casing
    }

    rows = []
    for ev in batch:
        row = ThreatEvent(
            event_type=ev["layer"],
            source_ip=ev["source_ip"],
            dest_ip=ev["dest_ip"],
            process_name=ev.get("process_name"),
            username=ev.get("user"),
            command_line=ev.get("raw_payload", {}).get("command_line"),
            severity=ev["severity"].lower(),
            category=ev.get("scenario"),
            mitre_technique=ev.get("raw_payload", {}).get("mitre"),
            is_anomaly=ev["severity"] in ("CRITICAL", "HIGH"),
            anomaly_score=ev["confidence"],
            raw_log=ev,
        )
        rows.append(row)

    for row in rows:
        db_session.add(row)
    await db_session.flush()
    logger.info("seed_complete", count=len(rows))


def save_demo_dataset(
    filepath: str = "app/data/demo_dataset.json",
    count: int = 500,
) -> None:
    """Write a demo dataset to disk as JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    events = generate_event_batch(count=count, scenario_mix=True)
    with open(filepath, "w") as fh:
        json.dump(events, fh, indent=2, default=str)
    logger.info("demo_dataset_saved", path=filepath, count=len(events))
    print(f"[synthetic_generator] Saved {len(events)} events → {filepath}")

    # Print scenario breakdown
    from collections import Counter
    breakdown = Counter(e["scenario"] for e in events)
    for scenario, n in sorted(breakdown.items()):
        print(f"  {scenario:<20} {n:>4} events  "
              f"({n/len(events)*100:.1f}%)")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import structlog as sl
    sl.configure()
    # Resolve path relative to repo root when run directly
    out = os.path.join(os.path.dirname(__file__), "demo_dataset.json")
    save_demo_dataset(filepath=out, count=500)
else:
    # Auto-generate on first import if file is missing
    _dataset_path = os.path.join(os.path.dirname(__file__), "demo_dataset.json")
    if not os.path.exists(_dataset_path):
        try:
            save_demo_dataset(filepath=_dataset_path, count=500)
        except Exception:
            pass  # Non-fatal; file will be generated on next explicit call
