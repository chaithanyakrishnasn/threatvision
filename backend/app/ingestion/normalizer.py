"""
Normalization pipeline for ThreatVision.

Accepts raw logs in three formats:
  - netflow   : dict with src_ip/dst_ip/bytes_in/bytes_out/...
  - windows_event : dict with EventID/EventData/Computer/...
  - http_access   : dict with client_ip/request/status/bytes/...

Enriches every event with GeoIP, asset-DB lookup, and threat-intel flags,
then returns a validated NormalizedEvent Pydantic model.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import structlog

from .event_schema import NormalizedEvent

logger = structlog.get_logger(__name__)

# ── Enrichment tables ─────────────────────────────────────────────────────────

# GeoIP — prefix → country label
_GEOIP: list[tuple[str, str]] = [
    ("185.220.", "Russia/Tor"),
    ("91.108.",  "Netherlands"),
    ("10.",      "Internal"),
    ("172.16.",  "Internal"),
    ("172.17.",  "Internal"),
    ("192.168.", "Internal"),
    ("127.",     "Internal"),
]

# Known assets — exact IP → friendly label
_ASSET_DB: dict[str, str] = {
    "10.0.1.25":  "admin-workstation",
    "10.0.1.50":  "auth-server",
    "10.0.50.100": "nas-backup",
    "10.0.2.87":  "c2-infected-host",
    "10.0.1.100": "workstation-east-01",
    "10.0.1.101": "workstation-east-02",
    "10.0.1.102": "workstation-east-03",
}

# Threat-intel: prefix → flags to add
_THREAT_INTEL: list[tuple[str, list[str]]] = [
    ("185.220.", ["tor_exit_node", "threat_intel_hit"]),
    ("91.108.",  ["known_c2_range", "threat_intel_hit"]),
]


def _geo(ip: str) -> Optional[str]:
    for prefix, country in _GEOIP:
        if ip.startswith(prefix):
            return country
    return None


def _asset_label(ip: str) -> Optional[str]:
    return _ASSET_DB.get(ip)


def _threat_flags(ip: str) -> list[str]:
    flags: list[str] = []
    for prefix, fl in _THREAT_INTEL:
        if ip.startswith(prefix):
            flags.extend(fl)
    if _asset_label(ip):
        flags.append("known_asset")
    return flags


def _enrich(event: dict, src_ip: str, dst_ip: str) -> dict:
    """Mutate event dict in-place: add geo_country and threat flags."""
    # GeoIP
    if not event.get("geo_country"):
        event["geo_country"] = _geo(src_ip) or _geo(dst_ip)

    # Threat-intel flags
    extra_flags: list[str] = []
    extra_flags.extend(_threat_flags(src_ip))
    extra_flags.extend(_threat_flags(dst_ip))

    # Asset enrichment in raw_payload
    event.setdefault("raw_payload", {})
    src_asset = _asset_label(src_ip)
    dst_asset = _asset_label(dst_ip)
    if src_asset:
        event["raw_payload"]["src_asset"] = src_asset
    if dst_asset:
        event["raw_payload"]["dst_asset"] = dst_asset

    # Merge flags (preserve existing)
    existing = set(event.get("flags") or [])
    event["flags"] = list(existing | set(extra_flags))

    return event


# ── Format detectors ──────────────────────────────────────────────────────────

def _detect_format(raw: dict) -> str:
    """Heuristic format detection — unified schema wins if both event_id and layer present."""
    keys = set(raw.keys())
    # Unified schema takes priority — it always has both event_id and layer
    if "event_id" in keys and "layer" in keys:
        return "unified"
    if raw.get("log_format"):
        return raw["log_format"]
    if keys & {"EventID", "EventData", "Computer", "Channel", "winlog"}:
        return "windows_event"
    if keys & {"client_ip", "request", "status_code", "response_bytes"}:
        return "http_access"
    if keys & {"src_ip", "dst_ip", "bytes_in", "bytes_out", "proto", "netflow_version"}:
        return "netflow"
    return "netflow"   # safe default


# ── Per-format normalizers ────────────────────────────────────────────────────

def _from_netflow(raw: dict) -> dict:
    src = raw.get("src_ip", raw.get("source_ip", "0.0.0.0"))
    dst = raw.get("dst_ip", raw.get("dest_ip", "0.0.0.0"))
    proto_num = raw.get("proto", raw.get("protocol", "TCP"))
    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP", 6: "TCP", 17: "UDP", 1: "ICMP"}
    protocol = proto_map.get(proto_num, str(proto_num).upper())

    event = {
        "layer": "network",
        "source_ip": src,
        "dest_ip": dst,
        "source_port": int(raw.get("src_port", raw.get("sport", 0))),
        "dest_port": int(raw.get("dst_port", raw.get("dport", 0))),
        "protocol": protocol,
        "bytes_sent": int(raw.get("bytes_out", raw.get("bytes_sent", raw.get("out_bytes", 0)))),
        "bytes_recv": int(raw.get("bytes_in",  raw.get("bytes_recv", raw.get("in_bytes",  0)))),
        "duration_ms": int(raw.get("duration_ms", raw.get("flow_duration_ms", 0))),
        "process_name": None,
        "parent_process": None,
        "user": raw.get("username"),
        "http_method": None,
        "http_endpoint": None,
        "http_status": None,
        "user_agent": None,
        "geo_country": None,
        "flags": list(raw.get("flags", [])),
        "scenario": raw.get("scenario"),
        "severity": str(raw.get("severity", "LOW")).upper(),
        "confidence": float(raw.get("confidence", 0.1)),
        "raw_payload": {k: v for k, v in raw.items()},
    }
    _enrich(event, src, dst)
    return event


def _from_windows_event(raw: dict) -> dict:
    winlog = raw.get("winlog", raw)
    event_data = winlog.get("EventData", winlog.get("event_data", {}))
    computer = (
        raw.get("Computer") or winlog.get("Computer") or
        winlog.get("computer_name") or "unknown"
    )
    src = (
        event_data.get("IpAddress") or event_data.get("SourceAddress") or
        raw.get("source_ip", "0.0.0.0")
    )
    dst = raw.get("dest_ip", "0.0.0.0")

    # Infer severity from Event ID
    event_id = int(raw.get("EventID", winlog.get("event_id", 0)))
    sev_map = {4625: "HIGH", 4648: "HIGH", 4672: "HIGH", 4688: "MEDIUM",
               4698: "MEDIUM", 4720: "MEDIUM", 7045: "HIGH"}
    severity = sev_map.get(event_id, "LOW")

    cmd = (
        event_data.get("CommandLine") or event_data.get("command_line") or
        event_data.get("ProcessCommandLine")
    )

    event = {
        "layer": "endpoint",
        "source_ip": src,
        "dest_ip": dst,
        "source_port": 0,
        "dest_port": int(raw.get("dest_port", 0)),
        "protocol": "N/A",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "duration_ms": 0,
        "process_name": (
            event_data.get("NewProcessName") or event_data.get("ProcessName") or
            event_data.get("process_name")
        ),
        "parent_process": (
            event_data.get("ParentProcessName") or event_data.get("ParentImage")
        ),
        "user": (
            event_data.get("SubjectUserName") or event_data.get("TargetUserName") or
            winlog.get("user")
        ),
        "http_method": None,
        "http_endpoint": None,
        "http_status": None,
        "user_agent": None,
        "geo_country": None,
        "flags": list(raw.get("flags", [])),
        "scenario": raw.get("scenario"),
        "severity": severity,
        "confidence": float(raw.get("confidence", 0.5)),
        "raw_payload": {
            "event_id": event_id,
            "computer": computer,
            "command_line": cmd,
            **{k: v for k, v in event_data.items()},
        },
    }
    _enrich(event, src, dst)
    return event


def _from_http_access(raw: dict) -> dict:
    src = raw.get("client_ip", raw.get("source_ip", "0.0.0.0"))
    dst = raw.get("server_ip", raw.get("dest_ip", "0.0.0.0"))
    status = int(raw.get("status_code", raw.get("http_status", 200)))

    # Severity heuristic: 4xx/5xx → medium; suspicious paths → high
    suspicious_paths = ["/admin", "/.env", "/wp-login", "/phpmyadmin", "/api/v1/auth"]
    path = raw.get("request", raw.get("http_endpoint", "/"))
    is_suspicious = any(p in path for p in suspicious_paths)
    severity = "HIGH" if (is_suspicious and status in (200, 201)) else (
        "MEDIUM" if status >= 400 else "LOW"
    )

    event = {
        "layer": "application",
        "source_ip": src,
        "dest_ip": dst,
        "source_port": int(raw.get("client_port", raw.get("source_port", 0))),
        "dest_port": int(raw.get("server_port", raw.get("dest_port", 80))),
        "protocol": "HTTPS" if raw.get("server_port", 80) == 443 else "HTTP",
        "bytes_sent": int(raw.get("request_bytes", raw.get("bytes_sent", 0))),
        "bytes_recv": int(raw.get("response_bytes", raw.get("bytes_recv", 0))),
        "duration_ms": int(raw.get("response_time_ms", raw.get("duration_ms", 0))),
        "process_name": None,
        "parent_process": None,
        "user": raw.get("username", raw.get("auth_user")),
        "http_method": raw.get("http_method", raw.get("method", "GET")),
        "http_endpoint": path,
        "http_status": status,
        "user_agent": raw.get("user_agent", raw.get("ua")),
        "geo_country": None,
        "flags": list(raw.get("flags", [])),
        "scenario": raw.get("scenario"),
        "severity": severity,
        "confidence": float(raw.get("confidence", 0.3 if is_suspicious else 0.05)),
        "raw_payload": {k: v for k, v in raw.items()},
    }
    _enrich(event, src, dst)
    return event


def _from_unified(raw: dict) -> dict:
    """Pass-through for events already in unified schema — still re-enrich."""
    event = dict(raw)
    # Ensure all required keys exist
    event.setdefault("layer", "network")
    event.setdefault("source_port", 0)
    event.setdefault("dest_port", 0)
    event.setdefault("protocol", "UNKNOWN")
    event.setdefault("bytes_sent", 0)
    event.setdefault("bytes_recv", 0)
    event.setdefault("duration_ms", 0)
    event.setdefault("flags", [])
    event.setdefault("severity", "LOW")
    event.setdefault("confidence", 0.0)
    event.setdefault("raw_payload", {})
    src = event.get("source_ip", "0.0.0.0")
    dst = event.get("dest_ip", "0.0.0.0")
    _enrich(event, src, dst)
    return event


# ── Public API ────────────────────────────────────────────────────────────────

_HANDLERS = {
    "netflow":       _from_netflow,
    "windows_event": _from_windows_event,
    "http_access":   _from_http_access,
    "unified":       _from_unified,
}


def normalize_event(raw: dict, fmt: str = "auto") -> Optional[NormalizedEvent]:
    """
    Normalize a single raw log dict to a NormalizedEvent.

    Args:
        raw: Raw log dict in any supported format.
        fmt: "auto" | "netflow" | "windows_event" | "http_access" | "unified"

    Returns:
        NormalizedEvent or None on validation failure.
    """
    detected = _detect_format(raw) if fmt == "auto" else fmt
    handler = _HANDLERS.get(detected, _from_netflow)
    try:
        normalized_dict = handler(raw)
        return NormalizedEvent(**normalized_dict)
    except Exception as exc:
        logger.warning(
            "normalization_failed",
            fmt=detected,
            error=str(exc),
            keys=list(raw.keys())[:10],
        )
        return None


def normalize_batch(
    raws: list[dict],
    fmt: str = "auto",
) -> list[NormalizedEvent]:
    """Normalize a list of raw logs, skipping failures."""
    results: list[NormalizedEvent] = []
    failed = 0
    for raw in raws:
        ev = normalize_event(raw, fmt)
        if ev is not None:
            results.append(ev)
        else:
            failed += 1
    if failed:
        logger.warning("normalize_batch_failures", failed=failed, total=len(raws))
    return results


# Keep backward-compat alias used by old code
def normalize_raw(raw: dict) -> Optional[NormalizedEvent]:
    return normalize_event(raw, fmt="auto")
