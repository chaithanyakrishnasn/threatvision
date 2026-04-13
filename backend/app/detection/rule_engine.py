"""
Sigma-style detection rule engine — 12 rules as Python dataclasses.
Each rule stores JSON-serialisable conditions; actual matching is delegated
to a companion RULE_MATCHERS dict so the dataclass stays clean.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str        # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    threat_type: str
    mitre_technique: str
    conditions: dict     # JSON-serialisable condition spec
    score: float         # 0.0–1.0 confidence contribution


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    severity: str
    threat_type: str
    score: float
    mitre_technique: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_internal(ip: str) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _flags(event: dict) -> list[str]:
    return event.get("flags") or []


def _proc(event: dict) -> str:
    return (event.get("process_name") or "").lower()


def _parent(event: dict) -> str:
    return (event.get("parent_process") or "").lower()


def _layer(event: dict) -> str:
    return (event.get("layer") or event.get("event_type") or "").lower()


# ── Rule catalogue ────────────────────────────────────────────────────────────

DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="TV-001",
        name="Brute Force Auth",
        description="Repeated auth failures from Tor/scanner IPs targeting common auth ports",
        severity="HIGH",
        threat_type="brute_force",
        mitre_technique="T1110.001",
        conditions={
            "dest_port": [443, 22],
            "source_ip_cidr": "185.220.0.0/16",
            "flags_contains_any": ["brute_force_pattern", "credential_stuffing"],
        },
        score=0.90,
    ),
    DetectionRule(
        rule_id="TV-002",
        name="C2 Beacon Pattern",
        description="Periodic small outbound connections with self-signed cert to external host",
        severity="HIGH",
        threat_type="c2_beacon",
        mitre_technique="T1071.001",
        conditions={
            "flags_contains_all": ["periodic_connection", "self_signed_cert"],
            "bytes_sent_lt": 1000,
            "dest_ip_external": True,
        },
        score=0.88,
    ),
    DetectionRule(
        rule_id="TV-003",
        name="Lateral Movement SMB",
        description="Internal-to-internal SMB connection with lateral movement flag",
        severity="CRITICAL",
        threat_type="lateral_movement",
        mitre_technique="T1021.002",
        conditions={
            "dest_port": [445],
            "source_ip_internal": True,
            "dest_ip_internal": True,
            "flags_contains_any": ["smb_traversal", "lateral_movement"],
        },
        score=0.92,
    ),
    DetectionRule(
        rule_id="TV-004",
        name="Lateral Movement WMI",
        description="WMI remote execution between internal hosts",
        severity="CRITICAL",
        threat_type="lateral_movement",
        mitre_technique="T1047",
        conditions={
            "dest_port": [135],
            "source_ip_internal": True,
            "dest_ip_internal": True,
            "process_name_contains": ["wmic"],
        },
        score=0.89,
    ),
    DetectionRule(
        rule_id="TV-005",
        name="Credential Dumping",
        description="LSASS or Mimikatz process detected on endpoint layer",
        severity="CRITICAL",
        threat_type="lateral_movement",
        mitre_technique="T1003.001",
        conditions={
            "layer": "endpoint",
            "process_name_contains": ["lsass", "mimikatz"],
        },
        score=0.95,
    ),
    DetectionRule(
        rule_id="TV-006",
        name="Suspicious PowerShell",
        description="PowerShell spawned from an unusual or non-interactive parent process",
        severity="HIGH",
        threat_type="lateral_movement",
        mitre_technique="T1059.001",
        conditions={
            "process_name_exact": "powershell.exe",
            "parent_process_contains": ["cmd.exe", "wscript.exe", "cscript.exe",
                                        "mshta.exe", "w3wp.exe"],
        },
        score=0.82,
    ),
    DetectionRule(
        rule_id="TV-007",
        name="Data Exfiltration Volume",
        description="Unusually large outbound data transfer to external destination",
        severity="HIGH",
        threat_type="data_exfiltration",
        mitre_technique="T1048",
        conditions={
            "bytes_sent_gt": 50_000_000,
            "dest_ip_external": True,
        },
        score=0.75,
    ),
    DetectionRule(
        rule_id="TV-008",
        name="Tor Exit Node Traffic",
        description="Network traffic originating from known Tor exit node CIDR range",
        severity="MEDIUM",
        threat_type="brute_force",
        mitre_technique="T1090",
        conditions={
            "source_ip_cidr": "185.220.0.0/16",
        },
        score=0.85,
    ),
    DetectionRule(
        rule_id="TV-009",
        name="Self-Signed Cert C2",
        description="Outbound connection to external host using a self-signed TLS certificate",
        severity="MEDIUM",
        threat_type="c2_beacon",
        mitre_technique="T1573",
        conditions={
            "flags_contains_any": ["self_signed_cert"],
            "dest_ip_external": True,
        },
        score=0.80,
    ),
    DetectionRule(
        rule_id="TV-010",
        name="RDP Lateral Movement",
        description="RDP connection between two internal hosts",
        severity="HIGH",
        threat_type="lateral_movement",
        mitre_technique="T1021.001",
        conditions={
            "dest_port": [3389],
            "source_ip_internal": True,
            "dest_ip_internal": True,
        },
        score=0.78,
    ),
    DetectionRule(
        rule_id="TV-011",
        name="Net Command Recon",
        description="net.exe executed on an endpoint — typical for post-compromise enumeration",
        severity="MEDIUM",
        threat_type="lateral_movement",
        mitre_technique="T1087.001",
        conditions={
            "layer": "endpoint",
            "process_name_contains": ["net.exe"],
        },
        score=0.72,
    ),
    DetectionRule(
        rule_id="TV-012",
        name="Known Asset False Positive",
        description="Suppressor: known asset transferring to internal dest during business hours",
        severity="LOW",
        threat_type="false_positive",
        mitre_technique="",
        conditions={
            "flags_contains_all": ["known_asset", "internal_destination", "business_hours"],
        },
        score=0.0,
    ),
]

RULE_MAP: dict[str, DetectionRule] = {r.rule_id: r for r in DETECTION_RULES}


# ── Matcher factory ───────────────────────────────────────────────────────────

def _build_matcher(rule: DetectionRule):
    c = rule.conditions

    def match(event: dict) -> bool:
        flags = _flags(event)

        if "dest_port" in c:
            if int(event.get("dest_port") or 0) not in c["dest_port"]:
                return False

        if "source_ip_cidr" in c:
            if not _in_cidr(event.get("source_ip") or "", c["source_ip_cidr"]):
                return False

        if "flags_contains_any" in c:
            if not any(f in flags for f in c["flags_contains_any"]):
                return False

        if "flags_contains_all" in c:
            if not all(f in flags for f in c["flags_contains_all"]):
                return False

        if "bytes_sent_lt" in c:
            if int(event.get("bytes_sent") or 0) >= c["bytes_sent_lt"]:
                return False

        if "bytes_sent_gt" in c:
            if int(event.get("bytes_sent") or 0) <= c["bytes_sent_gt"]:
                return False

        if c.get("dest_ip_external"):
            if _is_internal(event.get("dest_ip") or ""):
                return False

        if c.get("source_ip_internal"):
            if not _is_internal(event.get("source_ip") or ""):
                return False

        if c.get("dest_ip_internal"):
            if not _is_internal(event.get("dest_ip") or ""):
                return False

        if "layer" in c:
            if _layer(event) != c["layer"]:
                return False

        if "process_name_contains" in c:
            proc = _proc(event)
            if not any(p in proc for p in c["process_name_contains"]):
                return False

        if "process_name_exact" in c:
            if _proc(event) != c["process_name_exact"].lower():
                return False

        if "parent_process_contains" in c:
            parent = _parent(event)
            if not any(p in parent for p in c["parent_process_contains"]):
                return False

        return True

    return match


RULE_MATCHERS: dict[str, object] = {
    rule.rule_id: _build_matcher(rule) for rule in DETECTION_RULES
}


# ── Engine ────────────────────────────────────────────────────────────────────

class RuleEngine:
    def evaluate(self, event: dict) -> list[RuleMatch]:
        """Return RuleMatch for every rule that fires on this event."""
        matches: list[RuleMatch] = []
        for rule in DETECTION_RULES:
            try:
                if RULE_MATCHERS[rule.rule_id](event):
                    matches.append(RuleMatch(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        severity=rule.severity,
                        threat_type=rule.threat_type,
                        score=rule.score,
                        mitre_technique=rule.mitre_technique,
                    ))
                    logger.debug("rule_matched", rule_id=rule.rule_id, name=rule.name)
            except Exception as exc:
                logger.warning("rule_error", rule_id=rule.rule_id, error=str(exc))
        return matches

    def get_highest_severity(self, matches: list[RuleMatch]) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for sev in order:
            if any(m.severity == sev for m in matches):
                return sev
        return "LOW"

    def get_combined_score(self, matches: list[RuleMatch]) -> float:
        """Max score across all matched rules (not sum)."""
        if not matches:
            return 0.0
        return max(m.score for m in matches)


# Module-level singleton
_engine: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


# Backward-compat helpers used by old threat_classifier
def evaluate_event(event: dict) -> list[RuleMatch]:
    return get_rule_engine().evaluate(event)


def get_highest_severity(rules: list[RuleMatch]) -> str:
    return get_rule_engine().get_highest_severity(rules)
