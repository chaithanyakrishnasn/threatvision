"""
MITRE ATT&CK mapping for ThreatVision threat types.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.detection.threat_classifier import ThreatClassificationResult

THREAT_TO_MITRE: dict[str, dict] = {
    "brute_force": {
        "tactics": ["TA0006 - Credential Access", "TA0001 - Initial Access"],
        "techniques": [
            "T1110 - Brute Force",
            "T1110.001 - Password Guessing",
            "T1110.003 - Password Spraying",
        ],
        "references": ["https://attack.mitre.org/techniques/T1110/"],
    },
    "c2_beacon": {
        "tactics": ["TA0011 - Command and Control"],
        "techniques": [
            "T1071 - Application Layer Protocol",
            "T1071.001 - Web Protocols",
            "T1573 - Encrypted Channel",
            "T1008 - Fallback Channels",
        ],
        "references": ["https://attack.mitre.org/techniques/T1071/"],
    },
    "lateral_movement": {
        "tactics": ["TA0008 - Lateral Movement", "TA0006 - Credential Access"],
        "techniques": [
            "T1021 - Remote Services",
            "T1021.002 - SMB/Windows Admin Shares",
            "T1003 - OS Credential Dumping",
            "T1003.001 - LSASS Memory",
        ],
        "references": ["https://attack.mitre.org/techniques/T1021/"],
    },
    "data_exfiltration": {
        "tactics": ["TA0010 - Exfiltration"],
        "techniques": [
            "T1048 - Exfiltration Over Alternative Protocol",
            "T1041 - Exfiltration Over C2 Channel",
        ],
        "references": ["https://attack.mitre.org/techniques/T1048/"],
    },
    "false_positive": {
        "tactics": [],
        "techniques": [],
        "references": [],
    },
    "benign": {
        "tactics": [],
        "techniques": [],
        "references": [],
    },
}

# Backward-compat technique ID → metadata (used by old code paths)
TECHNIQUE_MAP: dict[str, dict] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control"},
    "T1087.001": {"name": "Local Account", "tactic": "Discovery"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
}


class MitreMapper:
    def get_mapping(self, threat_type: str) -> dict:
        return THREAT_TO_MITRE.get(threat_type, THREAT_TO_MITRE["benign"])

    def get_techniques(self, threat_type: str) -> list[str]:
        return self.get_mapping(threat_type)["techniques"]

    def get_tactics(self, threat_type: str) -> list[str]:
        return self.get_mapping(threat_type)["tactics"]

    def enrich_result(self, result: "ThreatClassificationResult") -> "ThreatClassificationResult":
        mapping = self.get_mapping(result.threat_type)
        result.mitre_tactics = mapping["tactics"]
        result.mitre_techniques = mapping["techniques"]
        return result


# Module-level singleton
_mapper: MitreMapper | None = None


def get_mitre_mapper() -> MitreMapper:
    global _mapper
    if _mapper is None:
        _mapper = MitreMapper()
    return _mapper


# Backward-compat helpers ──────────────────────────────────────────────────────

def get_tactic(technique_id: str) -> str | None:
    info = TECHNIQUE_MAP.get(technique_id)
    return info["tactic"] if info else None


def map_to_technique(text: str) -> str | None:
    """Keyword-based heuristic mapping (backward-compat)."""
    lower = text.lower()
    _KW = [
        (["powershell", "-encodedcommand", "-enc", "invoke-expression"], "T1059.001"),
        (["mimikatz", "lsass", "sekurlsa"], "T1003.001"),
        (["rdp", "mstsc", "3389"], "T1021.001"),
        (["smb", "admin$", "c$", "ipc$"], "T1021.002"),
        (["brute force", "password spray", "failed login", "authentication failure"], "T1110.001"),
        (["exfil", "data transfer", "upload"], "T1041"),
        (["beacon", "c2", "command and control"], "T1071"),
    ]
    for keywords, technique in _KW:
        if any(kw in lower for kw in keywords):
            return technique
    return None


def enrich_with_mitre(event: dict) -> dict:
    """Legacy enrichment — no-op passthrough (kept for old import paths)."""
    return event
