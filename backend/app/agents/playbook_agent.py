"""
Playbook Agent — standalone playbook generator for threat response.
Provides both instant hardcoded quick-response commands and Claude-powered
full IR playbooks.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.config import get_settings

logger = structlog.get_logger(__name__)

# ── Quick response command library ────────────────────────────────────────────

QUICK_RESPONSE: dict[str, list[str]] = {
    "brute_force": [
        "# Block attacking IP immediately",
        "iptables -A INPUT -s {source_ip} -j DROP",
        "# Check for successful logins from attacker IP",
        "grep 'Accepted' /var/log/auth.log | tail -20",
        "# Lock compromised account",
        "usermod -L {username}",
        "# Review all active sessions",
        "who -a && last | head -20",
        "# Check recent auth log failures",
        "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10",
        "# Enable account lockout via PAM",
        "faillock --user {username} --reset",
    ],
    "c2_beacon": [
        "# Isolate infected host immediately",
        "iptables -A FORWARD -s {source_ip} -j DROP",
        "# Kill suspicious process by port",
        "kill -9 $(lsof -ti:{dest_port})",
        "# Check scheduled tasks for persistence",
        "crontab -l && cat /etc/cron*/*",
        "# Dump network connections",
        "ss -tulnp && netstat -antp | grep ESTABLISHED",
        "# Check for unusual outbound connections",
        "ss -tulnp | grep ESTABLISHED | grep -v '127.0.0.1'",
        "# Inspect process command line for beacon process",
        "strings /proc/{pid}/exe | grep -i http",
    ],
    "lateral_movement": [
        "# Disable SMB on affected hosts",
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        "# Check for new local admins",
        "Get-LocalGroupMember -Group Administrators",
        "# Review recent logins across domain",
        "Get-EventLog -LogName Security -InstanceId 4624 -Newest 50",
        "# Reset compromised credentials",
        "net user {username} /random && net user {username} /active:yes",
        "# Check SMB sessions",
        "net session",
        "# Block internal lateral movement at firewall",
        "New-NetFirewallRule -DisplayName 'Block SMB' -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block",
    ],
    "data_exfiltration": [
        "# Block egress to destination IP",
        "iptables -A OUTPUT -d {dest_ip} -j DROP",
        "# Capture traffic for forensics",
        "tcpdump -i eth0 'dst {dest_ip}' -w /tmp/exfil_capture.pcap",
        "# Find recently modified large files",
        "find / -size +10M -newer /tmp/sentinel -mtime -1 2>/dev/null",
        "# Check for active transfers",
        "lsof -i TCP | grep ESTABLISHED",
        "# Kill active transfer process",
        "kill -9 $(lsof -ti TCP@{dest_ip})",
        "# Verify data integrity on sensitive directories",
        "find /data -name '*.zip' -o -name '*.tar.gz' | xargs ls -la",
    ],
    "false_positive": [
        "# Verify this is a known scheduled task",
        "schtasks /query /tn 'DailyBackup' /fo LIST",
        "# Confirm asset is whitelisted",
        "cat /etc/security/known_assets.conf | grep {source_ip}",
        "# Document false positive for tuning",
        "echo '{timestamp} FP confirmed: {source_ip} is known backup server' >> /var/log/fp_log.txt",
    ],
}


# ── Playbook Agent ─────────────────────────────────────────────────────────────

class PlaybookAgent:
    """Standalone playbook generator — fast commands + AI-powered full playbooks."""

    def __init__(self) -> None:
        settings = get_settings()
        self.llm = ChatAnthropic(
            model="claude-opus-4-5",
            api_key=settings.anthropic_api_key,
            max_tokens=2500,
            timeout=30,
            max_retries=0,
        )

    def get_quick_response(self, threat_type: str) -> list[str]:
        """Return immediate response commands for a threat type. No LLM needed."""
        cmds = QUICK_RESPONSE.get(threat_type)
        if cmds:
            return cmds
        # Fallback: generic IR commands
        return [
            "# Generic incident response",
            "# 1. Identify and isolate affected systems",
            "netstat -antp | grep ESTABLISHED",
            "# 2. Preserve evidence",
            "dmesg > /tmp/dmesg.txt && cp /var/log/syslog /tmp/syslog_backup.txt",
            "# 3. Notify security team",
            "echo 'Security incident detected' | mail -s 'IR Alert' security@company.com",
        ]

    async def generate_for_threat(
        self,
        threat_type: str,
        severity: str,
        affected_ips: list[str],
    ) -> "ResponsePlaybook":
        """Generate a full IR playbook for a specific threat type."""
        from app.agents.blue_agent import (
            BlueAgent, IncidentAnalysis, _fallback_playbook
        )

        incident = IncidentAnalysis(
            incident_id=str(uuid.uuid4()),
            severity=severity,
            threat_summary=f"{threat_type.replace('_', ' ').title()} detected on {', '.join(affected_ips[:3])}.",
            attack_chain=[
                f"Attacker initiates {threat_type}",
                "Persistence or escalation attempted",
                "Detection triggered",
            ],
            affected_assets=affected_ips,
            root_cause=f"Active {threat_type} attack targeting internal infrastructure.",
            business_impact="Potential data compromise, service disruption, or credential theft.",
            confidence=0.85,
            recommended_priority="immediate" if severity == "CRITICAL" else "high",
        )

        system_msg = (
            "You are an incident response expert. "
            "Generate detailed, actionable playbooks with real CLI commands. Always respond in valid JSON."
        )
        quick_cmds = self.get_quick_response(threat_type)
        user_msg = f"""Generate a full IR playbook for a {severity} severity {threat_type} incident.
Affected systems: {affected_ips[:5]}
Quick response commands available: {json.dumps(quick_cmds[:6], indent=2)}

Respond with this exact JSON:
{{
  "title": "IR Playbook: {threat_type.replace('_', ' ').title()} — {severity}",
  "phases": [
    {{
      "phase_name": "Containment", "priority": 1,
      "steps": [
        {{
          "step_id": "C1",
          "title": "Isolate affected host",
          "description": "Immediately isolate the affected system from the network",
          "commands": ["iptables -A INPUT -s ATTACKER_IP -j DROP"],
          "expected_outcome": "No further attacker access",
          "estimated_minutes": 5
        }}
      ]
    }},
    {{"phase_name": "Eradication", "priority": 2, "steps": []}},
    {{"phase_name": "Recovery", "priority": 3, "steps": []}},
    {{"phase_name": "Lessons Learned", "priority": 4, "steps": []}}
  ],
  "estimated_time_minutes": 120,
  "required_tools": ["Firewall", "EDR", "SIEM"],
  "success_criteria": ["Threat eliminated", "No recurrence in 24h"]
}}"""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_msg),
                HumanMessage(content=user_msg),
            ])
            content = response.content.strip()
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])
                from app.agents.blue_agent import PlaybookPhase, PlaybookStep, ResponsePlaybook
                phases = []
                for pd in data.get("phases", []):
                    steps = [
                        PlaybookStep(
                            step_id=s.get("step_id", str(uuid.uuid4())[:6]),
                            title=s.get("title", ""),
                            description=s.get("description", ""),
                            commands=s.get("commands", []),
                            expected_outcome=s.get("expected_outcome", ""),
                            estimated_minutes=int(s.get("estimated_minutes", 5)),
                        )
                        for s in pd.get("steps", [])
                    ]
                    phases.append(PlaybookPhase(
                        phase_name=pd.get("phase_name", ""),
                        priority=int(pd.get("priority", 1)),
                        steps=steps,
                    ))
                logger.info("playbook_agent_generated", via="claude", threat_type=threat_type)
                return ResponsePlaybook(
                    playbook_id=str(uuid.uuid4()),
                    incident_id=incident.incident_id,
                    threat_type=threat_type,
                    title=data.get("title", f"IR: {threat_type}"),
                    phases=phases,
                    estimated_time_minutes=int(data.get("estimated_time_minutes", 120)),
                    required_tools=data.get("required_tools", []),
                    success_criteria=data.get("success_criteria", []),
                )
        except Exception as exc:
            logger.warning("playbook_agent_claude_error", error=str(exc))

        return _fallback_playbook(incident, threat_type, {})

    async def generate_for_incident(
        self,
        incident: "IncidentAnalysis",
    ) -> "ResponsePlaybook":
        """Generate a playbook from an existing IncidentAnalysis."""
        from app.agents.blue_agent import BlueAgent
        agent = BlueAgent()
        return await agent._generate_playbook_internal(incident)
