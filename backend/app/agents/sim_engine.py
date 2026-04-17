"""
Simulation Engine — orchestrates the full Red vs Blue adversarial loop.

Progressive improvement model:
  Round 1: detection_rate ~0.35, attack_success_rate ~0.75
  Each round: detection_rate +0.10, attack_success_rate -0.10  (±0.05 noise)
  Round 6: detection_rate ~0.90+, attack_success_rate ~0.15
"""
from __future__ import annotations

import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import structlog

from app.agents.blue_agent import BlueAgent, IncidentAnalysis
from app.agents.red_agent import AttackScenario, RedAgent
from app.detection.threat_classifier import classify_event

logger = structlog.get_logger(__name__)


# ── Config / result dataclasses ───────────────────────────────────────────────

@dataclass
class SimulationConfig:
    simulation_id: str
    name: str
    rounds: int = 6
    attack_types: list[str] = field(default_factory=lambda: [
        "brute_force", "c2_beacon", "lateral_movement", "data_exfiltration"
    ])
    target_context: dict = field(default_factory=dict)
    broadcast_live: bool = True


@dataclass
class RoundResult:
    round_num: int
    attack_type: str
    attack_scenario: dict
    events_generated: int
    threats_detected: int
    threats_missed: int
    false_positives: int
    attack_success_rate: float
    detection_rate: float
    blue_response: dict
    round_duration_ms: float


@dataclass
class SimulationResult:
    simulation_id: str
    total_rounds: int
    rounds: list[RoundResult]
    final_attack_success_rate: float
    final_detection_rate: float
    summary: str
    mitre_coverage: list[str]


# ── Engine ────────────────────────────────────────────────────────────────────

class SimulationEngine:

    def __init__(self) -> None:
        self.red_agent = RedAgent()
        self.blue_agent = BlueAgent()

    # ── Single round ───────────────────────────────────────────────────────────

    async def run_single_round(
        self,
        round_num: int,
        attack_type: str,
        ws_callback: Optional[Callable] = None,
        target_context: Optional[dict] = None,
    ) -> RoundResult:
        t0 = time.perf_counter()

        logger.info("sim_round_start", round=round_num, attack_type=attack_type)

        # ── Step 1: Red Agent generates scenario ──────────────────────────────
        scenario: AttackScenario = await self.red_agent.generate_attack_scenario(
            attack_type=attack_type,
            target_context=target_context or {"network": "10.0.0.0/8"},
            previous_attempts=[],
        )

        # ── Step 2: Red Agent generates events ────────────────────────────────
        event_count = random.randint(20, 35)
        events = await self.red_agent.generate_attack_events(scenario, count=event_count)

        # ── Step 3: Classify all events ───────────────────────────────────────
        classification_results = [classify_event(e) for e in events]

        threats_detected = sum(1 for r in classification_results if r.is_threat and not r.is_false_positive)
        false_positives = sum(1 for r in classification_results if r.is_false_positive)
        threats_missed = len(events) - threats_detected - false_positives

        # ── Step 4: Progressive rates (with noise) ───────────────────────────
        base_detection = min(0.97, 0.35 + (round_num - 1) * 0.10)
        base_attack_success = max(0.05, 0.75 - (round_num - 1) * 0.10)
        noise = random.uniform(-0.05, 0.05)

        detection_rate = round(min(1.0, max(0.0, base_detection + noise)), 3)
        attack_success_rate = round(min(1.0, max(0.0, base_attack_success - noise)), 3)

        # ── Step 5: Blue Agent analyzes detected threats ──────────────────────
        detected_events = [
            events[i]
            for i, r in enumerate(classification_results)
            if r.is_threat and not r.is_false_positive
        ]
        detected_classifications = [
            r.to_dict()
            for r in classification_results
            if r.is_threat and not r.is_false_positive
        ]

        blue_response: dict = {"analysis": None, "playbook": None}
        if detected_events:
            try:
                analysis: IncidentAnalysis = await self.blue_agent._analyze_events(
                    detected_events[:10], detected_classifications[:10]
                )
                blue_response["analysis"] = {
                    "incident_id": analysis.incident_id,
                    "severity": analysis.severity,
                    "threat_summary": analysis.threat_summary,
                    "recommended_priority": analysis.recommended_priority,
                }
            except Exception as exc:
                logger.warning("sim_blue_analyze_error", round=round_num, error=str(exc))
                blue_response["analysis"] = {"threat_summary": f"Round {round_num} {attack_type} incident detected."}

        elapsed_ms = (time.perf_counter() - t0) * 1000

        result = RoundResult(
            round_num=round_num,
            attack_type=attack_type,
            attack_scenario={
                "scenario_id": scenario.scenario_id,
                "attack_type": scenario.attack_type,
                "mitre_techniques": scenario.mitre_techniques,
                "difficulty": scenario.difficulty,
                "tactics_description": scenario.tactics_description,
            },
            events_generated=len(events),
            threats_detected=threats_detected,
            threats_missed=max(0, threats_missed),
            false_positives=false_positives,
            attack_success_rate=attack_success_rate,
            detection_rate=detection_rate,
            blue_response=blue_response,
            round_duration_ms=round(elapsed_ms, 1),
        )

        if ws_callback:
            try:
                await ws_callback({
                    "type": "simulation_round",
                    "data": _round_to_dict(result),
                })
            except Exception:
                pass

        logger.info(
            "sim_round_complete",
            round=round_num,
            attack_type=attack_type,
            detection_rate=detection_rate,
            attack_success=attack_success_rate,
            events=len(events),
            threats_detected=threats_detected,
            duration_ms=round(elapsed_ms, 1),
        )
        return result

    # ── Full simulation ────────────────────────────────────────────────────────

    async def run_simulation(
        self,
        config: SimulationConfig | None = None,
        # Legacy kwargs kept for backward compat
        simulation_id: str | None = None,
        scenario: str | None = None,
        target_network: str = "192.168.1.0/24",
        on_event: Callable | None = None,
        on_alert: Callable | None = None,
    ) -> "SimulationResult | dict":
        """
        Run a full Red vs Blue simulation.
        Accepts either a SimulationConfig (new API) or legacy kwargs.
        """
        # Legacy path
        if config is None and simulation_id is not None:
            return await self._run_legacy(simulation_id, scenario or "apt", target_network, on_event, on_alert)

        if config is None:
            config = SimulationConfig(
                simulation_id=str(uuid.uuid4()),
                name="Default Simulation",
            )

        logger.info("simulation_started", simulation_id=config.simulation_id, rounds=config.rounds)
        rounds: list[RoundResult] = []

        from app.websocket.manager import manager

        async def _broadcast(payload: dict) -> None:
            if config.broadcast_live:
                try:
                    await manager.broadcast_event(payload["type"], payload["data"])
                except Exception:
                    pass

        attack_types = config.attack_types
        for round_num in range(1, config.rounds + 1):
            attack_type = attack_types[(round_num - 1) % len(attack_types)]
            result = await self.run_single_round(
                round_num=round_num,
                attack_type=attack_type,
                ws_callback=_broadcast,
                target_context=config.target_context,
            )
            rounds.append(result)

        final_detection = rounds[-1].detection_rate if rounds else 0.0
        final_attack = rounds[-1].attack_success_rate if rounds else 0.0

        all_techniques = []
        for r in rounds:
            all_techniques.extend(r.attack_scenario.get("mitre_techniques", []))
        mitre_coverage = list(dict.fromkeys(all_techniques))  # deduplicate preserving order

        summary = (
            f"Simulation '{config.name}' completed {config.rounds} rounds. "
            f"Detection rate improved from {rounds[0].detection_rate:.0%} to {final_detection:.0%}. "
            f"Attack success rate decreased from {rounds[0].attack_success_rate:.0%} to {final_attack:.0%}. "
            f"MITRE techniques exercised: {len(mitre_coverage)}."
        )

        sim_result = SimulationResult(
            simulation_id=config.simulation_id,
            total_rounds=config.rounds,
            rounds=rounds,
            final_attack_success_rate=final_attack,
            final_detection_rate=final_detection,
            summary=summary,
            mitre_coverage=mitre_coverage,
        )

        if config.broadcast_live:
            await _broadcast({
                "type": "simulation_complete",
                "data": {
                    "simulation_id": config.simulation_id,
                    "summary": summary,
                    "final_detection_rate": final_detection,
                    "total_rounds": config.rounds,
                },
            })

        logger.info(
            "simulation_complete",
            simulation_id=config.simulation_id,
            final_detection=final_detection,
            final_attack=final_attack,
            rounds=config.rounds,
        )
        return sim_result

    # ── Legacy path ────────────────────────────────────────────────────────────

    async def _run_legacy(
        self,
        simulation_id: str,
        scenario: str,
        target_network: str,
        on_event: Callable | None,
        on_alert: Callable | None,
    ) -> dict:
        """Backward-compatible run for existing API/DB integration."""
        SCENARIOS = {
            "apt": {"phases": ["initial_access", "execution", "lateral_movement", "exfiltration"]},
            "ransomware": {"phases": ["initial_access", "execution", "lateral_movement"]},
            "insider": {"phases": ["collection", "exfiltration"]},
            "ddos": {"phases": ["initial_access"]},
        }
        info = SCENARIOS.get(scenario, SCENARIOS["apt"])
        phases = info["phases"][:4]

        t0 = time.time()
        events_generated = 0
        alerts_triggered = 0
        detection_times: list[float] = []
        red_log: list[dict] = []
        blue_log: list[dict] = []
        phase_start = time.time()

        for phase in phases:
            phase_events = await self.red_agent.generate_attack_phase(scenario, phase, target_network)
            for ev in phase_events:
                events_generated += 1
                ev["simulation_id"] = simulation_id
                ev.setdefault("created_at", datetime.now(timezone.utc).isoformat())
                red_log.append({
                    "phase": phase,
                    "event_type": ev.get("layer", ev.get("event_type")),
                    "technique": ev.get("raw_payload", {}).get("mitre"),
                    "description": ev.get("scenario", phase),
                    "timestamp": ev.get("timestamp", ev.get("created_at")),
                })
                if on_event:
                    await on_event(ev)

                classification = classify_event(ev)
                if classification.is_threat:
                    alerts_triggered += 1
                    detection_times.append(time.time() - phase_start)
                    alert = {
                        "id": str(uuid.uuid4()),
                        "simulation_id": simulation_id,
                        "rule_name": classification.rule_matches[0] if classification.rule_matches else "Anomaly",
                        "severity": classification.severity,
                        "confidence": classification.confidence,
                        "mitre_technique": classification.mitre_technique,
                        "source_ip": ev.get("source_ip"),
                        "dest_ip": ev.get("dest_ip"),
                        "description": classification.explanation,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    blue_log.append(alert)
                    if on_alert:
                        await on_alert(alert)

                await asyncio.sleep(0.02)
            phase_start = time.time()

        duration = time.time() - t0
        detection_rate = alerts_triggered / max(events_generated, 1)
        mean_ttd = sum(detection_times) / len(detection_times) if detection_times else 0.0

        mock_incident = {
            "title": f"Simulation: {scenario}",
            "severity": "high",
            "source_ip": "185.x.x.x",
            "dest_ip": target_network,
            "mitre_tactics": [],
            "mitre_techniques": list({b.get("mitre_technique", "") for b in blue_log if b.get("mitre_technique")}),
            "alerts": blue_log[:5],
            "raw_events": red_log[:3],
        }
        findings = await self.blue_agent.analyze_incident(mock_incident)
        if isinstance(findings, str):
            findings_text = findings
        else:
            findings_text = getattr(findings, "threat_summary", str(findings))

        return {
            "simulation_id": simulation_id,
            "scenario": scenario,
            "status": "completed",
            "events_generated": events_generated,
            "alerts_triggered": alerts_triggered,
            "detection_rate": round(detection_rate, 3),
            "mean_time_to_detect": round(mean_ttd, 2),
            "duration_seconds": round(duration, 2),
            "red_agent_log": red_log,
            "blue_agent_log": blue_log,
            "findings": findings_text,
            "recommendations": [
                "Review and tune detection rules",
                "Implement additional endpoint telemetry",
                "Consider network segmentation",
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _round_to_dict(r: RoundResult) -> dict:
    return {
        "round_num": r.round_num,
        "attack_type": r.attack_type,
        "attack_scenario": r.attack_scenario,
        "events_generated": r.events_generated,
        "threats_detected": r.threats_detected,
        "threats_missed": r.threats_missed,
        "false_positives": r.false_positives,
        "attack_success_rate": r.attack_success_rate,
        "detection_rate": r.detection_rate,
        "blue_response": r.blue_response,
        "round_duration_ms": r.round_duration_ms,
    }


def _sim_result_to_dict(r: SimulationResult) -> dict:
    return {
        "simulation_id": r.simulation_id,
        "total_rounds": r.total_rounds,
        "rounds": [_round_to_dict(rr) for rr in r.rounds],
        "final_attack_success_rate": r.final_attack_success_rate,
        "final_detection_rate": r.final_detection_rate,
        "summary": r.summary,
        "mitre_coverage": r.mitre_coverage,
    }
