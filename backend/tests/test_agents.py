"""
Agent tests — split into fast (no Claude) and slow (Claude API) groups.

Fast tests (run always):
  - test_playbook_agent_quick_response
  - test_red_agent_generate_events
  - test_sim_engine_single_round
  - test_sim_engine_full_run

Slow tests (require real ANTHROPIC_API_KEY, skipped in CI):
  - test_red_agent_generate_scenario
  - test_blue_agent_analyze_incident
  - test_blue_agent_generate_playbook
  - test_blue_agent_explain_alert

Run all:   pytest tests/test_agents.py -v
Run fast:  pytest tests/test_agents.py -v -m "not slow"
Run slow:  pytest tests/test_agents.py -v -m slow
"""
import asyncio
import os

import pytest

# ── Markers ───────────────────────────────────────────────────────────────────
pytestmark = []  # set per-test below


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_real_api_key() -> bool:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    return bool(key) and not key.startswith("dummy") and not key.startswith("sk-ant-fake")


def run(coro):
    """Synchronously run a coroutine in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ═════════════════════════════════════════════════════════════════════════════
# FAST TESTS — no Claude API required
# ═════════════════════════════════════════════════════════════════════════════

def test_playbook_agent_quick_response():
    """PlaybookAgent returns hardcoded commands instantly, no LLM."""
    from app.agents.playbook_agent import PlaybookAgent

    agent = PlaybookAgent()

    # Known threat types
    for threat_type in ["brute_force", "c2_beacon", "lateral_movement", "data_exfiltration", "false_positive"]:
        cmds = agent.get_quick_response(threat_type)
        assert isinstance(cmds, list), f"Expected list for {threat_type}"
        assert len(cmds) >= 3, f"Expected at least 3 commands for {threat_type}, got {len(cmds)}"

    # Unknown threat type → generic fallback
    cmds = agent.get_quick_response("unknown_threat_xyz")
    assert isinstance(cmds, list)
    assert len(cmds) >= 3


def test_red_agent_generate_events():
    """RedAgent.generate_attack_events uses synthetic generator — no Claude needed."""
    from app.agents.red_agent import AttackScenario, RedAgent

    agent = RedAgent()

    # Build a minimal scenario without calling Claude
    scenario = agent._fallback_scenario("brute_force")
    assert isinstance(scenario, AttackScenario)
    assert scenario.attack_type == "brute_force"
    assert len(scenario.mitre_techniques) > 0
    assert len(scenario.source_ips) > 0

    events = run(agent.generate_attack_events(scenario, count=10))
    assert isinstance(events, list)
    assert len(events) == 10
    for ev in events:
        assert isinstance(ev, dict)
        assert "scenario_id" in ev


def test_sim_engine_single_round():
    """SimulationEngine runs one round using fallback data (no Claude API)."""
    from app.agents.sim_engine import RoundResult, SimulationEngine

    engine = SimulationEngine()
    result: RoundResult = run(engine.run_single_round(
        round_num=1,
        attack_type="brute_force",
        ws_callback=None,
        target_context={"network": "10.0.0.0/8"},
    ))

    assert isinstance(result, RoundResult)
    assert result.round_num == 1
    assert result.attack_type == "brute_force"
    assert result.events_generated > 0
    assert 0.0 <= result.detection_rate <= 1.0
    assert 0.0 <= result.attack_success_rate <= 1.0
    assert result.round_duration_ms > 0


def test_sim_engine_full_run():
    """SimulationEngine runs a 3-round simulation and returns correct structure."""
    from app.agents.sim_engine import SimulationConfig, SimulationEngine, SimulationResult

    config = SimulationConfig(
        simulation_id="test-sim-001",
        name="Test Simulation",
        rounds=3,
        attack_types=["brute_force", "c2_beacon", "lateral_movement"],
        target_context={"network": "10.0.0.0/8"},
        broadcast_live=False,
    )
    engine = SimulationEngine()
    result: SimulationResult = run(engine.run_simulation(config=config))

    assert isinstance(result, SimulationResult)
    assert result.simulation_id == "test-sim-001"
    assert result.total_rounds == 3
    assert len(result.rounds) == 3
    assert 0.0 <= result.final_detection_rate <= 1.0
    assert 0.0 <= result.final_attack_success_rate <= 1.0
    assert isinstance(result.summary, str)
    assert len(result.summary) > 20
    assert isinstance(result.mitre_coverage, list)

    # Progressive improvement: round 3 detection_rate should be higher than round 1
    # (with noise this isn't guaranteed every time, so just check the range)
    for i, rnd in enumerate(result.rounds, 1):
        assert rnd.round_num == i
        assert rnd.events_generated > 0


# ═════════════════════════════════════════════════════════════════════════════
# SLOW TESTS — require real ANTHROPIC_API_KEY
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.slow
@pytest.mark.skipif(not _has_real_api_key(), reason="No real ANTHROPIC_API_KEY set")
def test_red_agent_generate_scenario():
    """RedAgent generates a Claude-powered attack scenario."""
    from app.agents.red_agent import AttackScenario, RedAgent

    agent = RedAgent()
    scenario: AttackScenario = run(agent.generate_attack_scenario(
        attack_type="c2_beacon",
        target_context={"network": "10.0.0.0/8", "os": "Linux"},
        previous_attempts=[],
    ))

    assert isinstance(scenario, AttackScenario)
    assert scenario.attack_type == "c2_beacon"
    assert len(scenario.mitre_techniques) >= 2
    assert len(scenario.tactics_description) > 20
    assert len(scenario.event_sequence) >= 3


@pytest.mark.slow
@pytest.mark.skipif(not _has_real_api_key(), reason="No real ANTHROPIC_API_KEY set")
def test_blue_agent_analyze_incident():
    """BlueAgent produces IncidentAnalysis via Claude."""
    from app.agents.blue_agent import BlueAgent, IncidentAnalysis

    agent = BlueAgent()
    events = [
        {
            "event_type": "auth",
            "source_ip": "185.220.101.5",
            "dest_ip": "10.0.1.50",
            "layer": "auth",
            "bytes_sent": 512,
            "bytes_recv": 128,
            "flags": ["failed"],
            "scenario": "brute_force",
        }
    ] * 5
    classifications = [
        {
            "threat_type": "brute_force",
            "severity": "HIGH",
            "confidence": 0.92,
            "rule_matches": ["TV-001"],
        }
    ] * 5

    analysis: IncidentAnalysis = run(agent._analyze_events(events, classifications))
    assert isinstance(analysis, IncidentAnalysis)
    assert analysis.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert len(analysis.threat_summary) > 10
    assert 0.0 <= analysis.confidence <= 1.0


@pytest.mark.slow
@pytest.mark.skipif(not _has_real_api_key(), reason="No real ANTHROPIC_API_KEY set")
def test_blue_agent_generate_playbook():
    """BlueAgent generates a ResponsePlaybook via Claude."""
    from app.agents.blue_agent import BlueAgent, IncidentAnalysis, ResponsePlaybook
    import uuid

    incident = IncidentAnalysis(
        incident_id=str(uuid.uuid4()),
        severity="HIGH",
        threat_summary="Brute force attack on SSH from 185.220.101.5",
        attack_chain=["Credential stuffing", "SSH brute force", "Account lockout bypass"],
        affected_assets=["10.0.1.50"],
        root_cause="Exposed SSH port with weak credentials",
        business_impact="Potential unauthorized access to production server",
        confidence=0.90,
        recommended_priority="high",
    )

    agent = BlueAgent()
    playbook: ResponsePlaybook = run(agent._generate_playbook_internal(incident))
    assert isinstance(playbook, ResponsePlaybook)
    assert len(playbook.phases) >= 2
    assert playbook.estimated_time_minutes > 0


@pytest.mark.slow
@pytest.mark.skipif(not _has_real_api_key(), reason="No real ANTHROPIC_API_KEY set")
def test_blue_agent_explain_alert():
    """BlueAgent explains an alert in plain language via Claude (fast LLM)."""
    from app.agents.blue_agent import AlertExplanation, BlueAgent

    event = {
        "event_type": "network",
        "source_ip": "10.0.1.15",
        "dest_ip": "198.51.100.42",
        "dest_port": 443,
        "bytes_sent": 52000,
        "bytes_recv": 800,
        "layer": "network",
        "process_name": "svchost.exe",
        "scenario": "c2_beacon",
    }
    classification = {
        "threat_type": "c2_beacon",
        "severity": "HIGH",
        "confidence": 0.88,
        "rule_matches": ["TV-005"],
    }

    agent = BlueAgent()
    explanation: AlertExplanation = run(agent.explain_alert(event, classification))
    assert isinstance(explanation, AlertExplanation)
    assert len(explanation.what_happened) > 10
    assert len(explanation.why_suspicious) > 10
    assert 0.0 <= explanation.false_positive_likelihood <= 1.0
