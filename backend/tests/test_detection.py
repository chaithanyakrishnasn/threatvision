"""
Threat Detection Engine tests — Phase 2.

Covers:
  - ThreatClassifier: brute_force, C2, false_positive, lateral_movement
  - RuleEngine: TV-001, TV-012
  - AnomalyDetector: training + scoring
  - MitreMapper: brute_force mapping
  - CorrelationEngine: cross-layer detection
  - API: /demo-classify endpoint
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Fixtures / shared test events ─────────────────────────────────────────────

def _brute_force_event() -> dict:
    return {
        "event_id": "test-bf-001",
        "timestamp": "2024-01-15T10:30:00Z",
        "layer": "network",
        "source_ip": "185.220.101.42",   # Tor range → TV-001 + TV-008
        "dest_ip": "10.0.1.50",          # internal auth server
        "source_port": 54321,
        "dest_port": 443,
        "protocol": "HTTPS",
        "bytes_sent": 12,                # tiny — very anomalous vs benign baseline
        "bytes_recv": 0,                 # zero — even more anomalous
        "duration_ms": 80,
        "process_name": None,
        "parent_process": None,
        "user": "admin1",
        "http_method": "POST",
        "http_endpoint": "/api/v1/auth/login",
        "http_status": 401,
        "user_agent": "python-requests/2.28.0",
        "geo_country": "Russia/Tor",
        "flags": ["brute_force_pattern", "credential_stuffing", "tor_exit_node"],
        "scenario": "brute_force",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "raw_payload": {"attempt_number": 8, "tor_exit": True},
    }


def _c2_beacon_event() -> dict:
    return {
        "event_id": "test-c2-001",
        "timestamp": "2024-01-15T11:00:00Z",
        "layer": "network",
        "source_ip": "10.0.2.87",
        "dest_ip": "91.108.4.55",        # external C2
        "source_port": 49200,
        "dest_port": 443,
        "protocol": "HTTPS",
        "bytes_sent": 350,
        "bytes_recv": 80,                # very small — anomalous vs benign
        "duration_ms": 210,
        "process_name": "svchost.exe",
        "parent_process": "services.exe",
        "user": "SYSTEM",
        "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
        "geo_country": "Netherlands",
        "flags": ["c2_beacon", "self_signed_cert", "periodic_connection"],
        "scenario": "c2_beacon",
        "severity": "HIGH",
        "confidence": 0.91,
        "raw_payload": {
            "beacon_number": 5,
            "jitter_seconds": 50.3,
            "ssl_cert_self_signed": True,
        },
    }


def _false_positive_event() -> dict:
    return {
        "event_id": "test-fp-001",
        "timestamp": "2024-01-15T09:30:00Z",
        "layer": "network",
        "source_ip": "10.0.1.25",       # admin workstation
        "dest_ip": "10.0.50.100",        # internal NAS
        "source_port": 51000,
        "dest_port": 445,
        "protocol": "SMB",
        "bytes_sent": 524288000,
        "bytes_recv": 2048,
        "duration_ms": 600000,
        "process_name": "robocopy.exe",
        "parent_process": "taskeng.exe",
        "user": "backup_svc",
        "geo_country": "Internal",
        "flags": ["known_asset", "internal_destination", "business_hours", "backup_schedule"],
        "scenario": "false_positive",
        "severity": "LOW",
        "confidence": 0.15,             # below 0.2 threshold → FP
        "raw_payload": {"scheduled_task": "DailyBackup", "asset_tag": "ADMIN-WS-001"},
    }


def _lateral_movement_event() -> dict:
    return {
        "event_id": "test-lm-001",
        "timestamp": "2024-01-15T14:00:00Z",
        "layer": "network",
        "source_ip": "10.0.2.87",       # internal compromised host
        "dest_ip": "10.0.1.100",         # internal target
        "source_port": 48500,
        "dest_port": 445,                # SMB
        "protocol": "SMB",
        "bytes_sent": 4096,
        "bytes_recv": 2048,
        "duration_ms": 800,
        "process_name": "net.exe",
        "parent_process": "cmd.exe",
        "user": "CORP\\svc_backup",
        "geo_country": "Internal",
        "flags": ["lateral_movement", "smb_traversal", "credential_dumping"],
        "scenario": "lateral_movement",
        "severity": "CRITICAL",
        "confidence": 0.93,
        "raw_payload": {"share": "ADMIN$", "mitre": "T1021.002"},
    }


# ── ThreatClassifier tests ────────────────────────────────────────────────────

class TestThreatClassifier:

    def test_classify_brute_force(self):
        """Brute-force event must classify correctly with confidence > 0.8."""
        from app.detection.threat_classifier import classify_event

        result = classify_event(_brute_force_event())

        assert result.threat_type == "brute_force", (
            f"Expected brute_force, got {result.threat_type}"
        )
        assert result.confidence > 0.8, (
            f"Expected confidence > 0.8, got {result.confidence}"
        )
        assert result.is_false_positive is False
        assert result.severity in ("HIGH", "CRITICAL")

    def test_classify_c2_beacon(self):
        """C2 event must have MITRE technique T1071 in mitre_techniques list."""
        from app.detection.threat_classifier import classify_event

        result = classify_event(_c2_beacon_event())

        assert result.threat_type == "c2_beacon", (
            f"Expected c2_beacon, got {result.threat_type}"
        )
        # Check T1071 prefix appears in at least one listed technique
        has_t1071 = any("T1071" in t for t in result.mitre_techniques)
        assert has_t1071, (
            f"T1071 not found in mitre_techniques: {result.mitre_techniques}"
        )

    def test_classify_false_positive(self):
        """Scenario C event must be identified as a false positive."""
        from app.detection.threat_classifier import classify_event

        result = classify_event(_false_positive_event())

        assert result.is_false_positive is True, (
            f"Expected is_false_positive=True, confidence={result.confidence}"
        )
        assert result.threat_type == "false_positive"
        assert result.severity == "LOW"

    def test_classify_lateral_movement(self):
        """Lateral movement event must have severity=CRITICAL."""
        from app.detection.threat_classifier import classify_event

        result = classify_event(_lateral_movement_event())

        assert result.threat_type == "lateral_movement", (
            f"Expected lateral_movement, got {result.threat_type}"
        )
        assert result.severity == "CRITICAL", (
            f"Expected CRITICAL severity, got {result.severity}"
        )


# ── RuleEngine tests ──────────────────────────────────────────────────────────

class TestRuleEngine:

    def test_rule_engine_tv001(self):
        """TV-001 must fire on a brute-force event and return score=0.90."""
        from app.detection.rule_engine import get_rule_engine

        engine = get_rule_engine()
        matches = engine.evaluate(_brute_force_event())

        rule_ids = [m.rule_id for m in matches]
        assert "TV-001" in rule_ids, f"TV-001 did not fire; matched: {rule_ids}"

        tv001 = next(m for m in matches if m.rule_id == "TV-001")
        assert tv001.score == 0.90
        assert tv001.threat_type == "brute_force"

    def test_rule_engine_tv012(self):
        """TV-012 suppressor must fire on false-positive event with score=0.0."""
        from app.detection.rule_engine import get_rule_engine

        engine = get_rule_engine()
        matches = engine.evaluate(_false_positive_event())

        rule_ids = [m.rule_id for m in matches]
        assert "TV-012" in rule_ids, f"TV-012 did not fire; matched: {rule_ids}"

        tv012 = next(m for m in matches if m.rule_id == "TV-012")
        assert tv012.score == 0.0, f"TV-012 score should be 0.0, got {tv012.score}"


# ── AnomalyDetector tests ─────────────────────────────────────────────────────

class TestAnomalyDetector:

    def test_anomaly_detector_training(self):
        """Training on 500 events must set is_trained=True."""
        from app.detection.anomaly_detector import AnomalyDetector
        from app.data.synthetic_generator import generate_event_batch

        detector = AnomalyDetector()
        assert detector.is_trained is False

        events = generate_event_batch(count=500, scenario_mix=False)
        detector.train(events)

        assert detector.is_trained is True, "Detector should be trained after train()"

    def test_anomaly_score_malicious(self):
        """C2 beacon event with tiny bytes_recv must score > 0.5 anomaly."""
        from app.detection.anomaly_detector import AnomalyDetector
        from app.data.synthetic_generator import generate_event_batch

        detector = AnomalyDetector()
        baseline = generate_event_batch(count=500, scenario_mix=False)
        detector.train(baseline)

        # Event with extremely small bytes relative to benign baseline
        malicious = {
            **_c2_beacon_event(),
            "bytes_recv": 80,    # benign avg ~32000
            "bytes_sent": 300,
        }
        score = detector.score(malicious)
        assert score > 0.5, f"Expected anomaly score > 0.5 for C2 event, got {score}"


# ── MitreMapper tests ─────────────────────────────────────────────────────────

class TestMitreMapper:

    def test_mitre_mapper(self):
        """brute_force mapping must contain T1110 in techniques."""
        from app.detection.mitre_mapper import get_mitre_mapper

        mapper = get_mitre_mapper()
        techniques = mapper.get_techniques("brute_force")
        tactics = mapper.get_tactics("brute_force")

        has_t1110 = any("T1110" in t for t in techniques)
        assert has_t1110, f"T1110 not in brute_force techniques: {techniques}"
        assert len(tactics) > 0, "brute_force should have at least one tactic"


# ── CorrelationEngine tests ───────────────────────────────────────────────────

class TestCorrelationEngine:

    def test_correlation_engine(self):
        """
        Adding a network event then an endpoint event from the same source IP
        must return correlated=True.
        """
        from app.detection.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()

        network_event = {
            "event_id": "corr-net-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.2.87",
            "layer": "network",
            "flags": [],
        }
        endpoint_event = {
            "event_id": "corr-ep-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.2.87",   # same source IP
            "layer": "endpoint",
            "flags": [],
        }

        engine.add_event(network_event)
        is_correlated, ids = engine.check_correlation(endpoint_event)

        assert is_correlated is True, (
            "Expected cross-layer correlation for same source_ip in network+endpoint"
        )
        assert "corr-net-001" in ids, f"Expected corr-net-001 in correlated IDs: {ids}"


# ── API endpoint tests ────────────────────────────────────────────────────────

class TestDemoClassifyEndpoint:

    def test_demo_classify_endpoint(self):
        """POST /api/v1/threats/demo-classify must return 500 classified results."""
        # Use a minimal app with only the threats router to avoid DB/Redis lifespan
        from fastapi import FastAPI
        from fastapi.testclient import TestClient as _Client
        from app.api.threats import router

        mini_app = FastAPI()
        mini_app.include_router(router, prefix="/api/v1/threats")

        client = _Client(mini_app)
        response = client.post("/api/v1/threats/demo-classify")

        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text[:500]}"
        )
        data = response.json()

        assert data["total_classified"] == 500, (
            f"Expected 500 results, got {data['total_classified']}"
        )
        assert "summary" in data
        assert "by_threat_type" in data["summary"]
        assert "sample_results" in data
        assert len(data["sample_results"]) == 20
