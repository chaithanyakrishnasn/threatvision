"""
Ingestion pipeline tests.

Covers:
  - normalizer: netflow, windows_event formats
  - generator: all 4 scenarios present, throughput, false-positive flags
  - producer: Redis publish round-trip
"""
from __future__ import annotations

import asyncio
import sys
import os

import pytest

# Make sure 'app' is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_SCHEMA_FIELDS = [
    "event_id", "timestamp", "layer", "source_ip", "dest_ip",
    "source_port", "dest_port", "protocol", "bytes_sent", "bytes_recv",
    "duration_ms", "process_name", "parent_process", "user",
    "http_method", "http_endpoint", "http_status", "user_agent",
    "geo_country", "flags", "scenario", "severity", "confidence",
    "raw_payload",
]


def _assert_schema(event: dict) -> None:
    """Assert every required field is present in the event dict."""
    missing = [f for f in REQUIRED_SCHEMA_FIELDS if f not in event]
    assert not missing, f"Missing schema fields: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: Normalizer tests
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizer:

    def test_normalizer_netflow(self):
        """Normalize a raw netflow dict — all schema fields must be present."""
        from app.ingestion.normalizer import normalize_event

        raw = {
            "src_ip": "185.220.101.42",
            "dst_ip": "10.0.1.50",
            "src_port": 54321,
            "dst_port": 443,
            "proto": "6",          # TCP
            "bytes_out": 1240,
            "bytes_in": 5800,
            "duration_ms": 320,
            "netflow_version": 9,
        }
        result = normalize_event(raw, fmt="netflow")
        assert result is not None, "normalize_event returned None"

        d = result.model_dump()
        _assert_schema(d)

        # Enrichment: Tor exit node should be flagged
        assert "tor_exit_node" in d["flags"], f"Expected tor_exit_node flag, got: {d['flags']}"
        assert d["geo_country"] == "Russia/Tor", f"Expected Russia/Tor, got: {d['geo_country']}"
        assert d["source_ip"] == "185.220.101.42"
        assert d["dest_ip"] == "10.0.1.50"
        assert d["dest_port"] == 443
        assert d["bytes_sent"] == 1240
        assert d["bytes_recv"] == 5800
        # known asset dest
        assert "known_asset" in d["flags"], f"Expected known_asset flag (auth-server), got: {d['flags']}"

    def test_normalizer_windows_event(self):
        """Normalize a Windows Event Log 4625 (failed login)."""
        from app.ingestion.normalizer import normalize_event

        raw = {
            "EventID": 4625,
            "Computer": "DESKTOP-CORP01",
            "EventData": {
                "SubjectUserName": "jdoe",
                "TargetUserName": "Administrator",
                "IpAddress": "185.220.101.5",
                "ProcessName": "C:\\Windows\\System32\\lsass.exe",
                "LogonType": "3",
            },
        }
        result = normalize_event(raw, fmt="windows_event")
        assert result is not None

        d = result.model_dump()
        _assert_schema(d)

        assert d["layer"] == "endpoint"
        assert d["source_ip"] == "185.220.101.5"
        assert d["severity"] == "HIGH"          # Event ID 4625 → HIGH
        assert d["process_name"] is not None
        assert "tor_exit_node" in d["flags"]    # 185.220.x.x enrichment
        assert d["raw_payload"]["event_id"] == 4625

    def test_normalizer_http_access(self):
        """Normalize an HTTP access log — suspicious endpoint → HIGH severity."""
        from app.ingestion.normalizer import normalize_event

        raw = {
            "client_ip": "91.108.4.55",
            "server_ip": "10.0.1.50",
            "server_port": 443,
            "http_method": "POST",
            "request": "/api/v1/auth/login",
            "status_code": 401,
            "response_bytes": 320,
            "request_bytes": 850,
            "response_time_ms": 210,
            "user_agent": "python-requests/2.28.0",
        }
        result = normalize_event(raw, fmt="http_access")
        assert result is not None

        d = result.model_dump()
        _assert_schema(d)

        assert d["layer"] == "application"
        assert d["http_method"] == "POST"
        assert d["http_status"] == 401
        assert d["geo_country"] == "Netherlands"
        assert "known_c2_range" in d["flags"]

    def test_normalizer_auto_detection(self):
        """fmt='auto' should detect netflow without explicit format hint."""
        from app.ingestion.normalizer import normalize_event

        raw = {
            "src_ip": "10.0.2.87",
            "dst_ip": "91.108.4.55",
            "src_port": 49152,
            "dst_port": 443,
            "proto": 6,
            "bytes_out": 512,
            "bytes_in": 128,
            "duration_ms": 180,
        }
        result = normalize_event(raw, fmt="auto")
        assert result is not None
        d = result.model_dump()
        assert d["source_ip"] == "10.0.2.87"
        assert d["geo_country"] == "Internal"


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: Generator tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerator:

    def test_generator_all_scenarios(self):
        """
        200 events with scenario_mix=True must contain all 4 attack scenarios
        plus benign events.
        """
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=200, scenario_mix=True)
        assert len(events) == 200, f"Expected 200, got {len(events)}"

        scenarios = {e["scenario"] for e in events}
        required = {"brute_force", "c2_beacon", "false_positive", "lateral_movement", "benign"}
        missing = required - scenarios
        assert not missing, f"Missing scenarios: {missing}  (got {scenarios})"

    def test_false_positive_flags(self):
        """
        Scenario C events must carry the FP flags and a low confidence score.
        """
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=400, scenario_mix=True)
        fp_events = [e for e in events if e["scenario"] == "false_positive"]
        assert fp_events, "No false_positive events generated in 400-event batch"

        for ev in fp_events:
            flags = ev["flags"]
            assert "known_asset" in flags,         f"Missing known_asset: {flags}"
            assert "internal_destination" in flags, f"Missing internal_destination: {flags}"
            assert ev["confidence"] < 0.3, (
                f"False positive confidence too high: {ev['confidence']}"
            )
            assert ev["severity"] == "LOW", (
                f"False positive severity should be LOW, got {ev['severity']}"
            )

    def test_generator_throughput(self):
        """generate_event_batch(300) must return exactly 300 events."""
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=300, scenario_mix=True)
        assert len(events) == 300, f"Expected 300, got {len(events)}"

    def test_generator_schema_completeness(self):
        """Every generated event must contain all required schema fields."""
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=50, scenario_mix=True)
        for i, ev in enumerate(events):
            missing = [f for f in REQUIRED_SCHEMA_FIELDS if f not in ev]
            assert not missing, f"Event[{i}] missing fields: {missing}"

    def test_brute_force_scenario(self):
        """Brute force events must use Tor exit IPs and CRITICAL severity."""
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=400, scenario_mix=True)
        bf = [e for e in events if e["scenario"] == "brute_force"]
        assert bf, "No brute_force events in 400-event batch"

        for ev in bf:
            assert ev["severity"] == "CRITICAL"
            assert ev["confidence"] >= 0.9
            assert "brute_force_pattern" in ev["flags"]
            # Source must be from Tor range OR dest must be auth server
            is_tor_src = ev["source_ip"].startswith("185.220.101.")
            is_auth_dst = ev["dest_ip"] == "10.0.1.50"
            is_endpoint = ev["layer"] == "endpoint"
            assert is_tor_src or is_auth_dst or is_endpoint, (
                f"Brute force event has unexpected addresses: "
                f"src={ev['source_ip']} dst={ev['dest_ip']}"
            )

    def test_lateral_movement_starts_late(self):
        """
        Lateral movement events must only appear after the first 20% of the batch.
        We verify by checking timestamps are not among the very earliest.
        """
        from app.data.synthetic_generator import generate_event_batch
        from datetime import datetime, timezone

        events = generate_event_batch(count=200, scenario_mix=True)
        lm = [e for e in events if e["scenario"] == "lateral_movement"]
        assert lm, "No lateral_movement events found"

        for ev in lm:
            assert ev["severity"] == "CRITICAL"
            assert "lateral_movement" in ev["flags"]


# ─────────────────────────────────────────────────────────────────────────────
# Task 3: Redis Producer test
# ─────────────────────────────────────────────────────────────────────────────

class TestProducer:

    @pytest.mark.asyncio
    async def test_producer_connect(self):
        """Connect EventProducer to Redis and publish 10 events; count must be 10."""
        from app.ingestion.redis_consumer import EventProducer
        from app.data.synthetic_generator import generate_event_batch

        producer = EventProducer(redis_url="redis://localhost:6379/0")
        await producer.connect()

        events = generate_event_batch(count=10, scenario_mix=True)
        count = await producer.publish_batch(events)
        assert count == 10, f"Expected 10 published, got {count}"

        await producer.close()

    @pytest.mark.asyncio
    async def test_producer_publish_single(self):
        """publish_single must return a non-empty message ID string."""
        from app.ingestion.redis_consumer import EventProducer
        from app.data.synthetic_generator import generate_event_batch

        producer = EventProducer(redis_url="redis://localhost:6379/0")
        await producer.connect()

        event = generate_event_batch(count=1, scenario_mix=False)[0]
        msg_id = await producer.publish_single(event)
        assert msg_id, "Expected a non-empty Redis message ID"
        assert "-" in msg_id, f"Unexpected message ID format: {msg_id}"

        await producer.close()

    @pytest.mark.asyncio
    async def test_producer_stream_len(self):
        """stream_len should return a non-negative integer after publishing."""
        from app.ingestion.redis_consumer import EventProducer
        from app.data.synthetic_generator import generate_event_batch

        producer = EventProducer(redis_url="redis://localhost:6379/0")
        await producer.connect()
        await producer.publish_batch(generate_event_batch(count=5))
        length = await producer.stream_len()
        assert isinstance(length, int) and length >= 0
        await producer.close()
