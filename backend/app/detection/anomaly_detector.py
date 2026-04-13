"""
Anomaly detection using IsolationForest.
Trained on synthetic benign baseline data at startup.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import structlog

logger = structlog.get_logger(__name__)

KNOWN_PORTS = {80, 443, 22, 53, 25, 123, 3306, 5432}


class AnomalyDetector:
    feature_names = [
        "bytes_sent",
        "bytes_recv",
        "duration_ms",
        "source_port",
        "dest_port",
        "hour_of_day",
        "is_external_dest",
        "is_known_port",
    ]

    def __init__(self) -> None:
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    # ── Feature extraction ─────────────────────────────────────────────────────

    def _extract_features(self, event: dict) -> np.ndarray:
        bytes_sent = float(event.get("bytes_sent") or 0)
        bytes_recv = float(event.get("bytes_recv") or 0)
        duration_ms = float(event.get("duration_ms") or 0)
        source_port = float(event.get("source_port") or 0)
        dest_port_val = int(event.get("dest_port") or 0)

        # Parse hour from timestamp string or datetime
        ts = event.get("timestamp")
        try:
            if isinstance(ts, str):
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
            elif isinstance(ts, datetime):
                hour = ts.hour
            else:
                hour = datetime.now(timezone.utc).hour
        except Exception:
            hour = datetime.now(timezone.utc).hour

        dest_ip = event.get("dest_ip") or ""
        is_external = 0.0
        if not (
            dest_ip.startswith("10.")
            or dest_ip.startswith("192.168.")
            or dest_ip.startswith("172.")
        ):
            is_external = 1.0

        is_known = 1.0 if dest_port_val in KNOWN_PORTS else 0.0

        features = np.array([
            math.log1p(bytes_sent),
            math.log1p(bytes_recv),
            math.log1p(duration_ms),
            source_port,
            float(dest_port_val),
            float(hour),
            is_external,
            is_known,
        ])
        return features.reshape(1, -1)

    def _extract_features_batch(self, events: list[dict]) -> np.ndarray:
        return np.vstack([self._extract_features(e) for e in events])

    # ── Training ───────────────────────────────────────────────────────────────

    def train(self, events: list[dict]) -> None:
        """Train on a list of event dicts."""
        if not events:
            logger.warning("anomaly_detector_no_data")
            return
        X = self._extract_features_batch(events)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        logger.info(
            "anomaly_detector_trained",
            n_samples=len(events),
            features=self.feature_names,
        )

    def train_on_baseline(self) -> None:
        """Generate 1 000 benign events from synthetic generator and train."""
        from app.data.synthetic_generator import generate_event_batch

        events = generate_event_batch(count=1000, scenario_mix=False)
        self.train(events)
        logger.info("anomaly_detector_baseline_complete", n_samples=len(events))

    # ── Scoring ────────────────────────────────────────────────────────────────

    def score(self, event: dict) -> float:
        """
        Returns anomaly score in [0, 1].
        1.0 = most anomalous.  Trains on baseline first if not yet trained.
        """
        if not self.is_trained:
            self.train_on_baseline()
        try:
            X = self._extract_features(event)
            X_scaled = self.scaler.transform(X)
            # score_samples: lower (more negative) = more anomalous
            raw = self.model.score_samples(X_scaled)[0]
            # Normalize: raw typically in [-0.6, 0.1]; clamp to [0, 1]
            # More negative raw → higher anomaly score
            normalized = float(np.clip((-raw - 0.0) / 0.6, 0.0, 1.0))
            return round(normalized, 4)
        except Exception as exc:
            logger.warning("anomaly_score_error", error=str(exc))
            return 0.0

    def is_anomaly(self, event: dict, threshold: float = 0.5) -> bool:
        return self.score(event) >= threshold


# ── Singleton ─────────────────────────────────────────────────────────────────

_detector: Optional[AnomalyDetector] = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        _detector.train_on_baseline()
    return _detector
