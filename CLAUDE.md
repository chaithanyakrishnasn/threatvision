# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Commands

### Development (local, requires Docker for infra)

```bash
# Start infrastructure only
docker compose up -d postgres redis chromadb

# Backend (from /backend)
pip install -e ".[dev]"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (from /frontend)
npm install && npm run dev

# One-command dev start (runs both in parallel)
make dev
```

### Seeding

```bash
cd backend
python -m app.data.seed_db           # 50 classified ThreatEvents + Incidents
python -m app.data.seed_analysts     # 5 analysts + 1 project + 8 demo tickets
```

### Testing

```bash
# Fast (no services needed — detection + agent logic)
cd backend && pytest tests/test_detection.py tests/test_agents.py -v

# All tests (requires PostgreSQL + Redis running)
cd backend && pytest tests/ -v

# Single test file
cd backend && pytest tests/test_detection.py -v

# Skip tests requiring Anthropic API key
cd backend && pytest tests/ -v -m "not slow"
```

`asyncio_mode = auto` is set in `pytest.ini` — do not use `asyncio.get_event_loop()` in tests.

### Full Docker stack

```bash
make docker-up    # builds + starts all 5 services
make docker-down
make docker-clean # also removes volumes
```

---

## Architecture

### Request lifecycle

```
HTTP POST /api/v1/ingestion/ingest
  → normalizer.normalize_event()          # format detection + enrichment
  → EventProducer.publish_batch()         # XADD to Redis Stream "threatvision:events"
  → EventConsumer._loop()                 # XREADGROUP, 100 msg/batch
  → classify_event(event_dict)            # ThreatClassifier pipeline (see below)
  → _persist_classification()             # writes ThreatEvent + Incident + optional Ticket
  → manager.broadcast_event("new_threat") # WebSocket push to all clients
```

### ThreatClassifier pipeline (9 steps, `detection/threat_classifier.py`)

1. Fast-path FP check — `known_asset + internal_destination + business_hours` → TV-012 suppression
2. `RuleEngine.evaluate()` → list of `RuleMatch` (TV-001…TV-012)
3. `AnomalyDetector.score()` → float [0,1] (IsolationForest, trained on 1000 synthetic benign events at startup)
4. `confidence = 0.7 × rule_score + 0.3 × anomaly_score`
5. `CorrelationEngine` → +0.15 boost if same source IP appears in 2+ layers in 5-min window
6. `_infer_threat_type()` → `brute_force | c2_beacon | lateral_movement | data_exfiltration | benign | false_positive`
7. Severity calculation (lateral_movement always HIGH/CRITICAL)
8. `MitreMapper.get_tactics/techniques()`
9. `_build_explanation()` + `_ACTIONS` lookup

### Auto-ticket threshold

`confidence > 0.85 AND severity in (HIGH, CRITICAL) AND not false_positive` → auto-creates a Ticket and assigns it to the best available analyst via `AnalystService`.

### Key singletons (module-level, use `get_X()` factories)

- `get_rule_engine()` — `RuleEngine` with 12 compiled matchers
- `get_detector()` — `AnomalyDetector` (IsolationForest, initialized at app startup)
- `get_classifier()` — `ThreatClassifier`
- `get_pipeline()` — `IngestionPipeline` (producer + consumer)
- `manager` — `ConnectionManager` WebSocket singleton (imported directly, no factory)

### DB session pattern

Always use `get_db` dependency injection in FastAPI routes. Never mix sync/async sessions. `get_db` commits on success, rolls back on exception.

### Adding a new API router

1. Create `backend/app/api/<name>.py` with `router = APIRouter()`
2. Register in `backend/app/api/__init__.py` with prefix and tag
3. Static paths must be registered **before** `/{id}` wildcard paths in the same router

### Adding a new model

1. Create `backend/app/models/<name>.py` extending `UUIDMixin, TimestampMixin, Base`
2. Import and add to `__all__` in `backend/app/models/__init__.py`
3. `init_db()` calls `Base.metadata.create_all` — the model is auto-created on next startup

### Audit logging

Every significant mutation should call `audit_service.log_event(...)` as a fire-and-forget background task. The service maintains a SHA-256 hash chain (serialized via `asyncio.Lock`). Only non-benign detections are logged from the hot ingestion path to avoid flooding at 600+ EPS.

### Frontend state

- All shared state lives in Zustand: `src/lib/store.ts` (`useStore()` hook)
- WebSocket: `getWsClient()` singleton in `src/lib/websocket.ts` with exponential backoff reconnect
- All API calls in `src/lib/api.ts`, organized by domain (`dashboardApi`, `incidentsApi`, etc.)
- All TypeScript types in `src/types/index.ts` — single source of truth

---

## Critical constraints

- **`psycopg2-binary` is NOT installed** — always use async SQLAlchemy (`asyncpg`) in FastAPI code
- **Incident severity is lowercase** (`"critical"`, `"high"`); **Ticket severity is uppercase** (`"CRITICAL"`, `"HIGH"`)
- **Never change** confidence weights (`_RULE_WEIGHT = 0.7`, `_ANOMALY_WEIGHT = 0.3`, `_CROSS_LAYER_BOOST = 0.15`) or any detection rule scores — demo incidents are pre-tuned to these values
- **Never change** `SLA_HOURS` in `ticket_service.py` or Redis keys (`"threatvision:events"`, `"threatvision-consumers"`)
- **All Claude calls** (BlueAgent, RedAgent, PlaybookAgent) must have `try/except` with a meaningful fallback — the service must not crash when `ANTHROPIC_API_KEY` is absent
- **Playbook + simulation stores are in-memory** (`dict` at module level) — this is intentional; do not add DB persistence without explicit instruction
- ChromaDB host port is **8001** (container is 8000) — agents fall back to `EphemeralClient()` when unreachable

---

## Project context

Read `PROJECT_BRAIN.md` for complete module-by-module documentation, the full DB schema, all 12 detection rules, demo analyst profiles, and the agent handoff log tracking what each AI agent has built.
