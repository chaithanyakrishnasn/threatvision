# SentinelAI — Project Brain
> Active working context only. For full history see PROJECT_LOGS.md. For architecture see ARCHITECTURE.md.

---

## Current Phase
**Phase 6 — Audit Logger & Actionable Metrics**

Backend complete. Audit log viewer UI built. Metric drilldown API built. MetricDetailModal stabilized.

## Current Task
Metric drilldown frontend is stable. Next: proceed to Phase 7 (Sandbox Engine) or polish Phase 6 frontend.

## Current Owner
Handoff — available for next agent.

---

## System Snapshot

Full-stack SOC platform. FastAPI backend + Next.js 14 frontend. PostgreSQL + Redis + ChromaDB.
12 Sigma-style detection rules + IsolationForest anomaly detection. Claude AI agents (Blue/Red/Playbook).
Audit system with SHA-256 hash chain. Analyst + ticket engine with SLA enforcement.
Live WebSocket dashboard. 600+ EPS ingestion capacity.

**Ports:** Backend 8000 · Frontend 3000 · PostgreSQL 5432 · Redis 6379 · ChromaDB 8001

---

## Active Features (Phase 6)

- `GET /api/v1/audit/logs` — paginated audit log with filters (actor_type, action, target_type)
- `GET /api/v1/audit/logs/search` — ILIKE search on reasoning + metadata
- `GET /api/v1/audit/verify` — SHA-256 hash-chain integrity check
- `GET /api/v1/dashboard/metric-details?type=<metric>` — drilldown for: `events`, `threats`, `critical`, `false_positive`, `detection_rate`, `confidence`
- Audit log viewer page with WebSocket streaming, filters, search, detail panel
- MetricDetailModal (frontend) — fetches metric-details on card click, stable useEffect

---

## Critical Constraints

1. **Severity casing:** Incident severity is **lowercase** (`critical`, `high`). Ticket severity is **UPPERCASE** (`CRITICAL`, `HIGH`).
2. **Never change** `_RULE_WEIGHT=0.7`, `_ANOMALY_WEIGHT=0.3`, `_CROSS_LAYER_BOOST=0.15` — demo incidents are tuned to these.
3. **Never change** `SLA_HOURS` in `ticket_service.py` or Redis keys (`"threatvision:events"`, `"threatvision-consumers"`).
4. **Never change** any detection rule scores (TV-001 to TV-012).
5. **Never change** Tailwind color tokens in `tailwind.config.js`.
6. **All Claude calls** need `try/except` with a meaningful fallback — service must not crash without API key.
7. **Static API paths** must be registered before `/{id}` wildcard paths in the same router.
8. **No sync DB calls** in FastAPI routes — always use asyncpg via SQLAlchemy async.
9. **Auto-ticket threshold:** confidence > 0.85 AND severity HIGH/CRITICAL AND not false_positive.
10. **ChromaDB port:** host=8001, container=8000 — agents fall back to `EphemeralClient()` when unreachable.
11. **Playbook + simulation stores are in-memory** (module-level dicts) — intentional, do not add DB persistence.
12. When adding a new router: register in `backend/app/api/__init__.py`. When adding a new model: register in `backend/app/models/__init__.py`.

---

## Known Issues

- `raw_log` JSON flag queries for TV-012 conditions (`known_asset`, `internal_destination`, `business_hours`) fall back to 0 if raw_log is unpopulated — non-fatal, logged as WARNING.
- Audit hash chain uses in-memory `asyncio.Lock` — not safe for horizontal scaling (single-instance only).
- Confidence breakdown rule vs anomaly split is approximate (`is_anomaly=True` count used as proxy).
- Anomaly detector trains on 1000 *synthetic* benign events — not real traffic baselines.
- JWT auth is configured but not enforced on any route.
- `psycopg2-binary` is NOT installed — never use sync psycopg2 in FastAPI code.

---

## Next Step

**Option A (Phase 6 Polish):** Add pagination/virtualization to audit log viewer for large streams.

**Option B (Phase 7):** Begin Sandbox Environment Engine — `SandboxManager` class in `backend/app/sandbox/manager.py` using Python Docker SDK. Targets: DVWA, Juice Shop, vulnerable Flask API. Network isolation required.

---

## Reference Files

| File | Purpose |
|---|---|
| `ARCHITECTURE.md` | Full stack, detection pipeline, agents, schema, API list |
| `PROJECT_LOGS.md` | All agent handoff logs, build history, decisions |
| `CLAUDE.md` | Commands (build/test/seed), coding rules for Claude Code |
| `backend/app/api/dashboard.py` | Metric drilldown implementation |
| `backend/app/services/audit_service.py` | Hash-chain audit logger |
| `backend/app/detection/threat_classifier.py` | 9-step classification pipeline |
| `backend/app/services/ticket_service.py` | SLA_HOURS, ticket lifecycle |

## Execution State

- Active Phase: Phase 6 — Audit Logger
- Current Task: Metrics System Complete
- Current Owner: None (Ready for next phase)
- System Status: Stable

## Active Interfaces

### Backend APIs
- /api/v1/dashboard/metrics
- /api/v1/dashboard/metric-details
- /api/v1/audit/logs

### WebSocket Events
- new_threat
- new_audit_log