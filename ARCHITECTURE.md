# ARCHITECTURE.md
> Stable system design reference for ThreatVision / SentinelAI.
> Update when architecture changes. Not a log — no dated entries.

---

## Stack

### Backend
| Package | Version | Purpose |
|---|---|---|
| fastapi | 0.135.3 | Async web framework, REST + WebSocket |
| uvicorn | 0.44.0 | ASGI server |
| sqlalchemy | 2.0.49 | Async ORM (asyncpg driver) |
| asyncpg | ≥0.29 | Async PostgreSQL driver |
| redis | 7.4.0 | Streams-based event queue |
| langchain | 1.2.15 | LLM orchestration |
| langchain-anthropic | via langchain | Claude integration |
| anthropic | 0.94.0 | Anthropic SDK |
| chromadb | 1.5.7 | Vector DB for agent memory |
| scikit-learn | 1.8.0 | IsolationForest anomaly detection |
| structlog | 25.5.0 | Structured logging |
| pydantic | 2.12.5 | Data validation |
| alembic | 1.18.4 | DB migrations |

**Python:** ≥3.11. `psycopg2-binary` is NOT installed — use asyncpg only.

### Frontend
| Package | Version | Purpose |
|---|---|---|
| next | 14.2.3 | React framework (App Router) |
| react | 18.3.1 | UI library |
| tailwindcss | 3.4.4 | Utility CSS |
| recharts | 2.12.7 | Charts (ThreatTimeline, simulation) |
| framer-motion | 11.2.12 | Animations |
| zustand | 4.5.4 | Global state |
| axios | 1.7.2 | HTTP client |
| socket.io-client | 4.7.5 | WebSocket (alongside native WS) |
| lucide-react | 0.395.0 | Icons |

### Infrastructure
| Service | Image | Port | Purpose |
|---|---|---|---|
| PostgreSQL | postgres:16-alpine | 5432 | Primary database |
| Redis | redis:7-alpine | 6379 | Event stream queue |
| ChromaDB | chromadb/chroma:latest | 8001 host → 8000 container | Agent vector memory |
| Backend | ./backend Dockerfile | 8000 | FastAPI app |
| Frontend | ./frontend Dockerfile | 3000 | Next.js app |

### External APIs
- `claude-opus-4-5` — BlueAgent (analysis + playbooks), RedAgent, PlaybookAgent (max_tokens 2000–3000)
- `claude-haiku-4-5-20251001` — BlueAgent fast_llm for triage (max_tokens 600)

---

## Ingestion Pipeline

```
Raw Log (netflow / windows_event / http_access / unified)
  ↓
POST /api/v1/ingestion/ingest  OR  IngestionPipeline.ingest_events()
  ↓
normalizer.normalize_event()       ← format detection + enrichment (GeoIP, threat-intel flags, asset labels)
  ↓  NormalizedEvent (Pydantic)
EventProducer.publish_batch()      → Redis Stream: "threatvision:events" (XADD, pipelined)
  ↓
EventConsumer._loop()              ← XREADGROUP, 100 msgs/batch, 1000ms block
  ↓
classify_event(event_dict)         → ThreatClassifier (see below)
  ↓  ThreatClassificationResult
_persist_classification()          → PostgreSQL:
  - Always writes ThreatEvent row
  - If is_threat AND confidence > 0.30 → also writes Incident row
  - If confidence > 0.85 AND severity HIGH/CRITICAL AND not FP → auto-creates Ticket
  ↓
WebSocket broadcast: "new_threat"  → all connected WS clients
```

**Redis keys:**
- Stream: `"threatvision:events"`
- Consumer group: `"threatvision-consumers"`
- DLQ: `"threatvision:dlq"`

**Throughput:** 600+ events/sec in stress-test mode.

---

## Detection Pipeline

### ThreatClassifier — 9-step pipeline (`detection/threat_classifier.py`)

1. **Fast-path FP check** — `known_asset + internal_destination + business_hours` → TV-012 suppression (score 0.00, no incident created)
2. **RuleEngine.evaluate()** → list of `RuleMatch` objects (TV-001…TV-012)
3. **AnomalyDetector.score()** → float [0,1] (IsolationForest, trained on 1000 synthetic benign events at startup)
4. **Combine:** `confidence = 0.7 × rule_score + 0.3 × anomaly_score`
5. **CorrelationEngine** — +0.15 boost if same source IP appears in 2+ distinct layers in 5-minute window
6. **_infer_threat_type()** → `brute_force | c2_beacon | lateral_movement | data_exfiltration | benign | false_positive`
7. **Severity** — lateral_movement always HIGH/CRITICAL; otherwise derived from confidence thresholds (CRITICAL≥0.88, HIGH≥0.65, MEDIUM≥0.40)
8. **MitreMapper** — tactic/technique mappings per threat_type
9. **_build_explanation() + _ACTIONS** — human-readable explanation + recommended action

**Weights (do not change — demo tuned):**
- `_RULE_WEIGHT = 0.7`
- `_ANOMALY_WEIGHT = 0.3`
- `_CROSS_LAYER_BOOST = 0.15`

### Detection Rules (TV-001 to TV-012)

| Rule ID | Name | Severity | Threat Type | MITRE | Score | Trigger |
|---|---|---|---|---|---|---|
| TV-001 | Brute Force Auth | HIGH | brute_force | T1110.001 | 0.90 | dest_port in [443,22] + 185.220.0.0/16 + brute_force/credential_stuffing flag |
| TV-002 | C2 Beacon Pattern | HIGH | c2_beacon | T1071.001 | 0.88 | periodic_connection + self_signed_cert + bytes_sent < 1000 + external dest |
| TV-003 | Lateral Movement SMB | CRITICAL | lateral_movement | T1021.002 | 0.92 | dest_port 445 + internal→internal + smb_traversal/lateral_movement flag |
| TV-004 | Lateral Movement WMI | CRITICAL | lateral_movement | T1047 | 0.89 | dest_port 135 + internal→internal + process_name contains "wmic" |
| TV-005 | Credential Dumping | CRITICAL | lateral_movement | T1003.001 | 0.95 | layer=endpoint + process_name contains "lsass" or "mimikatz" |
| TV-006 | Suspicious PowerShell | HIGH | lateral_movement | T1059.001 | 0.82 | process_name=powershell.exe + parent is cmd/wscript/cscript/mshta/w3wp |
| TV-007 | Data Exfiltration Volume | HIGH | data_exfiltration | T1048 | 0.75 | bytes_sent > 50MB + external dest |
| TV-008 | Tor Exit Node Traffic | MEDIUM | brute_force | T1090 | 0.85 | source_ip in 185.220.0.0/16 |
| TV-009 | Self-Signed Cert C2 | MEDIUM | c2_beacon | T1573 | 0.80 | self_signed_cert flag + external dest |
| TV-010 | RDP Lateral Movement | HIGH | lateral_movement | T1021.001 | 0.78 | dest_port 3389 + internal→internal |
| TV-011 | Net Command Recon | MEDIUM | lateral_movement | T1087.001 | 0.72 | layer=endpoint + process_name contains "net.exe" |
| TV-012 | Known Asset FP | LOW | false_positive | — | 0.00 | Suppressor: known_asset + internal_destination + business_hours (ALL three required) |

---

## AI Agents

All agents use `langchain_anthropic.ChatAnthropic`. All Claude calls are wrapped in `try/except` with a deterministic fallback — the service must not crash when `ANTHROPIC_API_KEY` is absent.

### BlueAgent (`agents/blue_agent.py`)
- **Models:** `claude-opus-4-5` (analysis), `claude-haiku-4-5-20251001` (triage)
- **Functions:** `analyze_incident()`, `generate_playbook()`, `explain_alert()`, `triage_alert()`
- **Memory:** ChromaDB vector store for playbook retrieval; falls back to `EphemeralClient()` when port 8001 unreachable
- **Audit:** All calls logged via AuditService

### RedAgent (`agents/red_agent.py`)
- **Model:** `claude-opus-4-5`
- **Functions:** `generate_attack_scenario()`, `generate_attack_events()`, `adapt_strategy()`
- **Fallback scenarios:** Full static scenarios for brute_force, c2_beacon, lateral_movement, data_exfiltration
- **Audit:** All calls logged via AuditService

### PlaybookAgent (`agents/playbook_agent.py`)
- **Model:** `claude-opus-4-5`
- **Functions:** `generate_playbook()`, `get_quick_commands()`
- **Store:** In-memory `_playbook_store` dict (not persisted to DB — intentional)
- **Audit:** All calls logged via AuditService

### SimulationEngine (`agents/sim_engine.py`)
- Orchestrates multi-round Red vs Blue loop
- Default: 6 rounds; attack_types: brute_force, c2_beacon, lateral_movement, data_exfiltration
- Detection rate improves from ~35% to ~97% over rounds
- Results stored in-memory `_simulations` dict (not persisted — intentional)

---

## Audit Logging System

**AuditService** (`services/audit_service.py`):
- SHA-256 hash chain: each entry hashes `actor_type|actor_id|action|target_id|result|timestamp` + previous entry's hash
- First entry anchors to `GENESIS` constant
- `asyncio.Lock` serializes hash chain writes — no race conditions on single instance
- High-frequency calls (detection pipeline, ingestion) use fire-and-forget `asyncio.create_task()`
- Only non-benign events audited from ingestion pipeline (HIGH/CRITICAL only) — prevents 600 EPS flood
- `verify_chain()` walks all entries and re-computes hashes for tamper detection

**AuditMiddleware** (`middleware/audit_middleware.py`):
- Intercepts all `/api/v1/` requests
- Logs as `actor_type=human, action=api_call`

**Audit API** (`api/audit_logs.py`):
- `GET /api/v1/audit/logs` — paginated list with filters (actor_type, action, target_type)
- `GET /api/v1/audit/logs/search` — ILIKE search on reasoning + metadata fields
- `GET /api/v1/audit/verify` — full hash-chain integrity walk

---

## Ticket & Analyst System

### TicketService (`services/ticket_service.py`)
- SLA deadlines: CRITICAL=15min, HIGH=1hr, MEDIUM=4hr, LOW=24hr (stored in `SLA_HOURS` dict — do not change)
- Lifecycle: `open → acknowledged → in_progress → patch_attempted → resolved → verified → closed | escalated`
- Auto-escalation after 3 escalation_count; SLAMonitor background task checks every 60 seconds
- Ticket display ID: `TICK-NNNN` (PostgreSQL sequence `ticket_number_seq` starting at 1)
- **Ticket severity is uppercase** — `"CRITICAL"`, `"HIGH"`, etc.

### AnalystService (`services/analyst_service.py`)
- 3-tier hierarchy: tier 1=Junior (max 5 tickets), tier 2=Mid (max 8), tier 3=Senior (max 12)
- Smart assignment scoring: availability + workload capacity + skill match + tier weight
- Skills: `["web", "network", "cloud", "llm", "api", "malware", "forensics"]`

---

## WebSocket

Single endpoint `ws://host:8000/ws`. All event types broadcast through one connection.

`manager` singleton (`websocket/manager.py`) — imported everywhere via `from app.websocket.manager import manager`.

### WS Event Types
| Event | Trigger |
|---|---|
| `new_threat` | Every classified non-benign event |
| `new_alert` | Alert created via API |
| `incident_updated` | Incident patched |
| `ticket_created` | Auto-ticket or manual create |
| `sla_breach` | SLAMonitor detects breach |
| `live_event` | Every 5s from live streamer background task |
| `new_audit_log` | Every AuditService write |

---

## Database Schema (Summary)

All tables use `UUIDMixin` (auto UUID PK) + `TimestampMixin` (created_at, updated_at with TZ).

| Table | Key Columns | Notes |
|---|---|---|
| `incidents` | severity (lowercase), threat_type, confidence, is_false_positive, rule_matches (JSON), bytes_sent | Severity: critical/high/medium/low |
| `threat_events` | event_type, threat_type, confidence, is_false_positive, rule_matches (JSON), raw_log (JSON), is_anomaly | Raw classified events |
| `alerts` | rule_name, severity, false_positive, mitre_technique | Linked to incidents via FK |
| `analysts` | tier (1/2/3), skills (JSON), availability (online/busy/offline), current_ticket_count | |
| `tickets` | severity (UPPERCASE), status, sla_deadline, sla_breached, ticket_number (TICK-NNNN) | Severity: CRITICAL/HIGH/MEDIUM/LOW |
| `ticket_activities` | actor_type, action, old_value, new_value, comment | Append-only audit trail |
| `projects` | risk_tier, security_score (0-100), assigned_analysts (JSON) | |
| `audit_logs` | actor_type, action, target_type, hash, previous_hash | SHA-256 hash chain |
| `simulation_runs` | scenario, detection_rate, red_agent_log (JSON), blue_agent_log (JSON) | Legacy DB-stored simulations |

Full column-level schema: see PROJECT_BRAIN.md appendix (legacy) or inspect ORM models in `backend/app/models/`.

---

## API Structure

Base prefix: `/api/v1`

| Router | Prefix | Key Endpoints |
|---|---|---|
| incidents | `/incidents` | CRUD + `/{id}/analyze` (BlueAgent) |
| alerts | `/alerts` | CRUD |
| threats | `/threats` | classify, batch-classify, rules, MITRE, stats |
| simulation | `/simulation` | start, quick-demo, history, status, results |
| playbooks | `/playbooks` | generate, explain, quick/{threat_type} |
| dashboard | `/dashboard` | metrics, threat-timeline, metric-details, health-check |
| ingestion | `/ingestion` | ingest, demo, stress-test, stats, status |
| analysts | `/analysts` | CRUD, leaderboard, available, stats, availability |
| tickets | `/tickets` | CRUD, assign, acknowledge, resolve, escalate, comment, activities |
| projects | `/projects` | CRUD, security-score, tickets, analysts |
| audit | `/audit` | logs (paginated), logs/search, verify |

Root: `GET /health`, `GET /docs`, `GET /redoc`, `WS /ws`

---

## Frontend Structure

```
frontend/src/
  app/                        Next.js 14 App Router pages
    dashboard/page.tsx        Main SOC dashboard
    analysts/page.tsx         Analyst management
    tickets/page.tsx          Ticket lifecycle UI
  components/dashboard/       All dashboard components
    MetricCards.tsx           Clickable metric cards (drilldown via /metric-details)
    IncidentFeed.tsx          Left panel: incident list
    IncidentModal.tsx         Full incident detail + bytes_sent (exfil)
    AttackMap.tsx             SVG geographic attack visualization
    ThreatTimeline.tsx        Recharts area chart (last 60 min by threat type)
    SimulationPanel.tsx       Red vs Blue control + round chart
    LiveEventsPanel.tsx       Right panel: live event stream
  lib/
    api.ts                    All API calls organized by domain
    store.ts                  Zustand global state (useStore())
    websocket.ts              WebSocketClient singleton + useWebSocket() hook
  types/index.ts              Single source of truth for all TypeScript types
```

### UI Color Palette (tailwind.config.js — do not change hex values)
| Token | Hex | Usage |
|---|---|---|
| bg | `#0a0e1a` | Page background |
| surface | `#0f1629` | Panel/nav |
| card | `#141d35` | Cards |
| border | `#1e2d4a` | Borders |
| cyan | `#00d4ff` | Primary accent |
| danger | `#ff3b6b` | CRITICAL severity |
| warning | `#ffb800` | MEDIUM severity |
| success | `#00ff9d` | LOW / resolved |

---

## Startup Sequence (lifespan in `main.py`)

1. `init_db()` — `Base.metadata.create_all` (tables auto-created, no Alembic required)
2. `get_detector()` — trains IsolationForest on 1000 synthetic benign events
3. `pipeline.start()` — starts Redis consumer loop
4. `sla_monitor.start()` — background task, 60s interval
5. Live event streamer task — pushes synthetic event to WS clients every 5s

---

## Planned Phases (6–13)

| Phase | Name | Status |
|---|---|---|
| 6 | Sandbox Environment Engine | In progress (Audit Logger done; Sandbox not started) |
| 7 | Patch Agent | Planned |
| 8 | Multi-Domain Red Team Agents | Planned |
| 9 | AI Security Chatbot | Planned |
| 10 | Comprehensive Audit Logger (extended) | Planned |
| 11 | Compliance & Reporting | Planned |
| 12 | Knowledge Base & Learning | Planned |
| 13 | Multi-Tenancy & SaaS | Planned |
