# PROJECT_LOGS.md
> Append-only chronological agent handoff log for ThreatVision / SentinelAI.
> Add new entries at the bottom. Never edit or remove existing entries.

---

## Phase Build History (Chronological)

1. **Phase 1 (Core):** FastAPI skeleton, PostgreSQL models (Incident, Alert, ThreatEvent, SimulationRun), config, Docker Compose with 5 services, base schemas
2. **Phase 2 (Detection):** 12 Sigma-style rules (TV-001 to TV-012), IsolationForest anomaly detector, MITRE ATT&CK mapper, cross-layer correlation engine, unified ThreatClassifier combining all four with configurable weights
3. **Phase 3 (Ingestion + Agents):** Redis Streams producer/consumer pipeline, multi-format normalizer, BlueAgent (claude-opus-4-5), RedAgent (claude-opus-4-5), PlaybookAgent, SimulationEngine with 6-round adversarial loop, data seeder, synthetic event generator
4. **Phase 4 (API + Frontend):** All 10 REST API routers, WebSocket connection manager, live event streamer background task, Next.js 14 dashboard with all panels, Zustand store, WebSocket client with reconnect, TypeScript types
5. **Phase 5 (Analyst System + Tickets):** Analyst model + 3-tier system, TicketService with SLA enforcement and auto-escalation, AnalystService with smart scoring assignment, SLAMonitor background task, Project model, analysts/tickets pages, seed_analysts.py, test_phase5.py

---

## Key Decisions Made

- **Confidence formula:** 70% rule score + 30% anomaly score — rules dominate (tuned for demo data)
- **Cross-layer boost:** +0.15 when same source IP appears in 2+ distinct layers in 5-minute window
- **ChromaDB fallback:** EphemeralClient() when port 8001 unreachable — agents work without ChromaDB
- **Demo data strategy:** incidents endpoint returns hardcoded demo data when DB is empty — dashboard never blank on first run
- **SLA by severity:** CRITICAL=15min, HIGH=1hr, MEDIUM=4hr, LOW=24hr
- **Ticket auto-creation:** confidence > 0.85 AND HIGH/CRITICAL severity AND not FP — auto-ticket from every ingested event that qualifies
- **In-memory stores:** playbooks and simulation results stored in module-level dicts (intentional for demo simplicity — no persistence needed for hackathon)

---

## Agent Handoff Log

---

### [2026-04-14] Initial Build (Claude Code)
- Completed:
  - Phases 1–5 fully implemented
  - FastAPI + PostgreSQL + Redis + ChromaDB + Next.js 14 stack
  - 12 Sigma-style detection rules, IsolationForest anomaly detection
  - BlueAgent + RedAgent + PlaybookAgent + SimulationEngine
  - Analyst system, ticket engine, SLA monitor
  - Full dashboard with all panels, WebSocket live updates
- Modified:
  - All files — initial build
- Issues:
  - `psycopg2-binary` not installed (non-fatal, asyncpg used throughout)
  - ChromaDB falls back to EphemeralClient() when port 8001 unreachable
  - Playbook + simulation stores are in-memory (intentional for demo)
  - JWT auth configured but not enforced on any route
- Next Suggested Step:
  - Begin Phase 6: Sandbox Environment Engine

---

### [2026-04-15] Data Exfiltration Scenario (Claude Code)
- Completed:
  - Added malicious data exfiltration scenario (`_data_exfiltration_attack()`) to synthetic generator
  - Integrated exfiltration events into event batch pipeline (4% of batch, minimum 2 events)
  - Updated Simulation Engine default `attack_types` to include `data_exfiltration`
  - Updated RedAgent `_FALLBACK_SCENARIOS` with full `data_exfiltration` entry (MITRE T1048, T1041, T1560, T1071.001)
  - Updated RedAgent `attack_map` to route `data_exfiltration` → `data_exfiltration` scenario type
  - Ensured compatibility with Rule TV-007 (bytes_sent > 50 MB + external dest IP)
- Modified:
  - `backend/app/data/synthetic_generator.py` — new `EXFIL_DEST_IPS` constant, `_data_exfiltration_attack()` function, updated `generate_event_batch()`
  - `backend/app/agents/sim_engine.py` — added `data_exfiltration` to `SimulationConfig.attack_types` default list
  - `backend/app/agents/red_agent.py` — added `data_exfiltration` fallback scenario, updated `attack_map`
- Issues:
  - Exfiltration detection depends heavily on threshold tuning (bytes_sent > 50 MB in TV-007); transfers below this threshold are undetected
  - Endpoint staging events (dest_ip = src_ip/internal) do not trigger TV-007 by design — only the primary network transfer event does
- Next Suggested Step:
  - Enhance frontend to visualize exfiltration events clearly (e.g., highlight data_exfiltration in ThreatTimeline, add exfil-specific metric card)

---

### [2026-04-15] Exfiltration UI Enhancements (Gemini)
- Completed:
  - Enhanced UI to highlight data exfiltration attacks
  - Added transfer details in Incident Modal
  - Improved Attack Map visualization for exfiltration flows
  - Updated timeline and live feed to include exfiltration
- Modified:
  - `frontend/src/components/dashboard/IncidentFeed.tsx`
  - `frontend/src/components/dashboard/IncidentModal.tsx`
  - `frontend/src/components/dashboard/AttackMap.tsx`
  - `frontend/src/components/dashboard/ThreatTimeline.tsx`
  - `frontend/src/components/dashboard/LiveEventsPanel.tsx`
- Issues:
  - Requires consistent backend field naming for bytes_sent (Fixed by adding bytes_sent to Incident model and API)
- Next Suggested Step:
  - Proceed to Phase 6 (Audit Logger)

---

### [2026-04-15] Audit Logger — Phase 6 Backend (Claude Code)
- Completed:
  - Implemented AuditLog model with SHA-256 hash chain (tamper-evident, GENESIS anchor)
  - Built centralized AuditService with asyncio.Lock-serialized hash chain writes
  - Added verify_chain() full-walk integrity checker
  - Integrated audit logging across detection pipeline (threat_classified — non-benign only)
  - Integrated audit logging in ingestion consumer (HIGH/CRITICAL threats, fire-and-forget)
  - Integrated audit logging in TicketService (created, assigned, resolved, escalated)
  - Integrated audit logging in BlueAgent (incident_analysis, playbook_generated, alert_explained, triage)
  - Integrated audit logging in RedAgent (attack_scenario_generated — claude + fallback paths)
  - Integrated audit logging in PlaybookAgent (playbook_generated)
  - Added AuditMiddleware (all /api/v1/ requests logged as actor_type=human, action=api_call)
  - Implemented Audit API: GET /api/v1/audit/logs (paginated + filters), GET /api/v1/audit/logs/search (ILIKE on reasoning + metadata), GET /api/v1/audit/verify (hash-chain check)
  - Added WebSocket broadcast "new_audit_log" on every audit write
- Modified:
  - `backend/app/models/audit_log.py` (new)
  - `backend/app/models/__init__.py` (registered AuditLog)
  - `backend/app/services/audit_service.py` (new)
  - `backend/app/middleware/audit_middleware.py` (new)
  - `backend/app/api/audit_logs.py` (new)
  - `backend/app/api/__init__.py` (wired audit router)
  - `backend/app/main.py` (added AuditMiddleware + audit OpenAPI tag)
  - `backend/app/detection/threat_classifier.py`
  - `backend/app/ingestion/redis_consumer.py`
  - `backend/app/services/ticket_service.py`
  - `backend/app/agents/blue_agent.py`
  - `backend/app/agents/red_agent.py`
  - `backend/app/agents/playbook_agent.py`
- Issues:
  - High-frequency logging (600+ EPS) is mitigated by only auditing HIGH/CRITICAL threats in the ingestion pipeline and benign events are skipped
  - Hash chain uses in-memory asyncio.Lock — safe for single-instance deployment; requires distributed lock for horizontal scaling
- Next Suggested Step:
  - Build real-time audit log viewer UI (Phase 6 Frontend): live feed panel, chain verification badge, actor-type filters

---

### [2026-04-15] Audit Log Viewer UI (Gemini)
- Completed:
  - Built real-time audit log viewer page
  - Implemented WebSocket streaming for logs
  - Added filters and search functionality
  - Created detailed log inspection panel
- Modified:
  - Added logs page and components
  - Updated navigation
- Issues:
  - Large log streams may require pagination/virtualization
- Next Suggested Step:
  - Codex stabilization pass (performance + edge cases)

---

### [2026-04-15] Navigation Fix (Codex)
- Completed:
  - Fixed full page reload issue on Logs navigation
  - Converted navigation to Next.js client-side routing
- Modified:
  - Header/navigation component
- Issues:
  - None
- Next Suggested Step:
  - Optimize log stream performance if needed

---

### [2026-04-16] Metric Drilldown API (Claude Code)
- Completed:
  - Implemented metric drilldown API: GET /api/v1/dashboard/metric-details?type=<metric>
  - Supported types: events, threats, critical, false_positive, detection_rate, confidence
  - Each type returns: summary (value + label), breakdown (aggregated DB queries), insights (dynamic strings), explanation (rule/formula context), recommended_actions
  - events: GROUP BY event_type (layer), peak hour via EXTRACT(hour)
  - threats: active HIGH/CRITICAL non-FP incidents grouped by severity and threat_type
  - critical: CRITICAL incidents by threat_type + top triggered rules (sampled 200 rows)
  - false_positive: FP rate %, FP by layer, TV-012 flag counts from raw_log JSON with graceful fallback
  - detection_rate: detected/total with per-threat-type % breakdown
  - confidence: single-query distribution across 4 bands + avg + anomaly vs rule split
  - 400 error with clear message for unsupported type
  - /dashboard/metrics endpoint unchanged and fully backwards compatible
- Modified:
  - `backend/app/api/dashboard.py`
- Issues:
  - raw_log JSON flag queries (known_asset, internal_destination, business_hours) silently fallback to 0 if raw_log fields are not populated — non-fatal
  - rule vs anomaly split in confidence breakdown is an approximation (events with is_anomaly=True vs total)
  - CRITICAL rule_matches breakdown samples up to 200 rows to avoid memory pressure on large datasets
- Next Suggested Step:
  - Build frontend modal for interactive metric drilldown cards (click metric card → fetch /metric-details → show breakdown modal)

---

### [2026-04-16] MetricDetailModal Stabilization (Codex)
- Completed:
  - Fixed infinite API request loop in MetricDetailModal
  - Stabilized useEffect dependencies
  - Stabilized data fetching lifecycle
  - Removed all motion/animation from metric cards
  - Kept interaction behavior intact
- Modified:
  - MetricDetailModal component and metric card components
- Issues:
  - None
- Next Suggested Step:
  - Performance optimization or proceed to Phase 7 (Sandbox Engine)

---

### [2026-04-16] PROJECT_BRAIN Refactor (Claude Code)
- Completed:
  - Refactored PROJECT_BRAIN.md into a multi-file documentation system
  - Created PROJECT_LOGS.md (this file) — append-only agent handoff log + build history
  - Created ARCHITECTURE.md — stable system design reference
  - Rewrote PROJECT_BRAIN.md as concise active-context document (< 150 lines)
  - Migrated all content without data loss
- Modified:
  - `PROJECT_BRAIN.md` (rewritten as active context)
  - `PROJECT_LOGS.md` (created)
  - `ARCHITECTURE.md` (created)
- Issues:
  - None
- Next Suggested Step:
  - Continue Phase 6 frontend work or proceed to Phase 7 (Sandbox Environment Engine)
