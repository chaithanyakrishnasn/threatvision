# ThreatVision

AI-Driven Threat Detection & Simulation Engine — a full-stack SOC (Security Operations Center) platform powered by Claude AI.

## Overview

ThreatVision combines real-time threat detection, AI-driven incident analysis, and adversarial simulation into a unified platform:

- **Red Agent** — simulates attacker TTPs mapped to MITRE ATT&CK
- **Blue Agent** — analyzes incidents and generates defensive playbooks via Claude
- **Playbook Agent** — orchestrates multi-step remediation workflows
- **Simulation Engine** — runs controlled attack/defense scenarios
- **Threat Classifier** — ML + rule-based detection pipeline
- **Real-time Dashboard** — live SOC view with WebSocket updates

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    ThreatVision                      │
│                                                     │
│  ┌──────────┐   ┌──────────┐   ┌────────────────┐  │
│  │ Frontend │   │ Backend  │   │   AI Agents    │  │
│  │ Next.js  │◄──│ FastAPI  │──►│ Claude (via    │  │
│  │  React   │   │ WS/REST  │   │  Anthropic)    │  │
│  └──────────┘   └──────────┘   └────────────────┘  │
│                      │                              │
│         ┌────────────┼────────────┐                 │
│         ▼            ▼            ▼                 │
│    ┌─────────┐ ┌──────────┐ ┌──────────┐           │
│    │Postgres │ │  Redis   │ │ ChromaDB │           │
│    │(events) │ │(streams) │ │(vectors) │           │
│    └─────────┘ └──────────┘ └──────────┘           │
└─────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, React, Tailwind CSS, shadcn/ui, Recharts, Framer Motion |
| Backend | Python 3.11, FastAPI, SQLAlchemy, LangChain |
| AI | Anthropic Claude (via langchain-anthropic) |
| Vector DB | ChromaDB |
| Cache/Stream | Redis |
| Database | PostgreSQL 16 |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for local dev)
- Python 3.11+ (for local dev)

### 1. Clone and configure

```bash
git clone <repo>
cd threatvision
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### 2. Start with Docker (recommended)

```bash
make docker-up
```

Services:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- ChromaDB: http://localhost:8001

### 3. Seed synthetic data

```bash
make seed-data
```

### 4. Local development

```bash
make install
make dev
```

## Project Structure

```
threatvision/
├── backend/
│   ├── app/
│   │   ├── agents/          # AI agents (red, blue, playbook, sim engine)
│   │   ├── api/             # FastAPI routers
│   │   ├── data/            # Synthetic data generation
│   │   ├── detection/       # Threat classification pipeline
│   │   ├── ingestion/       # Event normalization & Redis consumer
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── websocket/       # WebSocket connection manager
│   │   ├── config.py        # App configuration
│   │   └── main.py          # FastAPI entrypoint
│   ├── Dockerfile
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── app/             # Next.js App Router pages
│   │   ├── components/      # React components
│   │   ├── lib/             # API client, WebSocket, Zustand store
│   │   └── types/           # TypeScript interfaces
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── .env.example
├── Makefile
└── README.md
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /api/v1/incidents | List incidents |
| POST | /api/v1/incidents | Create incident |
| GET | /api/v1/alerts | List alerts |
| POST | /api/v1/simulation/run | Start simulation |
| GET | /api/v1/threats | List threat events |
| GET | /api/v1/playbooks | List playbooks |
| GET | /api/v1/dashboard/metrics | Dashboard metrics |
| WS | /ws | Real-time event stream |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude |
| `POSTGRES_URL` | Async PostgreSQL connection URL |
| `REDIS_URL` | Redis connection URL |
| `CHROMA_HOST` | ChromaDB hostname |
| `JWT_SECRET` | Secret for JWT token signing |
| `NEXT_PUBLIC_API_URL` | Frontend → Backend HTTP URL |
| `NEXT_PUBLIC_WS_URL` | Frontend → Backend WebSocket URL |

## License

MIT
