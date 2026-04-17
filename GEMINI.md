# GEMINI.md

This file provides project-specific context and instructions for AI agents working on the ThreatVision (SentinelAI) codebase.

## Project Overview
ThreatVision is a production-grade, full-stack Security Operations Center (SOC) platform. It features real-time threat detection, AI-driven incident analysis (powered by Claude), and adversarial attack/defense simulations.

- **Backend:** FastAPI (Python 3.11+) with an async ingestion pipeline.
- **Frontend:** Next.js 14 (App Router) with Tailwind CSS and Framer Motion.
- **Data Layers:** 
  - **PostgreSQL:** Primary relational database for incidents, alerts, and tickets.
  - **Redis:** Used for real-time event streams and pipeline queuing.
  - **ChromaDB:** Vector database used for AI agent memory and contextual retrieval.

## Building and Running

The project utilizes a `Makefile` to simplify common development tasks.

### Prerequisites
- Docker and Docker Compose
- Node.js 18+
- Python 3.11+

### Installation
```bash
make install
```

### Development Environment
To start the infrastructure (Postgres, Redis, ChromaDB) and the development servers:
```bash
make dev
```
*Note: Ensure you have copied `.env.example` to `.env` and provided an `ANTHROPIC_API_KEY`.*

### Docker Deployment (Full Stack)
```bash
make docker-up
```

### Data Seeding
To populate the database with synthetic threat events and incidents:
```bash
make seed-data
```

### Testing
```bash
make test
```

## Architecture & Project Structure
- `/backend`: FastAPI application.
  - `app/agents`: LLM-powered agents (RedAgent, BlueAgent, PlaybookAgent).
  - `app/detection`: Threat classification logic (IsolationForest + Rule Engine).
  - `app/ingestion`: Log normalization and Redis stream consumer.
- `/frontend`: Next.js application.
  - `src/app`: Page routes and layouts.
  - `src/components/dashboard`: Core SOC dashboard components.
  - `src/lib`: API clients and state management (Zustand).
- `/docker-compose.yml`: Orchestration for backend, frontend, and all data services.

## Development Conventions

### Coding Standards
- **Backend:** Use async/await for all I/O operations (database, redis, external APIs). Adhere to Pydantic for data validation.
- **Frontend:** Prefer Functional Components and Tailwind utility classes. Use `use client` directives where necessary in the App Router.
- **Types:** Strictly define TypeScript interfaces in `frontend/src/types/index.ts` to match backend Pydantic schemas.

### Verification Mandate
- Before completing any task, ensure that the application builds and tests pass.
- New features should include corresponding tests in `backend/tests/` or `frontend/` (if configured).
- Always verify that WebSocket events are correctly broadcasted when data state changes.

## AI Agent Instructions
- **Security:** Never hardcode or log the `ANTHROPIC_API_KEY`.
- **Infrastructure:** The backend expects ChromaDB on port 8001 (mapped from 8000 in container).
- **Environment:** Use the shared `.env` in the root directory for cross-service configuration.
