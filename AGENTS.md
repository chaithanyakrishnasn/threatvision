# Repository Guidelines

## Project Structure & Module Organization

This repository is a monorepo with a FastAPI backend and a Next.js 14 frontend.

- `backend/app/`: API routers, AI agents, detection pipeline, ingestion, models, schemas, services, and WebSocket manager.
- `backend/tests/`: pytest suites for agents, detection, ingestion, and Phase 5 workflows.
- `frontend/src/app/`: App Router pages.
- `frontend/src/components/`: dashboard and shared UI components.
- `frontend/src/lib/`: API clients, Zustand store, toast helpers, and WebSocket utilities.
- `frontend/src/types/`: shared TypeScript types.
- Root files: `Makefile`, `docker-compose.yml`, `.env.example`, `README.md`, `PROJECT_BRAIN.md`.

## Build, Test, and Development Commands

- `make install`: install backend editable deps and frontend packages.
- `make dev`: start Postgres, Redis, ChromaDB, FastAPI, and Next.js for local development.
- `make build`: validate backend install and build the frontend production bundle.
- `make docker-up`: build and run the full stack in Docker.
- `make test`: run backend pytest and the frontend test script.
- `cd backend && pytest tests/ -v`: run backend tests directly.
- `cd backend && pytest -m "not slow"`: skip tests needing live Claude access.
- `cd frontend && npm run dev`: run only the frontend on port `3000`.

## Coding Style & Naming Conventions

Use Python 3.11+ and TypeScript with 2-space indentation in frontend files and conventional Python formatting in backend files. Prefer descriptive module names such as `ticket_service.py` or `MetricDetailModal.tsx`. Use `PascalCase` for React components, `camelCase` for functions/props, and `snake_case` for Python modules, variables, and API payload fields where the backend already uses them.

## Testing Guidelines

Backend tests use `pytest` and `pytest-asyncio`; place new tests under `backend/tests/` as `test_*.py`. Keep fast unit coverage for new logic and mark external-model tests with `@pytest.mark.slow` when they require real API keys. The frontend currently has no real test suite; if you add one, wire it into `frontend/package.json` instead of leaving placeholder scripts.

## Commit & Pull Request Guidelines

Recent history mixes styles (`feat: ...`, `phase 5: ...`, plain summaries). Prefer short imperative subjects with an optional scope prefix, for example `frontend: fix metric detail fetch loop`. Keep PRs focused, describe behavior changes, list verification steps, link issues when relevant, and include screenshots or short recordings for dashboard/UI changes.

## Security & Configuration Tips

Do not commit `.env` or secrets. Start from `.env.example`, set `ANTHROPIC_API_KEY`, and verify `NEXT_PUBLIC_API_URL` and WebSocket settings before debugging frontend/backend integration.
