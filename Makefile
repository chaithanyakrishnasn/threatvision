.PHONY: install dev build docker-up docker-down seed-data test clean

install:
	@echo "Installing backend dependencies..."
	cd backend && pip install -e ".[dev]"
	@echo "Installing frontend dependencies..."
	cd frontend && npm install

dev:
	@echo "Starting development servers..."
	@cp -n .env.example .env 2>/dev/null || true
	docker compose up postgres redis chromadb -d
	@sleep 3
	$(MAKE) -j2 dev-backend dev-frontend

dev-backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm run dev

build:
	@echo "Building backend..."
	cd backend && pip install -e .
	@echo "Building frontend..."
	cd frontend && npm run build

docker-up:
	@cp -n .env.example .env 2>/dev/null || true
	docker compose up --build -d
	@echo "Services starting up..."
	@echo "  Backend:  http://localhost:8000"
	@echo "  Frontend: http://localhost:3000"
	@echo "  API Docs: http://localhost:8000/docs"

docker-down:
	docker compose down

docker-clean:
	docker compose down -v --remove-orphans

seed-data:
	@echo "Seeding synthetic threat data..."
	cd backend && python -m app.data.synthetic_generator

test:
	@echo "Running backend tests..."
	cd backend && pytest tests/ -v
	@echo "Running frontend tests..."
	cd frontend && npm run test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	cd frontend && rm -rf .next node_modules 2>/dev/null || true

logs:
	docker compose logs -f

ps:
	docker compose ps
