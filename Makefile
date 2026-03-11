PYTHON ?= python3

.PHONY: dev dev-backend dev-frontend test lint lint-backend lint-frontend

dev:
	docker compose up

dev-backend:
	$(PYTHON) -m uvicorn backend.main:app --reload

dev-frontend:
	cd frontend && npm run dev

test:
	$(PYTHON) -m pytest

lint: lint-backend lint-frontend

lint-backend:
	$(PYTHON) -m pip install flake8 >/dev/null 2>&1 || true
	flake8 backend sandbox engines

lint-frontend:
	cd frontend && npx eslint src || true

