# Kaaval — one-command operations. Run `make` (or `make help`) for the list.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help doctor setup up local demo down reset logs clean test

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

doctor: ## Pre-flight checks (OS/arch, Docker, memory, ports, .env, line endings)
	@bash scripts/doctor.sh

setup: ## Check prerequisites and create .env from the template
	@bash setup.sh

up: setup ## Build + start the whole stack (default: OpenRouter LLM)
	docker compose up -d --build
	@echo "Kaaval SOC:    http://localhost:8080/        (login token: kaaval-operator)"
	@echo "Range console: http://localhost:8080/range"
	@echo "Run 'make demo' to launch the attack chain."

local: setup ## Start with a bundled local Ollama container (fully offline)
	KAAVAL_LLM_PROVIDER=local OLLAMA_HOST=http://ollama:11434 \
	  docker compose --profile local up -d --build

demo: ## Launch the IT->OT attack chain and print where to watch it
	@bash scripts/demo.sh

reset: ## Reset to a clean pre-attack baseline (plant, logs, containment, incidents)
	@curl -fsS -X POST -H "Authorization: Bearer $(KAAVAL_ADMIN_TOKEN)" http://localhost:8000/api/reset >/dev/null \
	  && echo "reset: clean pre-attack baseline (plant reseeded, containment flushed, incidents cleared)" \
	  || echo "reset failed — is the stack up? (make up)"

KAAVAL_ADMIN_TOKEN ?= kaaval-admin

down: ## Stop and remove the stack
	docker compose down

logs: ## Tail backend + sensor logs
	docker compose logs -f backend sensor

clean: ## Stop the stack and remove volumes + local Zeek logs
	docker compose down -v
	-find logs -maxdepth 1 -name '*.log' -delete 2>/dev/null || true

test: ## Run the offline backend test suite (in the backend container, or local .venv)
	@if [ -n "$$(docker compose -p kaaval ps -q backend 2>/dev/null)" ]; then \
	  echo "running tests inside the backend container..."; \
	  docker compose -p kaaval exec -T backend python -m pytest tests -q; \
	elif [ -x .venv/bin/python ]; then \
	  echo "running tests in local .venv..."; \
	  .venv/bin/python -m pytest backend/tests -q; \
	else \
	  echo "No backend container and no .venv — run 'make up' first (or create a .venv)."; exit 1; \
	fi
