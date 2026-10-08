.PHONY: setup dev test lint format seed simulate evaluate train-ml clean

setup: ## First-time environment setup
	cp -n .env.example .env || true
	docker compose build

dev: ## Start the full local stack
	docker compose up --build

test: ## Run backend + frontend test suites
	docker compose run --rm backend pytest
	docker compose run --rm frontend npm test

lint: ## Static analysis
	docker compose run --rm backend ruff check .
	docker compose run --rm backend mypy app
	docker compose run --rm frontend npm run lint

format: ## Auto-format
	docker compose run --rm backend ruff format .
	docker compose run --rm frontend npm run format

seed: ## Load demo data
	docker compose exec backend python scripts/seed_demo_data.py

simulate: ## Replay a demo scenario. Usage: make simulate SCENARIO=brute_force_privilege_escalation
	docker compose exec backend python -m simulator.replay --scenario $(SCENARIO)

evaluate: ## Run detection / ML / agent evaluation suite
	docker compose exec backend python -m evaluation.run_all

train-ml: ## Retrain the anomaly detection model
	docker compose exec backend python scripts/train_anomaly_model.py

ingest-knowledge-base: ## Chunk, embed, and store the RAG knowledge base
	docker compose exec backend python scripts/ingest_knowledge_base.py

import-attack-data: ## Seed MITRE ATT&CK reference data
	docker compose exec backend python scripts/import_attack_data.py

import-threat-intel: ## Import the sample threat intelligence feed
	docker compose exec backend python -c "from app.core.db import SessionLocal; from app.services.threat_intel_service import ThreatIntelService; db = SessionLocal(); print(ThreatIntelService().import_feed(db, 'threat-intel/sample_feed.json')); db.commit()"

sync-detection-rules: ## Index detection-rules/*.yml into the database
	docker compose exec backend python scripts/sync_detection_rules.py

clean: ## Tear down containers and volumes
	docker compose down -v
