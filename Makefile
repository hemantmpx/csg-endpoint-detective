.PHONY: up down logs seed validate-scenarios test load-test reset-lab
up:
	docker compose up --build -d
down:
	docker compose down
logs:
	docker compose logs -f --tail=100
seed:
	docker compose exec backend python -m app.seed_database
validate-scenarios:
	python3 tools/build_scenarios.py
	python3 tools/validate_scenario.py
test:
	./.venv/bin/python -m unittest discover -s backend/tests -v
	cd frontend && npm run typecheck && npm run test:e2e
load-test:
	python3 load-tests/classroom_load_test.py
reset-lab:
	docker compose down -v
	docker compose up --build -d
