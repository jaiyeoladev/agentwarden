.PHONY: install run scan check test lint docker

install:
	python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

run:
	python -m agentwarden serve --reload

scan:
	python -m agentwarden scan

check:
	python -m agentwarden check

test:
	pytest -q

lint:
	ruff check .

docker:
	docker compose up --build
