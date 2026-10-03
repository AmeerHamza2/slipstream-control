.PHONY: env apple-root up down test test-go test-node test-python demo lint
GO_PKGS := ./...

env:            ## generate .env with dev secrets for docker compose
	./scripts/gen-env.sh

apple-root:     ## download Apple Root CA G3 (App Store JWS chain anchor)
	mkdir -p deploy && curl -fsSL https://www.apple.com/certificateauthority/AppleRootCA-G3.cer -o deploy/AppleRootCA-G3.cer

up: env apple-root
	docker compose up --build

down:
	docker compose down -v

test: test-go test-node test-python

test-go:        ## needs Postgres + Redis; set TEST_DATABASE_URL / TEST_REDIS_URL for integration tests
	go vet $(GO_PKGS)
	go test -race -count=1 $(GO_PKGS)

test-node:
	cd services/billing-webhooks && npm ci && npm run lint && npm test

test-python:
	cd services/fleet-prober && python3 -m venv .venv && .venv/bin/pip install -q -e '.[dev]' && \
	  .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q

demo:           ## end-to-end demo with all three services running natively
	./scripts/demo.sh
