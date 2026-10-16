VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X lemongate/internal/app.Version=$(VERSION)

.PHONY: all assets build mock dev test test-integration e2e vet lint-brand up down clean

all: build

web/node_modules: web/package.json
	cd web && npm install && touch node_modules

assets: web/node_modules
	cd web && npm run build

build: assets
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/lemongate ./cmd/lemongate

mock:
	go build -o bin/mockvllm ./cmd/mockvllm
	go build -o bin/mockmcp ./cmd/mockmcp

dev: assets mock
	scripts/dev-restart.sh 4000

vet:
	go vet ./...

test:
	go test ./...

# Requires a disposable Postgres, e.g. TEST_DATABASE_URL=postgres://lemongate:lemongate@localhost:55432/lemongate_test?sslmode=disable
test-integration:
	go test -count=1 -run Integration ./internal/...

# Headless-browser smoke test in an isolated throwaway database and server (never your data).
e2e:
	scripts/e2e.sh

lint-brand:
	@scripts/lint-brand.sh

up:
	docker compose up -d --build

down:
	docker compose down

clean:
	rm -rf bin tmp web/static/dist/*
