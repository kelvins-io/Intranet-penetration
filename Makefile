.PHONY: build run-server run-control run-edge run-agent run-demo test tidy private-up private-down

build:
	go build -o bin/server ./cmd/server
	go build -o bin/control ./cmd/control
	go build -o bin/edge ./cmd/edge
	go build -o bin/agent ./cmd/agent
	go build -o bin/local-http ./examples/local-http

tidy:
	go mod tidy

test:
	go test ./...

run-server:
	go run ./cmd/server -config configs/server.yaml

run-control:
	go run ./cmd/control -config configs/control.yaml

run-edge:
	go run ./cmd/edge -config configs/edge.yaml

run-agent:
	go run ./cmd/agent -config configs/agent.yaml

run-demo:
	go run ./examples/local-http

private-up:
	./scripts/private-install.sh

private-down:
	docker compose -f deploy/docker-compose.yml --profile with-agent down
