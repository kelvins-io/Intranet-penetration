.PHONY: build run-server run-agent run-demo test tidy

build:
	go build -o bin/server ./cmd/server
	go build -o bin/agent ./cmd/agent
	go build -o bin/local-http ./examples/local-http

tidy:
	go mod tidy

test:
	go test ./...

run-server:
	go run ./cmd/server -config configs/server.yaml

run-agent:
	go run ./cmd/agent -config configs/agent.yaml

run-demo:
	go run ./examples/local-http
