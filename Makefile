.PHONY: tidy test run build

tidy:
	go mod tidy

test:
	go test ./...

run:
	go run ./cmd/server

build:
	mkdir -p .bin
	go build -o .bin/tools-api ./cmd/server
