.PHONY: verify lint test build tidy
verify: lint test build
lint:
	golangci-lint run ./...
test:
	go test ./...
build:
	go build ./...
tidy:
	go mod tidy
