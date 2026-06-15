.PHONY: verify lint test build tidy test-docker
verify: lint test build
lint:
	golangci-lint run ./...
test:
	go test ./...
build:
	go build ./...
tidy:
	go mod tidy
test-docker:
	docker build -f Dockerfile.test -t burnside/license-go-test .
