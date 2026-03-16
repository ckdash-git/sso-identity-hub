.PHONY: all build run test test-unit test-integration lint fmt vet migrate-up migrate-down docker-up docker-down generate-keys

BINARY_NAME=sso-identity-hub
BUILD_DIR=./bin
CMD_PATH=./cmd/server

all: fmt vet lint test build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

run:
	go run $(CMD_PATH)/main.go

test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	go test -v -race -count=1 ./tests/unit/...

test-integration:
	@echo "Running integration tests (requires Docker)..."
	go test -v -race -count=1 -timeout 120s ./tests/integration/...

lint:
	@which golangci-lint > /dev/null 2>&1 || (echo "golangci-lint not found, install from https://golangci-lint.run" && exit 1)
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w .

vet:
	go vet ./...

migrate-up:
	@echo "Applying migrations..."
	migrate -path ./migrations -database "postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=$(POSTGRES_SSLMODE)" up

migrate-down:
	@echo "Rolling back last migration..."
	migrate -path ./migrations -database "postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=$(POSTGRES_SSLMODE)" down 1

docker-up:
	docker compose up -d

docker-down:
	docker compose down

# Generate RSA-2048 key pair for RS256 JWT signing into ./secrets directory
generate-keys:
	@mkdir -p ./secrets
	openssl genrsa -out ./secrets/rsa_private.pem 2048
	openssl rsa -in ./secrets/rsa_private.pem -pubout -out ./secrets/rsa_public.pem
	@echo "RS256 key pair written to ./secrets/"

tidy:
	go mod tidy
