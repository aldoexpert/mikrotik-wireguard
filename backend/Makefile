.PHONY: help install build run dev test fmt lint clean

help: ## Tampilkan help
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	go mod download
	go mod tidy

build: ## Build binary production
	@mkdir -p bin
	go build -ldflags="-s -w" -o bin/mikrotik-wireguard-backend ./cmd/api
	@echo "Build complete: bin/mikrotik-wireguard-backend"

run: ## Run aplikasi
	go run ./cmd/api

dev: ## Run dengan login dimatikan (hanya untuk pengembangan lokal)
	MTWG_DISABLE_LOGIN=true go run ./cmd/api

test: ## Run tests
	go test -v ./...

fmt: ## Format code
	gofmt -w .

lint: ## Run go vet
	go vet ./...

clean: ## Hapus build artifacts
	rm -rf bin/
	go clean
