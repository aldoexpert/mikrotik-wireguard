.PHONY: help install build build-frontend build-all run dev test fmt lint clean

help: ## Tampilkan help
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	go mod download
	go mod tidy

build-frontend: ## Build frontend (../frontend) dan sync hasilnya ke web/dist/
	@echo "Building frontend..."
	cd ../frontend && npm run build
	@mkdir -p web/dist
	rsync -av --delete ../frontend/www/ web/dist/
	@echo "Frontend synced to web/dist/ -- commit the result so a bare"
	@echo "'go build ./cmd/api' also serves the real UI, not the placeholder."

build-all: build-frontend build ## Build frontend + binary backend sekaligus

build: ## Build binary production (embeds whatever is currently in web/dist/)
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
