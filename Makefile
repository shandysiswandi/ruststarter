# =============================================================================
# Project Variables & Configuration
# =============================================================================

# Define tools to ensure consistency
CARGO := cargo
GOOSE := goose
DOCKER := docker

# Define directories
MIGRATIONS_DIR := migrations

# Include the .env file if it exists, but don't fail if it's missing.
# This allows DATABASE_URL to be set either in .env or directly in the shell.
-include .env
export

DATABASE_URL := postgres://user:password@localhost:5432/rust

# =============================================================================
# Phony Targets (Commands that are not files)
# =============================================================================

.PHONY: install run build test test-cov format lint clean migrate-up migrate-down migrate-fix docker-build help

# Set the default goal to 'help' so running `make` shows the help message.
.DEFAULT_GOAL := help

# =============================================================================
# Development Workflow
# =============================================================================

install: ## Install all required development tools.
	@echo ">> Installing development tools (cargo-watch, cargo-tarpaulin, goose)..."
	@$(CARGO) install cargo-watch
	@$(CARGO) install cargo-tarpaulin
	@go install github.com/pressly/goose/v3/cmd/goose@latest

run: ## Run the application in watch mode for live reloading.
	@echo ">> Starting application in watch mode..."
	@$(CARGO) watch -q -c -w src -x run

build: ## Build the application for release with optimizations.
	@echo ">> Building release binary..."
	@$(CARGO) build --release

clean: ## Remove build artifacts.
	@echo ">> Cleaning up build artifacts..."
	@$(CARGO) clean

# =============================================================================
# Code Quality & Testing
# =============================================================================

test: ## Run the test suite.
	@echo ">> Running tests..."
	@$(CARGO) test --lib

test-cov: ## Run tests and generate an HTML code coverage report.
	@echo ">> Generating code coverage report..."
	@$(CARGO) tarpaulin --lib --timeout 120 --out Html

format: ## Format the code using rustfmt.
	@echo ">> Formatting code..."
	@$(CARGO) fmt

lint: ## Lint the code using clippy, failing on any warnings.
	@echo ">> Linting code..."
	@$(CARGO) clippy -- -D warnings

# =============================================================================
# Database Migrations
# =============================================================================

migrate-up: ## Apply all pending database migrations.
	@echo ">> Running database migrations up..."
	@$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" up

migrate-down: ## Roll back the last database migration.
	@echo ">> Rolling back last database migration..."
	@$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" down

migrate-fix: ## Fix migration version order if needed (rarely used).
	@echo ">> Fixing migration versioning..."
	@$(GOOSE) -dir $(MIGRATIONS_DIR) fix

# =============================================================================
# Docker & Containerization
# =============================================================================

docker-build: ## Build the production Docker image.
	@echo ">> Building Docker image..."
	@$(DOCKER) build -t ruststarter:latest .

# =============================================================================
# Help
# =============================================================================

help: ## Show this help message.
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

