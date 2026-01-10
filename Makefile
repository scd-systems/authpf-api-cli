.PHONY: build clean install help test

VERSION ?= dev
BINARY_NAME = authpf-api-cli
BUILD_DIR = build
MAIN_PACKAGE = authpf-api-cli

# Default target
help:
	@echo "authpf-api-cli Makefile targets:"
	@echo "  make build          - Build for current platform"
	@echo "  make build-all      - Build for multiple platforms"
	@echo "  make build-linux    - Build for Linux"
	@echo "  make build-freebsd  - Build for FreeBSD"
	@echo "  make build-darwin   - Build for macOS"
	@echo "  make install        - Install to GOPATH/bin"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make test           - Run tests"
	@echo "  make help           - Show this help message"

# Build for current platform
build: clean
	@echo "Building $(BINARY_NAME) for current platform..."
	go build -ldflags="-X main.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(BINARY_NAME)
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for all platforms
build-all: build-linux build-freebsd build-darwin
	@echo "✓ All builds complete"

# Build for Linux
build-linux: clean
	@echo "Building $(BINARY_NAME) for Linux..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(BINARY_NAME)-linux-amd64
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

# Build for FreeBSD
build-freebsd: clean
	@echo "Building $(BINARY_NAME) for FreeBSD..."
	GOOS=freebsd GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64"

# Build for macOS
build-darwin: clean
	@echo "Building $(BINARY_NAME) for macOS..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o ../$(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64"

# Install to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "✓ Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean
	@echo "✓ Clean complete"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "✓ Tests complete"

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "✓ Format complete"

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...
	@echo "✓ Lint complete"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies updated"
