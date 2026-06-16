APP_NAME := pwnedcheck
MAIN_PKG := ./cmd/pwnedcheck
DIST_DIR := dist

GO ?= go
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOBIN ?= $(shell go env GOBIN)

ifeq ($(strip $(GOBIN)),)
GOBIN := $(shell go env GOPATH)/bin
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: help tidy test run build install clean build-linux build-macos install-linux install-macos

help:
	@echo "Targets:"
	@echo "  make build         Build a local binary for the current OS"
	@echo "  make install       Install the CLI to $(GOBIN) for the current OS"
	@echo "  make build-linux    Build a Linux binary in $(DIST_DIR)/"
	@echo "  make build-macos    Build a macOS binary in $(DIST_DIR)/"
	@echo "  make install-linux  Build a Linux binary in $(DIST_DIR)/ and copy it to $(GOBIN)/$(APP_NAME)"
	@echo "  make install-macos  Build a macOS binary in $(DIST_DIR)/ and copy it to $(GOBIN)/$(APP_NAME)"
	@echo "  make run            Run the CLI from source"
	@echo "  make test           Run go test ./..."
	@echo "  make tidy           Run go mod tidy"
	@echo "  make clean          Remove build artifacts"

tidy:
	$(GO) mod tidy

test:
	$(GO) test ./...

run:
	$(GO) run $(MAIN_PKG) $(ARGS)

build:
	$(GO) build -o $(APP_NAME) $(MAIN_PKG)

install:
	$(GO) install $(MAIN_PKG)
	@echo "Installed $(APP_NAME) to $(GOBIN)"

build-linux:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -o $(DIST_DIR)/$(APP_NAME)-linux-$(GOARCH) $(MAIN_PKG)

build-macos:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=$(GOARCH) $(GO) build -o $(DIST_DIR)/$(APP_NAME)-darwin-$(GOARCH) $(MAIN_PKG)

install-linux: build-linux
	install -m 0755 $(DIST_DIR)/$(APP_NAME)-linux-$(GOARCH) $(GOBIN)/$(APP_NAME)
	@echo "Installed $(APP_NAME) to $(GOBIN)"

install-macos: build-macos
	install -m 0755 $(DIST_DIR)/$(APP_NAME)-darwin-$(GOARCH) $(GOBIN)/$(APP_NAME)
	@echo "Installed $(APP_NAME) to $(GOBIN)"
	@echo "Installed $(APP_NAME)-darwin-$(GOARCH) to $(GOBIN)"

clean:
	rm -rf $(DIST_DIR) $(APP_NAME)