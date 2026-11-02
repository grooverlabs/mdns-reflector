# Makefile for mdns-reflector

# Binary name
BINARY_NAME=mdns-reflector

# Build directory
BUILD_DIR=bin

# This repo is outside the go/src workspace (go.work)
export GOWORK=off

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Default architecture
ARCH ?= arm64

# Version from git tag (strips leading 'v'), falls back to 0.0.0-dev
VERSION ?= $(shell (git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0-dev") | sed 's/^v//')

# Raspberry Pi (aarch64) parameters
PLATFORM_PI=linux/arm64

.PHONY: all build clean test lint fuzz vuln cross-compile package help

all: build

help:
	@echo "Usage:"
	@echo "  make build           - Build for the current platform"
	@echo "  make cross-compile   - Build for architecture (default arm64, use ARCH=amd64 for Intel)"
	@echo "  make package         - Build .deb package for architecture (default arm64)"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make test            - Run go tests (race detector)"
	@echo "  make lint            - Run go vet and golangci-lint"
	@echo "  make fuzz            - Fuzz each target for FUZZTIME (default 60s)"
	@echo "  make vuln            - Run govulncheck"

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v .

cross-compile:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=$(ARCH) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(ARCH) -v .

package: cross-compile
	cp $(BUILD_DIR)/$(BINARY_NAME)-$(ARCH) $(BUILD_DIR)/$(BINARY_NAME)-pkg
	export ARCH=$(ARCH) VERSION=$(VERSION); nfpm pkg --packager deb --target $(BUILD_DIR)/$(BINARY_NAME)_$(VERSION)_$(ARCH).deb
	rm $(BUILD_DIR)/$(BINARY_NAME)-pkg

test:
	$(GOTEST) -race ./...

lint:
	$(GOCMD) vet ./...
	golangci-lint run ./...

FUZZTIME ?= 60s
fuzz:
	$(GOTEST) -run='^$$' -fuzz='^FuzzScanMsg$$' -fuzztime=$(FUZZTIME) .
	$(GOTEST) -run='^$$' -fuzz='^FuzzHandlePacket$$' -fuzztime=$(FUZZTIME) .

vuln:
	$(GOCMD) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

deps:
	$(GOMOD) tidy
	$(GOMOD) download
