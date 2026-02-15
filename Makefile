# Makefile for mdns-reflector

# Binary name
BINARY_NAME=mdns-reflector

# Build directory
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Raspberry Pi (aarch64) parameters
PLATFORM_PI=linux/arm64

.PHONY: all build clean test cross-compile help

all: build

help:
	@echo "Usage:"
	@echo "  make build           - Build for the current platform"
	@echo "  make cross-compile   - Build for Raspberry Pi (aarch64)"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make test            - Run go tests"

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v .

cross-compile:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-pi -v .

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

deps:
	$(GOMOD) tidy
	$(GOMOD) download
