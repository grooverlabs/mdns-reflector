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

# Default architecture
ARCH ?= arm64

# Raspberry Pi (aarch64) parameters
PLATFORM_PI=linux/arm64

.PHONY: all build clean test cross-compile package help

all: build

help:
	@echo "Usage:"
	@echo "  make build           - Build for the current platform"
	@echo "  make cross-compile   - Build for architecture (default arm64, use ARCH=amd64 for Intel)"
	@echo "  make package         - Build .deb package for architecture (default arm64)"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make test            - Run go tests"

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v .

cross-compile:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=$(ARCH) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-$(ARCH) -v .

package: cross-compile
	cp $(BUILD_DIR)/$(BINARY_NAME)-$(ARCH) $(BUILD_DIR)/$(BINARY_NAME)-pkg
	export ARCH=$(ARCH); nfpm pkg --packager deb --target $(BUILD_DIR)/$(BINARY_NAME)_1.0.0_$(ARCH).deb
	rm $(BUILD_DIR)/$(BINARY_NAME)-pkg

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

deps:
	$(GOMOD) tidy
	$(GOMOD) download
