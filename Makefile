PREFIX = easyrest-
BINARIES = plugin-sqlite server
SRC_DIR = ./cmd
BUILD_DIR ?= $(shell pwd)/bin
BIN_OUT = $(addprefix $(BUILD_DIR)/$(PREFIX), $(BINARIES))
COVERAGE ?= cover.out
export PATH := $(BUILD_DIR):$(PATH)
export CGO_ENABLED := 0

all: $(BIN_OUT)

$(BINARIES): %: $(BUILD_DIR)/$(PREFIX)%

$(BUILD_DIR)/$(PREFIX)%: $(SRC_DIR)/%/*.go
	mkdir -p $(BUILD_DIR)
	go build -o $@ $(SRC_DIR)/$*

clean:
	rm -rf $(BUILD_DIR)

test: plugin-sqlite
	go test -v -coverpkg=./... -coverprofile=$(COVERAGE) ./...
	go tool cover -func=$(COVERAGE)

bench: plugin-sqlite
	go test -bench=. ./... -benchmem

run: plugin-sqlite
	go run cmd/server/main.go --config test_config.yaml

run-perf: all
	perf record -g ./bin/easyrest-server --config test_config.yaml

.PHONY: all clean test
