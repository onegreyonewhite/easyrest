PREFIX = easyrest-
BINARIES = $(shell ls cmd)
SRC_DIR = ./cmd
BUILD_DIR ?= $(shell pwd)/bin
BIN_OUT = $(addprefix $(BUILD_DIR)/$(PREFIX), $(BINARIES))
COVERAGE ?= cover.out
export PATH := $(BUILD_DIR):$(PATH)
export CGO_ENABLED := 0
export ER_TOKEN_CACHE_TTL := 20

all: $(BIN_OUT)

$(BINARIES): %: $(BUILD_DIR)/$(PREFIX)%

$(BUILD_DIR)/$(PREFIX)%: $(SRC_DIR)/%/*.go
	mkdir -p $(BUILD_DIR)
	go build -trimpath -ldflags="-s -w" -o $@ $(SRC_DIR)/$*

clean:
	rm -rf $(BUILD_DIR)

COVERPKG ?= $(shell go list ./... | grep -v '/cmd/' | tr '\n' ',' | sed 's/,$$//')

test: plugin-sqlite auth-jwt
	go test -v -coverpkg=$(COVERPKG) -coverprofile=$(COVERAGE) ./...
	go tool cover -func=$(COVERAGE)

bench:
	go test -cpuprofile cpu.prof -bench=. -benchmem ./tests/benchmark_test.go

run: plugin-sqlite auth-jwt
	go run cmd/gateway/main.go --config test_config.yaml

multirun:
	go run cmd/server/main.go --config test_config.yaml

run-perf: server
	perf record -g ./bin/easyrest-server --config test_config.yaml

pgo-up:
	python3 pgo/seed_sqlite.py
	docker compose -f pgo/docker-compose.yml up -d --build --force-recreate easyrest-server

pgo-collect:
	./pgo/scripts/run_load_test.sh

pgo-down:
	docker compose -f pgo/docker-compose.yml down -v

pgo-verify: server
	@go build -pgo=off -gcflags="-m=2" -o /tmp/easyrest-nopgo $(BUILD_DIR)/easyrest-server 2> /tmp/nopgo.txt || true
	@go build -gcflags="-m=2" -o /tmp/easyrest-withpgo $(BUILD_DIR)/easyrest-server 2> /tmp/withpgo.txt || true
	@diff /tmp/nopgo.txt /tmp/withpgo.txt | grep -E "inlining call to|devirtualizing" || true
	@go version -m $(BUILD_DIR)/easyrest-server | grep -E "build.*-pgo" || echo "PGO not embedded in $(BUILD_DIR)/easyrest-server"

.PHONY: all clean test bench run multirun run-perf pgo-up pgo-collect pgo-down pgo-verify

update-packages:
	go get -u ./... && go mod tidy
