PREFIX = easyrest-
BINARIES = plugin-sqlite server
SRC_DIR = ./cmd
BUILD_DIR = $(shell pwd)/bin
BIN_OUT = $(addprefix $(BUILD_DIR)/$(PREFIX), $(BINARIES))
export PATH := $(BUILD_DIR):$(PATH)

all: $(BIN_OUT)

$(BINARIES): %: $(BUILD_DIR)/$(PREFIX)%

$(BUILD_DIR)/$(PREFIX)%: $(SRC_DIR)/%/*.go
	mkdir -p $(BUILD_DIR)
	go build -o $@ $(SRC_DIR)/$*

clean:
	rm -rf $(BUILD_DIR)

test: $(BUILD_DIR)/$(PREFIX)plugin-sqlite
	go test ./...

bench: $(BUILD_DIR)/$(PREFIX)plugin-sqlite
	go test -bench=. ./...

run: $(BUILD_DIR)/$(PREFIX)plugin-sqlite
	export ER_DB_TEST=sqlite://./test.db
	export ER_TOKEN_USER_SEARCH=sub
	export ER_PORT=8080
	export ER_CHECK_SCOPE=1
	go run cmd/server/main.go

.PHONY: all clean test
