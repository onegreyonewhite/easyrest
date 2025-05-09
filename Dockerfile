FROM golang:1.24-alpine AS builder

RUN apk add --no-cache make tzdata

ARG GOARCH="amd64"
ENV CGO_ENABLED=0
ENV GOOS=linux

WORKDIR /app

# Use Docker BuildKit's mount=type=cache to cache Go modules
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY internal ./internal
COPY plugin ./plugin
COPY plugins ./plugins
COPY cmd ./cmd
COPY Makefile ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make clean server


FROM scratch
# Copy the timezone database from Alpine (builder) image
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=builder /app/bin/easyrest-server /easyrest-server

ENTRYPOINT ["/easyrest-server"]
