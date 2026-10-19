FROM golang:1.26 AS builder

RUN apt update && apt install -y make

ARG GOARCH="amd64"
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOAMD64=v2

WORKDIR /app

# Use Docker BuildKit's mount=type=cache to cache Go modules
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY internal ./internal
COPY plugin ./plugin
COPY plugins ./plugins
COPY embed ./embed
COPY cmd ./cmd
COPY Makefile ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make clean server


FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /app/bin/easyrest-server /easyrest-server
EXPOSE 8080
ENTRYPOINT ["/easyrest-server"]
