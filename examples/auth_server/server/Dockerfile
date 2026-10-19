FROM golang:1.26 AS builder

ARG GOARCH="amd64"
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOAMD64=v2

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY internal ./internal
COPY plugin ./plugin
COPY plugins ./plugins
COPY cmd ./cmd
COPY examples/auth_server/fixedform ./examples/auth_server/fixedform
COPY examples/auth_server/cmd/content-fixedform ./examples/auth_server/cmd/content-fixedform

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/easyrest-server ./cmd/server \
 && go build -trimpath -ldflags="-s -w" -o /out/easyrest-content-fixedform ./examples/auth_server/cmd/content-fixedform

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /out/easyrest-server /usr/local/bin/easyrest-server
COPY --from=builder /out/easyrest-content-fixedform /usr/local/bin/easyrest-content-fixedform
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/easyrest-server"]
