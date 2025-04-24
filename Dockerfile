FROM golang:1.24-alpine AS builder

RUN apk add --no-cache make

ARG GOARCH="amd64"
ENV CGO_ENABLED=0
ENV GOOS=linux

COPY internal /app/internal
COPY plugin /app/plugin
COPY cmd /app/cmd
COPY Makefile /app/Makefile
COPY go.mod /app/go.mod
COPY go.sum /app/go.sum

WORKDIR /app

RUN make clean all


FROM alpine:latest

ARG GOARCH="amd64"

RUN apk add --no-cache curl

RUN curl -L -o easyrest-plugin-postgres \
    https://github.com/onegreyonewhite/easyrest-plugin-postgres/releases/download/v0.5.1/easyrest-plugin-postgres-linux-$GOARCH && \
    curl -L -o easyrest-plugin-redis \
    https://github.com/onegreyonewhite/easyrest-plugin-redis/releases/download/v0.1.0/easyrest-plugin-redis-linux-$GOARCH && \
    curl -L -o easyrest-plugin-mysql \
    https://github.com/onegreyonewhite/easyrest-plugin-mysql/releases/download/v0.5.1/easyrest-plugin-mysql-linux-$GOARCH && \
    chmod +x easyrest-plugin-postgres && \
    chmod +x easyrest-plugin-redis && \
    chmod +x easyrest-plugin-mysql && \
    mv easyrest-plugin-postgres /usr/local/bin/easyrest-plugin-postgres && \
    mv easyrest-plugin-redis /usr/local/bin/easyrest-plugin-redis && \
    mv easyrest-plugin-mysql /usr/local/bin/easyrest-plugin-mysql

COPY --from=builder /app/bin/easyrest-server /usr/local/bin/easyrest-server
COPY --from=builder /app/bin/easyrest-plugin-sqlite /usr/local/bin/easyrest-plugin-sqlite

ENTRYPOINT ["/usr/local/bin/easyrest-server"]
