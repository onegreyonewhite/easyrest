#!/bin/sh
set -eu
dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)/tls
mkdir -p "$dir"
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$dir/key.pem" \
  -out "$dir/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 644 "$dir/key.pem" "$dir/cert.pem"
