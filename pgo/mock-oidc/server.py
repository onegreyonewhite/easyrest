#!/usr/bin/env python3
"""Minimal OIDC discovery + userinfo mock for PGO load testing."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 9000
BASE = f"http://mock-oidc:{PORT}"
STATIC_OIDC_TOKEN = "pgo-static-oidc-token"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": BASE,
                    "authorization_endpoint": f"{BASE}/authorize",
                    "token_endpoint": f"{BASE}/token",
                    "userinfo_endpoint": f"{BASE}/userinfo",
                },
            )
            return

        if self.path == "/userinfo":
            auth = self.headers.get("Authorization", "")
            expected = f"Bearer {STATIC_OIDC_TOKEN}"
            if auth != expected:
                self._json(401, {"error": "invalid_token"})
                return
            self._json(
                200,
                {
                    "sub": "oidc-user",
                    "scope": "read write",
                    "role": "admin",
                },
            )
            return

        self.send_error(404)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"mock-oidc listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
