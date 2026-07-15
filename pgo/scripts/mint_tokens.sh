#!/usr/bin/env bash
# mint_tokens.sh — emit credentials for PGO load testing (stdout: KEY=value lines).
set -euo pipefail

SECRET="${PGO_JWT_SECRET:-pgo-dev-secret-change-me}"
BASIC_USER="${PGO_BASIC_USER:-pgo-user}"
BASIC_PASS="${PGO_BASIC_PASS:-pgo-pass}"
API_KEY="${PGO_API_KEY:-pgo-api-key-secret}"
OIDC_TOKEN="${PGO_OIDC_TOKEN:-pgo-static-oidc-token}"

python3 - "$SECRET" "$BASIC_USER" "$BASIC_PASS" "$API_KEY" "$OIDC_TOKEN" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time

secret, basic_user, basic_pass, api_key, oidc_token = sys.argv[1:6]

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "pgo-jwt-user",
    "role": "admin",
    "scope": "read write",
    "iat": now,
    "exp": now + 86400,
}
segments = [
    b64url(json.dumps(header, separators=(",", ":")).encode()),
    b64url(json.dumps(payload, separators=(",", ":")).encode()),
]
signing_input = ".".join(segments).encode()
signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
jwt_token = ".".join(segments + [b64url(signature)])

basic_creds = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()

print(f'JWT_TOKEN="{jwt_token}"')
print(f'BASIC_AUTH="Basic {basic_creds}"')
print(f'API_KEY="{api_key}"')
print(f'OIDC_TOKEN="{oidc_token}"')
PY
