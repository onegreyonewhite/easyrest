#!/usr/bin/env bash
# create_local.sh — set up a local EasyREST SQLite test environment.
#
# Creates:
#   local.db            — SQLite database with 10,000 users
#   local_config.yaml   — server config (CRUD + QUERY connections)
#   local_token.txt     — JWT signed with the config secret
#
# Usage:
#   ./create_local.sh
#   go run cmd/server/main.go --config local_config.yaml
#
# Requires: python3, curl (optional: jq for pretty output)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SECRET="${SECRET:-local-dev-secret-change-me}"
PORT="${PORT:-8080}"
DB_FILE="${DB_FILE:-local.db}"
CONFIG="${CONFIG:-local_config.yaml}"
TOKEN_FILE="${TOKEN_FILE:-local_token.txt}"

echo "==> EasyREST local SQLite test harness"
echo "    repo:   $SCRIPT_DIR"
echo "    db:     $DB_FILE"
echo "    config: $CONFIG"
echo "    port:   $PORT"
echo

# ---------------------------------------------------------------------------
# 1. Seed SQLite database (10,000 users)
# ---------------------------------------------------------------------------
echo "==> Seeding $DB_FILE with 10,000 users..."

python3 - "$DB_FILE" <<'PY'
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

db_path = sys.argv[1]
cities = ["Berlin", "London", "Paris", "Tokyo", "New York", "Sydney", "Moscow", "Rome"]
now = datetime.now(timezone.utc)

conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("DROP TABLE IF EXISTS users")
cur.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    age INTEGER NOT NULL,
    city TEXT NOT NULL,
    created_at TEXT NOT NULL
)
""")

rows = []
for n in range(1, 10_001):
    created = (now - timedelta(minutes=n)).strftime("%Y-%m-%d %H:%M:%S")
    rows.append((
        n,
        f"User {n}",
        f"user{n}@example.com",
        18 + (n % 60),
        cities[n % len(cities)],
        created,
    ))

cur.executemany(
    "INSERT INTO users (id, name, email, age, city, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    rows,
)
conn.commit()
count = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
conn.close()
print(f"    inserted {count} rows")
PY

# ---------------------------------------------------------------------------
# 2. Write local_config.yaml
# ---------------------------------------------------------------------------
echo "==> Writing $CONFIG..."

cat > "$CONFIG" <<YAML
port: ${PORT}
access_log: true
check_scope: true
token_user_search: sub

auth_plugins:
  jwt:
    settings:
      jwt_secret: "${SECRET}"

plugins:
  crud:
    title: "SQLite CRUD"
    uri: sqlite://./${DB_FILE}
  query:
    title: "SQLite Query (read-only)"
    uri: sqlite://./${DB_FILE}
    use_query: true

anon_claims:
  role: anonymous
  sub: 0
YAML

echo "    done"

# ---------------------------------------------------------------------------
# 3. Mint JWT (HS256)
# ---------------------------------------------------------------------------
echo "==> Minting JWT -> $TOKEN_FILE..."

python3 - "$SECRET" "$TOKEN_FILE" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time

secret = sys.argv[1].encode()
token_path = sys.argv[2]

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "local-admin",
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
signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
token = ".".join(segments + [b64url(signature)])

with open(token_path, "w", encoding="utf-8") as f:
    f.write(token)
print(f"    token written ({len(token)} chars)")
PY

TOKEN="$(cat "$TOKEN_FILE")"

# ---------------------------------------------------------------------------
# 4. Print ready-to-run curl commands
# ---------------------------------------------------------------------------
cat <<CURL

================================================================================
 Local environment ready.

 Start the server:
   go run cmd/server/main.go --config ${CONFIG}

 Load the token in your shell:
   export TOKEN=\$(cat ${TOKEN_FILE})

 Or inline:
   TOKEN=\$(cat ${TOKEN_FILE})

--------------------------------------------------------------------------------
 QUERY connection (read-only, use_query: true) — /api/query/
--------------------------------------------------------------------------------

# Select rows (expect 5 rows, age > 40)
curl -s -X QUERY "http://localhost:${PORT}/api/query/" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: text/plain" \\
  --data 'SELECT id, name, email, age FROM users WHERE age > 40 ORDER BY id LIMIT 5'

# Aggregate by city
curl -s -X QUERY "http://localhost:${PORT}/api/query/" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: text/plain" \\
  --data 'SELECT city, COUNT(*) AS cnt FROM users GROUP BY city'

# Write attempt (expect HTTP 500 — read-only connection rejects writes)
curl -s -o /dev/null -w "HTTP %{http_code}\\n" -X QUERY "http://localhost:${PORT}/api/query/" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: text/plain" \\
  --data 'DELETE FROM users WHERE id = 1'

--------------------------------------------------------------------------------
 CRUD connection (DB plugin) — /api/crud/
--------------------------------------------------------------------------------

# List first 5 users
curl -s "http://localhost:${PORT}/api/crud/users/?select=id,name,email&ordering=id&limit=5" \\
  -H "Authorization: Bearer \$TOKEN"

# Filter: age > 40 and city = Berlin
curl -s "http://localhost:${PORT}/api/crud/users/?where.gt.age=40&where.eq.city=Berlin&limit=3" \\
  -H "Authorization: Bearer \$TOKEN"

# Insert a new user (id 10001)
curl -s -X POST "http://localhost:${PORT}/api/crud/users/" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '[{"id":10001,"name":"Test User","email":"test@example.com","age":30,"city":"Berlin","created_at":"2026-06-26 12:00:00"}]'

# Update user id=1
curl -s -X PATCH "http://localhost:${PORT}/api/crud/users/?where.eq.id=1" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"User One Updated"}'

# Delete user id=10001
curl -s -X DELETE "http://localhost:${PORT}/api/crud/users/?where.eq.id=10001" \\
  -H "Authorization: Bearer \$TOKEN"

================================================================================
 Tip: pipe any curl through | jq for formatted JSON output.
 Secret is a local dev placeholder — change SECRET=... for non-local use.
================================================================================
CURL

echo
echo "==> Done. Files created:"
echo "    $DB_FILE"
echo "    $CONFIG"
echo "    $TOKEN_FILE"
