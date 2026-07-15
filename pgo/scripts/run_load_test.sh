#!/usr/bin/env bash
# run_load_test.sh — start compose stack, drive mixed oha load, capture pprof, write default.pgo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PGO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PGO_DIR}/.." && pwd)"
COMPOSE_FILE="${PGO_DIR}/docker-compose.yml"
PROFILES_DIR="${PGO_DIR}/profiles"
LOG_DIR="${PROFILES_DIR}/oha-logs"
OUTPUT_PROFILE="${PROFILES_DIR}/combined.pprof"
DEFAULT_PGO="${REPO_ROOT}/cmd/server/default.pgo"
OHA_IMAGE="${OHA_IMAGE:-ghcr.io/hatoo/oha:latest}"
NETWORK="${PGO_NETWORK:-easyrest-pgo-net}"
SERVER_URL="${PGO_SERVER_URL:-http://localhost:8080}"
OHA_TARGET_URL="${PGO_OHA_TARGET_URL:-http://easyrest-server:8080}"
PPROF_URL="${PGO_PPROF_URL:-http://localhost:6060}"
DURATION="${PGO_DURATION:-30}"
CONCURRENCY="${PGO_CONCURRENCY:-20}"
STARTUP_BARRIER="${PGO_STARTUP_BARRIER:-5}"
LOAD_DURATION=$((DURATION + STARTUP_BARRIER))

cd "${REPO_ROOT}"

echo "==> Seeding SQLite database"
python3 "${PGO_DIR}/seed_sqlite.py"

mkdir -p "${PROFILES_DIR}" "${LOG_DIR}"

echo "==> Starting docker compose stack"
docker compose -f "${COMPOSE_FILE}" up -d --build

echo "==> Waiting for ${SERVER_URL}/health"
deadline=$((SECONDS + 180))
until curl -sf "${SERVER_URL}/health" >/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "ERROR: server did not become healthy within 180s" >&2
    docker compose -f "${COMPOSE_FILE}" logs easyrest-server | tail -50
    exit 1
  fi
  sleep 2
done
echo "    server is healthy"

# shellcheck disable=SC1090
eval "$("${PGO_DIR}/scripts/mint_tokens.sh")"

echo "==> Pre-pulling oha image"
docker pull "${OHA_IMAGE}"

OHA_PIDS=()
OHA_NAMES=()

run_oha() {
  local name="$1"
  shift
  echo "    starting oha: ${name} (log: ${LOG_DIR}/${name}.log)" >&2
  docker run --rm --network "${NETWORK}" "${OHA_IMAGE}" "$@" \
    >"${LOG_DIR}/${name}.log" 2>&1 &
  OHA_PIDS+=("$!")
  OHA_NAMES+=("${name}")
}

print_oha_summary() {
  echo "==> Per-test load summary (full logs: ${LOG_DIR}/)"
  local name log
  for name in "${OHA_NAMES[@]}"; do
    log="${LOG_DIR}/${name}.log"
    echo "  --- ${name} ---"
    if [[ ! -f "${log}" ]]; then
      echo "    (no log file)"
      continue
    fi
    grep 'Success rate:' "${log}" | sed 's/^/    /' || echo "    (no Success rate line)"
    awk '/Status code distribution:/{p=1; print "    "$0; next} p && /^$/{p=0} p{print "    "$0}' "${log}" || true
    awk '/Error distribution:/{p=1; print "    "$0; next} p && /^$/{p=0} p{print "    "$0}' "${log}" || true
  done
}

echo "==> Starting load generators (${LOAD_DURATION}s each, ${STARTUP_BARRIER}s warm-up before profiling)"
run_oha sqlite-get-jwt \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  "${OHA_TARGET_URL}/api/sqlite_crud/users/?select=id,name&limit=10"

run_oha mysql-get-jwt \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  "${OHA_TARGET_URL}/api/mysql_crud/users/?select=id,name&limit=10"

run_oha postgres-get-jwt \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  "${OHA_TARGET_URL}/api/postgres_crud/users/?select=id,name&limit=10"

run_oha redis-cache-basic \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "Authorization: ${BASIC_AUTH}" \
  "${OHA_TARGET_URL}/api/redis_cache_test/users/?select=id,name&limit=10"

run_oha memcached-cache-apikey \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "X-API-Key: ${API_KEY}" \
  "${OHA_TARGET_URL}/api/memcached_cache_test/users/?select=id,name&limit=10"

run_oha lru-cache-oidc \
  -z "${LOAD_DURATION}s" -c "${CONCURRENCY}" --no-tui \
  -H "Authorization: Bearer ${OIDC_TOKEN}" \
  "${OHA_TARGET_URL}/api/lru_cache_test/users/?select=id,name&limit=10"

run_oha sqlite-post-jwt \
  -z "${LOAD_DURATION}s" -c 1 --no-tui \
  -m POST \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[{"name":"oha-load-user"}]' \
  "${OHA_TARGET_URL}/api/sqlite_crud/users/"

run_oha mysql-patch-basic \
  -z "${LOAD_DURATION}s" -c 5 --no-tui \
  -m PATCH \
  -H "Authorization: ${BASIC_AUTH}" \
  -H "Content-Type: application/json" \
  -d '{"name":"patched-by-oha"}' \
  "${OHA_TARGET_URL}/api/mysql_crud/users/?where.eq.id=1"

QUERY_BODY='SELECT id, name FROM users ORDER BY id LIMIT 10'
run_oha sqlite-query-apikey \
  -z "${LOAD_DURATION}s" -c 5 --no-tui \
  -m QUERY \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: text/plain" \
  -d "${QUERY_BODY}" \
  "${OHA_TARGET_URL}/api/sqlite_query/"

echo "==> Warming up for ${STARTUP_BARRIER}s before profiling"
sleep "${STARTUP_BARRIER}"

echo "==> Capturing CPU profile for ${DURATION}s"
curl -sf -o "${OUTPUT_PROFILE}" \
  "${PPROF_URL}/debug/pprof/profile?seconds=${DURATION}" &
PPROF_PID=$!
wait "${PPROF_PID}"

echo "==> Waiting for load generators to finish"
FAILED_TESTS=()
for i in "${!OHA_PIDS[@]}"; do
  if ! wait "${OHA_PIDS[$i]}"; then
    FAILED_TESTS+=("${OHA_NAMES[$i]}")
  fi
done
if (( ${#FAILED_TESTS[@]} > 0 )); then
  echo "WARNING: load generator(s) exited non-zero, profile may be skewed: ${FAILED_TESTS[*]}" >&2
fi

print_oha_summary

if [[ ! -s "${OUTPUT_PROFILE}" ]]; then
  echo "ERROR: profile file is missing or empty: ${OUTPUT_PROFILE}" >&2
  exit 1
fi

cp "${OUTPUT_PROFILE}" "${DEFAULT_PGO}"
echo "==> Wrote PGO profile: ${DEFAULT_PGO} ($(wc -c < "${DEFAULT_PGO}") bytes)"
echo
echo "Next steps:"
echo "  make server"
echo "  go version -m bin/easyrest-server | grep pgo"
echo "  make pgo-verify"
