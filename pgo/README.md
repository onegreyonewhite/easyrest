# PGO load-test environment for `easyrest-server`

This directory contains a self-contained Docker Compose stack and scripts to collect a representative CPU profile for Profile-Guided Optimization (PGO) of the universal `easyrest-server` binary (all DB, cache-middleware, and auth plugins embedded).

## Prerequisites

- Docker with Compose v2
- `curl`
- Python 3
- Go 1.26+ (for rebuilding with PGO)

## Quick start

From the repository root:

```bash
make pgo-collect   # seed DB, start stack, run oha load, write cmd/server/default.pgo
make server        # rebuild with auto-detected default.pgo
make pgo-verify    # confirm PGO was applied
make pgo-down      # tear down containers and volumes
```

## What runs

| Service | Purpose |
|---------|---------|
| `mysql` | MySQL 8 with `schemas/mysql.sql` + seed data |
| `postgres` | PostgreSQL 15 with `schemas/postgres.sql` + seed data |
| `redis` | Valkey/Redis store for `cache-redis` middleware |
| `memcached` | Memcached store for `cache-memcached` middleware |
| `mock-oidc` | Minimal OIDC discovery + userinfo mock |
| `easyrest-server` | Built from repo `Dockerfile`; pprof on `:6060` when `ER_PPROF_ADDR` is set |

Load generators use [oha](https://github.com/hatoo/oha) (`ghcr.io/hatoo/oha`) with `-w` so HTTP/1 in-flight requests are not aborted when `-z` ends (`aborted due to deadline`), and `--http-version=1.1` so h2c is not probed. Workloads:

- `sqlite_crud`, `mysql_crud`, `postgres_crud` — CRUD reads/writes (`sqlite-get-jwt.log`, `mysql-get-jwt.log`, `postgres-get-jwt.log`, plus `sqlite-post-jwt.log` / `mysql-patch-basic.log`)
- `sqlite-ndjson-jwt`, `postgres-ndjson-jwt` — NDJSON streams with `Prefer: page_size` so SQLite does five pages (`limit=250`, `page_size=50`) and Postgres three pages (five seed rows, `page_size=2`)
- `redis_cache_test`, `memcached_cache_test`, `lru_cache_test` — 200 GETs that mint quoted representation ETags, and matching `*-cache-304-*` runs that send `If-None-Match` (quotes kept) for 304
- Auth schemes: JWT, Basic, API key, OIDC (mock)

**Not covered:** `awssigv4` auth (requires AWS-compatible SigV4 signing infrastructure).

## Configuration

- [`config.yaml`](config.yaml) — plugin wiring for the compose network
- [`docker-compose.yml`](docker-compose.yml) — service definitions. The SQLite file is chmod'd world-writable by [`seed_sqlite.py`](seed_sqlite.py) so the distroless `nonroot` process (uid 65532) can enable WAL.
- Environment overrides for the load script:
  - `PGO_DURATION` — profile capture duration in seconds (default: `30`); load generators run for this plus `PGO_STARTUP_BARRIER`
  - `PGO_STARTUP_BARRIER` — warm-up seconds after all oha containers start and before CPU profiling begins (default: `5`)
  - `PGO_CONCURRENCY` — oha workers per target (default: `20`)
  - `PGO_SERVER_URL` — API base (default: `http://localhost:8080`)
  - `PGO_PPROF_URL` — pprof base (default: `http://localhost:6060`)

## Load test logs

Each `oha` workload writes its own summary to [`profiles/oha-logs/`](profiles/oha-logs/) (for example `sqlite-get-jwt.log`, `sqlite-ndjson-jwt.log`, `redis-cache-304-basic.log`). After `make pgo-collect`, the script prints a compact per-test status summary and points to these files for full histograms and status-code breakdowns.

## Manual steps

```bash
python3 pgo/seed_sqlite.py
docker compose -f pgo/docker-compose.yml up -d --build
./pgo/scripts/run_load_test.sh
```

## Alternative: merge per-workload profiles

If a single mixed capture is not representative enough, collect equal-duration profiles per workload and merge (per [go.dev/doc/pgo](https://go.dev/doc/pgo)):

```bash
# Each capture must use the same ?seconds=N value.
curl -o pgo/profiles/sqlite.pprof "http://localhost:6060/debug/pprof/profile?seconds=30"
# ... repeat for mysql, postgres, cache variants ...

go tool pprof -proto \
  pgo/profiles/sqlite.pprof \
  pgo/profiles/mysql.pprof \
  pgo/profiles/postgres.pprof \
  > cmd/server/default.pgo
```

Merge semantics sum sample counts; keep each input profile the same wall duration so none is over-weighted.

## PGO rebuild

Place the profile at `cmd/server/default.pgo`. Go auto-detects it on `go build` (`-pgo=auto`). The existing [`Dockerfile`](../Dockerfile) copies `cmd/` before `make server`, so Docker release builds pick up PGO with no flag changes.

Verify:

```bash
go version -m bin/easyrest-server
go build -pgo=off -gcflags="-m=2" -o /tmp/nopgo ./cmd/server 2> /tmp/nopgo.txt
go build -gcflags="-m=2" -o /tmp/withpgo ./cmd/server 2> /tmp/withpgo.txt
diff /tmp/nopgo.txt /tmp/withpgo.txt | grep -E 'inlining call to|devirtualizing'
```

## pprof endpoint

Set `ER_PPROF_ADDR` (e.g. `0.0.0.0:6060`) to expose `net/http/pprof` on a separate listener. Disabled by default in production.
