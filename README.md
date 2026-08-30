# EasyREST

![CI](https://github.com/onegreyonewhite/easyrest/actions/workflows/tests.yml/badge.svg)
![Release](https://github.com/onegreyonewhite/easyrest/actions/workflows/release.yml/badge.svg)
![Go](https://img.shields.io/github/go-mod/go-version/onegreyonewhite/easyrest)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

Turn a SQL database into a REST API. Authentication, request hooks, and every data backend are plugins: in-process in `easyrest-server`, or separate HashiCorp [go-plugin](https://github.com/hashicorp/go-plugin) processes in `easyrest-gateway`.

## Table of contents

- [What it is](#what-it-is)
- [Why it is different](#why-it-is-different)
- [Quickstart](#quickstart)
- [Architecture](#architecture)
- [API](#api)
- [Plugin model](#plugin-model)
- [Configuration](#configuration)
- [Distributions and deployment](#distributions-and-deployment)
- [Writing a plugin](#writing-a-plugin)
- [Development](#development)
- [License](#license)



## What it is

EasyREST is a small HTTP server that maps URL paths to database connections. Each named connection in the config becomes `/api/<name>/`. Table CRUD, RPC functions, a read-only `QUERY` method, and a generated Swagger 2.0 schema all go through the same pipeline: authenticate, check scopes, build a plugin context, run middleware, then call a data plugin.

The HTTP core never talks to a database driver itself. It sanitizes identifiers, parses query parameters into typed SQL fragments, and forwards those fragments to a plugin that owns the connection (in-process, or over go-plugin RPC).

## Why it is different

- **Several backends in one process.** SQLite, PostgreSQL, and MySQL can sit next to each other as `/api/app/`, `/api/analytics/`, `/api/legacy/`.
- **Three extension points, not one.** Auth, middleware (`PreRequest` / `PostRequest`), and data (`DBPlugin` / `DBQueryPlugin`) are independent plugin families. A request hits all three.
- **PostgREST-style context round-trip.** Claims, headers, and `Prefer` values are injected into the SQL session. Triggers and functions can set `response.headers`, `response.status`, and `cache.invalidate`; the plugin harvests them before `COMMIT`.
- **Two distributions.** `easyrest-server` embeds the common plugins. `easyrest-gateway` is the same HTTP core with no built-ins — every plugin is an external binary.
- **Cache and rate limiting as middleware.** ETag version tokens, 304/412, and a fixed-window limiter are first-class plugins, not a sidecar.



## Quickstart

Requires [Go 1.26](https://go.dev/dl/) and Python 3 (the seed script). No Docker, no extra databases.

```bash
make server
./create_local.sh
./bin/easyrest-server --config local_config.yaml
```

`[create_local.sh](create_local.sh)` writes `local.db` (10,000 users), `[local_config.yaml](local_config.yaml)`, and a JWT in `local_token.txt`.

```bash
export TOKEN=$(cat local_token.txt)

# List
curl -s "http://localhost:8080/api/crud/users/?select=id,name,email&ordering=id&limit=5" \
  -H "Authorization: Bearer $TOKEN"

# Filter
curl -s "http://localhost:8080/api/crud/users/?where.gt.age=40&where.eq.city=Berlin&limit=3" \
  -H "Authorization: Bearer $TOKEN"

# Swagger 2.0 schema for this connection (no auth)
curl -s "http://localhost:8080/api/crud/"
```

The same file also configures a read-only `QUERY` connection at `/api/query/`. See the curl examples printed by `create_local.sh`.

## Architecture



### Where plugins plug in

Auth plugins run once per request, before the handler builds context. Middleware wraps the handler (`PreRequest` after context is built, `PostRequest` immediately before the body is written). Data plugins own SQL. Cache stores are not HTTP plugins; they sit behind the `cache-*` middleware.

```mermaid
flowchart LR
    Client[HTTP client] --> Router[chi router]
    Router --> Handlers[Handlers]

    subgraph authLayer [Auth plugins]
        AuthJWT[jwt]
        AuthOther["oidc, basic, apikey, awssigv4"]
    end

    subgraph mwLayer [Middleware plugins]
        MwPre[PreRequest]
        MwPost[PostRequest]
    end

    subgraph dataLayer [Data plugins]
        DBPlug[DBPlugin]
        QueryPlug[DBQueryPlugin]
        CacheStore[cache.Store]
    end

    Handlers -->|"Authenticate"| authLayer
    Handlers -->|"PreRequest then PostRequest"| mwLayer
    Handlers -->|"TableGet / CallFunction / QueryCall"| dataLayer
    DBPlug --> SQL[(SQL database)]
    QueryPlug --> SQL
    CacheStore --> KV[("Redis, SQL, LRU, Memcached")]
```



HTTP routes live in `[internal/server/server.go](internal/server/server.go)` (`SetupRouter`). Plugin maps are filled by `[LoadPlugins](internal/server/plugin_lifecycle.go)`.

### Request lifecycle

Order is fixed. The sequence below is the table handler in `[internal/server/table.go](internal/server/table.go)`. RPC and `QUERY` share auth, context, and middleware; schema skips auth.

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Server as EasyREST server
    participant Auth as Auth plugin
    participant MW as Middleware
    participant DB as DB plugin
    participant SQL as Database

    Client->>Server: HTTP request
    Server->>Server: Sanitize identifier, resolve connection
    Server->>Auth: Authenticate(headers, method, path, query)
    Auth-->>Server: claims
    Server->>Server: CheckScope
    Server->>Server: BuildPluginContext
    Server->>MW: PreRequest(dbKey, ctx)
    alt PreRequest returns an HTTP status
        Server-->>Client: stop chain, write that status
    else continue
        MW-->>Server: updated ctx
        Server->>Server: Parse select, where, body, then substitute context
        Server->>DB: TableGet / TableCreate / TableUpdate / TableDelete / CallFunction
        DB->>SQL: Inject session context
        DB->>SQL: db.pre-request hook
        DB->>SQL: statement
        DB->>SQL: db.post-request hook
        DB->>SQL: Harvest response.* and cache.invalidate
        SQL-->>DB: rows plus session settings
        DB-->>Server: rows plus ctx
        Server->>MW: PostRequest(dbKey, ctx)
        MW-->>Server: extra headers
        Server->>Server: Apply response.header.* and response.status
        Server-->>Client: HTTP response
    end
```



`PreRequest` that returns a non-nil status writes immediately and **does not** call the handler or `PostRequest`. `PostRequest` cannot change the body; it can only add headers. `response.status` in the context overrides the handler status after `PostRequest` returns.

### How plugins are loaded

`easyrest-server` tries an in-process factory first (the "preserved" map registered in `[cmd/server/main.go](cmd/server/main.go)`). `easyrest-gateway` has an empty preserved map, so every plugin is an executable.

```mermaid
flowchart TD
    Start[LoadPlugins] --> Kind{Plugin family}
    Kind -->|data| DataKey["URI scheme, e.g. sqlite"]
    Kind -->|auth| AuthKey["config key, e.g. jwt"]
    Kind -->|middleware| MwKey["config key, e.g. ratelimit"]
    DataKey --> PathSet{path set in YAML?}
    AuthKey --> PathSet
    MwKey --> PathSet
    PathSet -->|yes| External[Start subprocess]
    PathSet -->|no| Preserved{Preserved factory?}
    Preserved -->|yes, server only| InProcess[Construct in-process]
    Preserved -->|no| Search[Search PATH, cwd, executable dir]
    Search --> OsArch["Also try name-GOOS-GOARCH"]
    OsArch --> External
    External --> Handshake[go-plugin handshake]
    Handshake --> Dispense["Dispense db, query, auth, or middleware"]
    Dispense --> InitCall["InitConnection or Init"]
    InProcess --> InitCall
    InitCall --> PluginMap[Atomic plugin map]
```



Search and handshake: `[internal/server/plugin_load.go](internal/server/plugin_load.go)`. Default executable names:


| Family     | Config source            | Binary name                 |
| ---------- | ------------------------ | --------------------------- |
| Data       | URI scheme               | `easyrest-plugin-<scheme>`  |
| Auth       | `auth_plugins` key       | `easyrest-auth-<key>`       |
| Middleware | `middleware_plugins` key | `easyrest-middleware-<key>` |


A non-empty `path` always forces the subprocess path, even when a preserved factory exists. RPC service keys are `"db"`, `"query"`, `"auth"`, and `"middleware"`.

### Context round-trip

This is the distinctive part of EasyREST. The server builds a `map[string]any`, middleware may add hook names or headers, the server substitutes `erctx.*` / `request.*` into SQL fragments, and SQL plugins push that map into the session so triggers can write response metadata back.

```mermaid
flowchart TD
    Req[HTTP request] --> Build[BuildPluginContext]
    Build --> Ctx["claims, headers, prefer, timezone, db.type, table, cookies, client_ip"]
    Ctx --> Pre[Middleware PreRequest]
    Pre --> Subst["Substitute erctx.* and request.* in select, where, body"]
    Subst --> Inject{Session injection}
    Inject -->|Postgres| Pg["set_config request.* and erctx.*"]
    Inject -->|MySQL| My["SET @request_* and @erctx_*"]
    Inject -->|SQLite| Sq["No session variables"]
    Pg --> SQL["SQL, triggers, functions"]
    My --> SQL
    Sq --> SQL
    SQL --> Harvest{Harvest before COMMIT}
    Harvest -->|Postgres and MySQL| Back["Merge response.* and cache.invalidate into ctx"]
    Harvest -->|SQLite and QUERY| Skip[ctx unchanged]
    Back --> Post[PostRequest reads handler.status]
    Skip --> Post
    Post --> Apply[Apply headers and response.status]
    Apply --> Resp[HTTP response]
```



`erctx.claims_sub` is the flattened form (dots and dashes become underscores). `request.claims.sub` walks the nested map. Flattening drops values that contain `;` or `--`.

Postgres and MySQL harvest `response.header.*`, `response.headers` (PostgREST JSON array), `response.status`, and `cache.invalidate`. SQLite does not. `QUERY` never returns context, so it cannot harvest either. Example SQL: `[schemas/postgres.sql](schemas/postgres.sql)`, `[schemas/mysql.sql](schemas/mysql.sql)`.

## API


| Method                        | Path                    | Plugin                                      | Auth                                   |
| ----------------------------- | ----------------------- | ------------------------------------------- | -------------------------------------- |
| `GET`                         | `/api/{db}/`            | `DBPlugin.GetSchema`                        | none                                   |
| `QUERY`                       | `/api/{db}/`            | `DBQueryPlugin.QueryCall`                   | yes, scope `read`                      |
| `POST`                        | `/api/{db}/rpc/{func}/` | `DBPlugin.CallFunction`                     | yes, scope `{func}-write`              |
| `GET` `POST` `PATCH` `DELETE` | `/api/{db}/{table}/`    | `TableGet` / `Create` / `Update` / `Delete` | yes, `{table}-read` or `{table}-write` |
| `GET`                         | `/health`               | —                                           | none                                   |


`{db}` is the key under `plugins:` (lowercased). A connection with `use_query: true` only serves `QUERY`; table CRUD and schema are unavailable for that name.

`QUERY` is experimental. Give it a dedicated connection and a database user that can only `SELECT`. The plugin opens a read-only transaction, but the body is still raw SQL.

Schema responses are cached per connection. A cache hit returns immediately and skips middleware.

### Select, aliases, aggregates

```
GET /api/app/users/?select=id,name
GET /api/app/users/?select=username:name
GET /api/app/orders/?select=total:amount.sum(),order_date
GET /api/app/users/?select=count()
```

Allowed functions: `count`, `sum`, `avg`, `min`, `max`. Non-aggregated select fields become `GROUP BY`. Identifiers must match `[A-Za-z_][A-Za-z0-9_]*`.

### Filters and ordering

`where.<op>.<field>=value`, optional `not`:


| Operator                         | SQL                        |
| -------------------------------- | -------------------------- |
| `eq` `neq` `lt` `lte` `gt` `gte` | `=` `!=` `<` `<=` `>` `>=` |
| `like` `ilike` `is` `in`         | `LIKE` `ILIKE` `IS` `IN`   |


```
GET /api/app/users/?where.eq.city=Berlin
GET /api/app/users/?where.gt.age=40
GET /api/app/users/?where.not.eq.name=Alice
GET /api/app/users/?where.in.id=1,2,3
GET /api/app/users/?where.eq.name=request.claims.sub
```

`ordering` is a comma-separated list of **plain identifiers**. There is no `ASC`/`DESC` token; direction is not part of the query language.

### Pagination

Default page size is `default_limit` (100 unless overridden per connection).

- Query: `limit` and `offset`.
- Headers: `Range-Unit: items` plus `Range: 0-9` (inclusive). This wins over query parameters.

Responses include `Content-Range`, `Range-Unit: items`, and `Accept-Ranges: items`. An unsatisfiable range is **416** with an empty JSON array.

### Formats

JSON is the default. Choose CSV, XML, or form encoding with `Accept` or `?format=json|xml|csv`. Request bodies accept the same `Content-Type` set. `Server-Timing: db;dur=...` reports plugin time.

### Prefer

`Prefer: timezone=UTC tx=rollback`

- `timezone` — used when formatting timestamps and stored on the context.
- `tx` — `commit` or `rollback`, honored only when the connection's `db_tx_end` ends in `-allow-override`.

The applied values are echoed in `Preference-Applied`. Other `Prefer` tokens are passed through as `ctx["prefer"]`.

YAML `db_tx_end` defaults to `commit` (env-defined `ER_DB_*` connections default to `commit-allow-override`). Valid values: `commit`, `commit-allow-override`, `rollback`, `rollback-allow-override`.

### Auth and scopes

Plugins are tried in a fixed order: `jwt`, `basic`, `apikey`, `oidc`, `awssigv4`, then any other names alphabetically. The first success wins. Claims are cached when `token_cache_ttl` is positive (keyed on the `Authorization` header).

If every plugin fails and `anon_claims` is set, the request continues with those claims and an empty user id. Without `anon_claims`, the response is 401.

`check_scope` (default on) requires a `scope` claim. A claim of `read` or `write` satisfies any required scope that ends with that word (`users-read`, `orders-write`). Per-table `public` lists skip the scope check — they do **not** skip `Authenticate`. Unauthenticated public access still needs `anon_claims`.

`exclude` hides objects from the API. `allow` is an allow-list: when non-empty, only those tables or functions exist.

## Plugin model

Contracts live in `[plugin/plugin.go](plugin/plugin.go)`. A binary may register any subset of the four RPC keys.

```go
type DBPlugin interface {
    InitConnection(uri string) error
    TableGet(userID, table string, selectFields []string, where map[string]any,
        ordering, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error)
    TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, map[string]any, error)
    TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, map[string]any, error)
    TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, map[string]any, error)
    CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, map[string]any, error)
    GetSchema(ctx map[string]any) (any, map[string]any, error)
}

type DBQueryPlugin interface {
    InitConnection(uri string) error
    QueryCall(query string, ctx map[string]any) ([]map[string]any, error)
}

type AuthPlugin interface {
    Init(settings map[string]any) (map[string]any, error) // Swagger 2.0 security definition
    Authenticate(headers map[string]string, method, path, query string) (map[string]any, error)
}

type MiddlewarePlugin interface {
    Init(settings map[string]any) error
    PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error)
    PostRequest(dbKey string, ctx map[string]any) (map[string]string, error)
}
```

A nil returned context map means "keep the caller's map". A non-nil map replaces it.

### Built-in vs external


|            | `easyrest-server`                                                         | `easyrest-gateway`               |
| ---------- | ------------------------------------------------------------------------- | -------------------------------- |
| Data       | sqlite, postgres, mysql (DB + Query)                                      | external `easyrest-plugin-*`     |
| Auth       | jwt, oidc, basic, apikey, awssigv4                                        | external `easyrest-auth-*`       |
| Middleware | ratelimit, dbqueryhook, cache-{redis,postgres,mysql,sqlite,memcached,lru} | external `easyrest-middleware-*` |


`basic` and `apikey` have no `cmd/` binary — they exist only as preserved plugins inside `easyrest-server`.

### First-party plugins

Settings are the `settings:` map in YAML (auth and middleware) or URI query parameters (data). Read `Init` / `InitConnection` in the package for the full table.


| Plugin                    | Package                                                                                                          | Role                                                                                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| sqlite / postgres / mysql | `[plugins/data/sqlite](plugins/data/sqlite)`, `[postgres](plugins/data/postgres)`, `[mysql](plugins/data/mysql)` | CRUD, schema, optional `QUERY`. Postgres URI scheme is `postgres://` (not `postgresql://`).                                                     |
| jwt / oidc                | `[plugins/auth/jwt](plugins/auth/jwt)`                                                                           | HMAC JWT, or OIDC userinfo. Empty `jwt_secret` decodes without verifying the signature.                                                         |
| basic / apikey / awssigv4 | `[plugins/auth/basic](plugins/auth/basic)`, `[apikey](plugins/auth/apikey)`, `[awssigv4](plugins/auth/awssigv4)` | Header auth. basic and apikey always set `scope: "read write"`.                                                                                 |
| ratelimit                 | `[plugins/middleware/ratelimit](plugins/middleware/ratelimit)`                                                   | Fixed window. Keys: `global`, `ip`, `cookie`. Exceeded → 429 with `Retry-After`.                                                                |
| dbqueryhook               | `[plugins/middleware/dbqueryhook](plugins/middleware/dbqueryhook)`                                               | Sets `db.pre-request` / `db.post-request` from `by_type` and `by_key`. Postgres runs `SELECT name()`, MySQL `CALL name()`, SQLite ignores them. |
| cache-*                   | `[plugins/middleware/cache](plugins/middleware/cache)`                                                           | ETag tokens at `etag:<dbKey>:<table>`. `If-None-Match` → 304 on GET/HEAD, `If-Match` → 412 on writes. Schema and `QUERY` are not cached.        |


Cache backends implement `cache.Store` (`InitConnection`, `Set`, `Get`). SQL-backed stores share `[plugins/data/sqlcache](plugins/data/sqlcache)` and create an `easyrest_cache` table.

## Configuration

Flags write `ER_*` environment variables, then `[config.Load](internal/config/config.go)` builds defaults from the environment and overlays the YAML file (`--config` / `ER_CONFIG_FILE`). Fields present in YAML win.

```yaml
port: 8080
access_log: true
check_scope: true
token_user_search: sub          # claim used as user id
default_limit: 100
default_timezone: GMT
token_cache_ttl: 0              # seconds; <=0 disables the claims cache
anon_claims:                    # used when every auth plugin fails
  role: anonymous
  sub: 0

auth_plugins:
  jwt:
    settings:
      jwt_secret: "change-me"

global_request_middlewares:
  - ratelimit

middleware_plugins:
  ratelimit:
    settings:
      limit: 100
      period: 1m
      key: ip
  cache-redis:
    settings:
      uri: redis://localhost:6379/0
      ttl: 24h

plugins:
  app:
    uri: postgres://user:pass@localhost:5432/app?sslmode=disable
    title: App API
    db_tx_end: commit-allow-override
    request_middlewares: [cache-redis]
    public:
      table: [status]
    exclude:
      table: [schema_migrations]

cors:
  enabled: true
  origins: ["*"]
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
  headers: ["Content-Type", "Authorization"]
  max_age: 86400

# server: timeouts, HTTP/2, max_body_size, trusted_proxy_mode — see Config.Server

otel:
  enabled: false
  endpoint: localhost:4317
  protocol: otlp                # otlp | otlphttp | zipkin (deprecated)
  service_name: easyrest-server
```

If `auth_plugins` is omitted, Load synthesizes a `jwt` plugin from `ER_TOKEN_SECRET`. There is no top-level `token_secret` YAML key.

Additional connection files: `plugin_configs: [./more.yaml]` (YAML documents with a `name:` field) and `ER_DB_<NAME>=sqlite://./file.db`. `ER_USE_QUERY_<NAME>=1` marks that connection as `QUERY`-only.

The complete struct, including the `server:` HTTP/2 and trusted-proxy fields, is `[internal/config/config.go](internal/config/config.go)`. Environment variables use the `ER_` prefix (`ER_PORT`, `ER_CHECK_SCOPE=1`, `ER_ACCESSLOG=1`, `ER_ANON_CLAIMS`, `ER_TLS_CERT_FILE`, …).

Useful flags: `--config`, `--port`, `--version`, `--access-log`, `--enable-plugin-log`, `--timezone`, `--tls-cert-file`, `--tls-key-file`, `--cors-enabled`. Full list: `[internal/cli/cli.go](internal/cli/cli.go)`.

## Distributions and deployment


| Binary             | What you get                                                                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `easyrest-server`  | HTTP core + built-in sqlite/postgres/mysql, all five auth plugins, ratelimit, dbqueryhook, six cache middlewares. PGO profile at `[cmd/server/default.pgo](cmd/server/default.pgo)` is picked up automatically. |
| `easyrest-gateway` | HTTP core only. Put plugin binaries on `PATH` or set `path:`.                                                                                                                                                   |


Release tags publish `easyrest-server-{linux,darwin}-{amd64,arm64}` and `easyrest-gateway-…`, plus a multi-arch image:

```bash
docker pull ghcr.io/onegreyonewhite/easyrest:latest
docker run --rm -p 8080:8080 -v $PWD/config.yaml:/config.yaml \
  ghcr.io/onegreyonewhite/easyrest:latest --config /config.yaml
```

The image is distroless, runs as non-root, and contains only `easyrest-server` (`[Dockerfile](Dockerfile)`).

TLS (`tls_enabled` / cert and key files) serves HTTP/2. Without TLS the server speaks h2c. `SIGHUP` reloads YAML and restarts plugins; `SIGINT`/`SIGTERM` shut down gracefully.

Optional pprof on `easyrest-server` only: `ER_PPROF_ADDR=:6060`.

A full MySQL + Postgres + Redis + Memcached stack for load tests lives in `[pgo/docker-compose.yml](pgo/docker-compose.yml)`.

## Writing a plugin

Build a binary, register one RPC key, serve with `easyrest.Handshake`.

```go
package main

import (
    hplugin "github.com/hashicorp/go-plugin"
    easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type Guard struct{}

func (Guard) Init(map[string]any) error { return nil }

func (Guard) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
    return ctx, nil, nil
}

func (Guard) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
    return nil, nil
}

func main() {
    hplugin.Serve(&hplugin.ServeConfig{
        HandshakeConfig: easyrest.Handshake,
        Plugins: map[string]hplugin.Plugin{
            "middleware": &easyrest.MiddlewarePluginPlugin{Impl: Guard{}},
        },
    })
}
```

Auth plugins register `"auth"` with `AuthPluginPlugin` and implement `Init` + `Authenticate(headers, method, path, query)`. Data plugins register `"db"` and/or `"query"`. A custom ETag backend implements `cache.Store` and is wrapped with `cache.New(store)` as a middleware plugin — see `[cmd/middleware-cache-redis/main.go](cmd/middleware-cache-redis/main.go)`.

Name the binary for auto-discovery (`easyrest-middleware-guard` for `middleware_plugins.guard`) or set `path:`.

## Development

```bash
make            # all cmd/ binaries -> bin/easyrest-<dirname>
make server     # bin/easyrest-server (PGO auto if default.pgo exists)
make test       # go test ./... with coverage; needs plugin-sqlite + auth-jwt on PATH
make bench
```

Integration tests under `[tests/](tests)` use in-process SQLite. They do not need Docker.

Profile-guided optimization: `make pgo-up`, `make pgo-collect` (writes `cmd/server/default.pgo`), `make pgo-verify`, `make pgo-down`. Details in `[pgo/README.md](pgo/README.md)`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2025 Sergei Kliuikov