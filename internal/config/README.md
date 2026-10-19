# Configuration

`server.SetupApplication` loads defaults, then each `-config` file in order, then a YAML overlay from the flags that were actually passed. A field absent from a later document keeps its previous value. Startup calls `SetupApplication` and then rebuilds the chi router. `SIGHUP` repeats that with the same files and overlay.

The struct is [config.go](config.go). Plugin `settings` keys are documented next to each plugin. This file covers the server document.

## Example

```yaml
port: "8080"
access_log: true
plugin_log: false
check_scope: true
token_user_search: sub
default_limit: 100
default_timezone: GMT
token_cache_ttl: 0
anon_claims:
  role: anonymous
  sub: 0

application:
  template: ""
  template_path: ""
  version: v1
  auth: jwt
  source: app
  public: false
  storage: local
  api:
    v1:
      middlewares: [ratelimit]
      content_handlers: []
      endpoints:
        users: {}

auth_plugins:
  jwt:
    settings:
      jwt_secret: "change-me"

global_request_middlewares:
  - ratelimit

content_plugins: {}
storage_plugins: {}
default_content_handlers: []
default_storage_plugin: local

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
    db_prefer_count: estimated
    db_max_rows: 10000
    request_middlewares: [cache-redis]
    content_handlers: []
    public:
      table: [status]
    exclude:
      table: [schema_migrations]
  hidden:
    uri: postgres://user:pass@localhost:5432/hidden?sslmode=disable
    internal: true

cors:
  enabled: true
  origins: ["*"]
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
  headers: ["Content-Type", "Authorization", "Accept", "Prefer", "If-Match", "If-None-Match", "If-Resource-Version", "Range", "Range-Unit"]
  max_age: 86400

server:
  read_timeout: 5s
  write_timeout: 10s
  idle_timeout: 120s
  read_header_timeout: 5s
  keep_alive_period: 3m
  max_header_bytes: 1048576
  max_body_size: 10485760
  trusted_proxy_mode: none

otel:
  enabled: false
  endpoint: localhost:4317
  protocol: otlp
  service_name: easyrest-server

tls_enabled: false
tls_cert_file: ""
tls_key_file: ""
```

## Top-level fields

| Field | Default | Meaning |
| --- | --- | --- |
| `port` | `8080` | HTTP listen port |
| `access_log` | false | Access log |
| `plugin_log` | false | Logs from plugin processes. `true` enables them |
| `check_scope` | true | Require a `scope` claim. See [Auth and scopes](../server/README.md#auth-and-scopes) |
| `token_user_search` | `sub` | Claim used as the user id |
| `default_limit` | `100` when omitted or zero | Page size when the request does not set one |
| `default_timezone` | zone from `/etc/localtime`, or `GMT` | Used when `Prefer` omits `timezone` |
| `token_cache_ttl` | `-1` | Seconds. `<= 0` disables the claims cache |
| `anon_claims` | empty map | Used when every auth plugin fails |
| `plugin_configs` | empty | Extra connection files. See [Connection files](#connection-files) |
| `global_request_middlewares` | empty | Middleware names applied to every connection |
| `default_content_handlers` | empty | Empty means the five standard content plugins, in order `json`, `ndjson`, `xml`, `csv`, `form` |
| `default_storage_plugin` | `local` when empty | Instance name used when a REST action does not set `storage` |
| `tls_enabled` | false | With both cert and key files, serves HTTP/2. Without TLS the server speaks h2c. Server-built absolute URLs use `https`. `X-Forwarded-Proto` and `Forwarded` choose the scheme only while TLS is off |
| `tls_cert_file`, `tls_key_file` | empty | Certificate and key paths |

There is no top-level `token_secret` key. If `auth_plugins` is omitted, Load synthesizes a `jwt` plugin with an empty `jwt_secret` and `flow: password`.

`content_plugins` adds or replaces content handlers. The five standards (`json`, `ndjson`, `xml`, `csv`, `form`) are always loaded in-process. `html` (Swagger UI) is loaded for schema pages and is not one of those five. A `path` on one of those names replaces it with an RPC plugin. `yaml` is not one of the five. See [YAML](../../cmd/content-yaml/README.md).

`storage_plugins` registers storage instances. `local`, `memory`, `dbglob`, and `static` are preserved in the server package. `s3` is preserved only by `easyrest-server`. An empty `plugin` means the map key is the driver, so `local:` still loads the local driver. The same driver can appear more than once with different settings. A non-empty `path` starts `easyrest-storage-<plugin>`. Driver keys are in each storage README.

## Connections

Each key under `plugins` is a named database connection. The HTTP path uses that key, lowercased, as `/api/{db}/`.

| Field | Default | Meaning |
| --- | --- | --- |
| `uri` | required | Passed to the data plugin. The scheme selects the driver |
| `path` | empty | Forces an external binary |
| `title` | empty | Schema title |
| `use_query` | false | `true` makes the connection `QUERY`-only |
| `internal` | false | Removes the key from every `/api/{db}/` route and leaves it as a `/restapi` source |
| `db_tx_end` | `commit` | `commit`, `commit-allow-override`, `rollback`, `rollback-allow-override` |
| `db_prefer_count` | empty | Copied into `prefer.count` when the client omits `count` |
| `db_max_rows` | `10000` when omitted or zero | `estimated` runs an exact count only below this |
| `default_limit` | the top-level limit | Per-connection page size |
| `public` | empty | Tables and functions that skip the scope check |
| `exclude` | empty | Hidden tables and functions |
| `allow` | empty | When non-empty, only these tables or functions exist |
| `request_middlewares` | empty | Middleware names for this connection |
| `content_handlers` | empty | Empty inherits `default_content_handlers` |

`public`, `exclude`, and `allow` each take `table` and `func` lists.

## Application and `/restapi`

`application` mounts each `api` entry at `/restapi/{name}/`. [APPLICATION.md](../../APPLICATION.md) builds a full app on this section: page, versions, function routes, files, and a cookie session. `source`, `public`, and `storage` are shared by those APIs. `storage` must accept uploads: `local`, `memory`, `s3`, and `dbglob` do. `static` does not. `version`, when set, must be one of those API keys, and that schema is passed to the `/` template. The string `application.auth` must be an `auth_plugins` key and is passed into the template. It does not remove other security schemes.

Each API, endpoint, and action may set `auth` to a list of `auth_plugins` keys. A missing list inherits the parent. The API inherits every loaded auth plugin. `auth: []` calls no auth plugin and does not return 401 by itself. An API `anon_claims` map, including `{}`, replaces the global `anon_claims` after those plugins fail, or immediately when the resolved auth list is empty.

`required_scopes` on an endpoint replaces `endpoint-read` / `endpoint-write` for every action. A non-empty action list replaces the endpoint list for that action. Every listed scope must match. `public: true` and `check_scope: false` skip that check. The OpenAPI `security` array lists only the auth names that apply to the operation. An `oauth2` scheme carries those effective scopes. Other schemes carry an empty scope list. An empty auth list emits `"security": []` and leaves that name out of `securityDefinitions`.

An inline `template` is used even if `template_path` is also set. Both empty keeps the embedded page. `/api/{db}/` and `/restapi/{name}/` keep the embedded page. Set `no_trailing_slash: true` on an endpoint or on a list, detail, state, or CRUD action to register that route without a final slash. The OpenAPI path matches it. The other form is not registered.

`storage` on a REST action, or on a detail, list, or state action, overrides the endpoint, which overrides the app, which overrides `default_storage_plugin`. A state action with `func` registers GET and PUT at `/{segment}/` and calls that database function. `post: true` registers POST instead of PUT, and it is rejected when `func` is empty. It cannot also set `source_field`. A state action with `source_field` stays GET and PUT of that column at `/{id}/{segment}/`. An empty `url` uses the action name. A set `url` on a state, list, or detail action is that path segment: `[a-z0-9_.-]+`, not `.` or `..`, and not a string that contains `/`. Two actions that would register the same method on the same path, including the trailing-slash flag, do not load. GET and PUT may sit beside POST on one segment.

Endpoint fields also include `url`, `description`, `table`, `primary_key`, `filters` (`field`, `op`, `not`), `actions`, `detail_actions`, `list_actions`, and `state_actions`. CRUD action fields include `type`, `fields`, `extra_fields`, `label`, and `description`.

## Internal RPC

`internal_rpc` listens beside the HTTP port. Set `network` to `tcp` or `unix` and `address` to the socket, or set `fd` to an inherited listening descriptor. `fd` and `address` cannot both be set. An empty `internal_rpc` does not listen.

Clients call `TableGet`, `TableCreate`, `TableUpdate`, `TableDelete`, and `CallFunction` for `/api/{db}/{table}/` and `/api/{db}/rpc/{func}/`. Those calls do not authenticate and do not check scopes. Plugins that dial the host (`dbsession`, table-mode `dbglob`) need this listener. A zero `HostRPC` fails those calls with `host rpc is not configured`.

## Connection files

`plugin_configs: [./more.yaml]` loads extra YAML documents. Each document needs a `name:` field. A name already present in `plugins` is left as-is. Set `use_query: true` on a connection to make it `QUERY`-only.

## CORS

`cors.enabled` defaults to false. When the block is omitted, the other defaults are origins `["*"]`, methods `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`, the header list in `defaultCORS` (includes `X-Requested-With` plus the headers in the example above), and `max_age` `86400`.

## Server

Durations use Go's `time.ParseDuration` form (`5s`, `3m`). Defaults from `defaultServerConfig`:

| Field | Default |
| --- | --- |
| `read_timeout` | `5s` |
| `write_timeout` | `10s` |
| `idle_timeout` | `120s` |
| `read_header_timeout` | `5s` |
| `keep_alive_period` | `3m` |
| `max_header_bytes` | `1048576` (1 MiB) |
| `max_body_size` | `10485760` (10 MiB) |
| `trusted_proxy_mode` | `none` |
| `trusted_proxy_count` | `1` |

`trusted_proxy_mode` is `none`, `xff_count`, or `header`. `trusted_proxy_header` is the header name when the mode is `header` (for example `CF-Connecting-IP` or `X-Real-IP`).

HTTP/2 fields, left at zero unless set: `http2_max_concurrent_streams`, `http2_max_read_frame_size`, `http2_max_upload_buffer_per_connection`, `http2_max_upload_buffer_per_stream`, `http2_idle_timeout`, `http2_read_idle_timeout`, `http2_ping_timeout`, `http2_permit_prohibited_cipher_suites`.

`disable_html_escape` turns off `<`, `>`, and `&` escaping in JSON bodies.

## OpenTelemetry

`otel.enabled` stays false when `endpoint` is empty. Empty `protocol` becomes `otlp` (`otlp` or `otlphttp`). Empty `service_name` becomes `easyrest-server`.

## Flags

Repeat `-config` for each file. `-port`, `-access-log`, and `-plugin-log` are written into the YAML overlay only when present on the command line. See [internal/cli/cli.go](../cli/cli.go).

## See also

- [Server README](../../README.md)
- [HTTP API](../server/README.md)
- [Plugin SDK](../../plugin/README.md)
