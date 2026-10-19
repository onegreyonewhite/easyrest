# HTTP API

Routes, query language, content negotiation, and auth live here. Connection fields are in [Configuration](../config/README.md). Format-specific parse and render rules are in each content plugin README.

## Routes

| Method | Path | Plugin | Auth |
| --- | --- | --- | --- |
| `GET` | `/api/{db}/` | `DBPlugin.GetSchema` | none |
| `QUERY` | `/api/{db}/` | `DBQueryPlugin.QueryCall` | yes, scope `read` |
| `POST` | `/api/{db}/rpc/{func}/` | `DBPlugin.CallFunction` | yes, scope `{func}-write` |
| `GET` `POST` `PATCH` `DELETE` | `/api/{db}/{table}/` | `TableGet` / `Create` / `Update` / `Delete` | yes, `{table}-read` or `{table}-write` |
| `GET` | `/health` | none | none |

`{db}` is the key under `plugins:` (lowercased). A connection with `use_query: true` only serves `QUERY`. Table CRUD and schema are unavailable for that name. `internal: true` removes the key from every public `/api/{db}/` route, including `QUERY` and a schema that was already cached, and leaves that connection available as a `/restapi` source. The internal RPC listener still reaches it and does not run HTTP auth.

`Accept: text/html` or `?format=html` on `/`, `/api/{db}/`, `/restapi/`, and `/restapi/{api}/` returns a Swagger UI page. The page does not contain the document. Swagger UI loads it from the same path with the first non-HTML format, usually `?format=json`. `GET /` lists every database schema whose plugin is not `internal` and not `use_query`, plus every restapi schema. Those spec URLs are absolute, including `X-Forwarded-Prefix`. With `tls_enabled`, the scheme is `https`. `X-Forwarded-Proto` and `Forwarded` choose the scheme only while TLS is off. Swagger UI's CSS and JavaScript are served from `/media/static/`. A file of the same name in the `static` storage directory replaces the copy embedded in the server. See [Swagger UI](../../plugins/content/swaggerui/README.md) and [static storage](../../plugins/storage/static/README.md).

`QUERY` is experimental. Give it a dedicated connection and a database user that can only `SELECT`. The plugin opens a read-only transaction, but the body is still raw SQL.

Schema responses are cached per connection. A cache hit returns immediately and skips middleware.

## Select, aliases, aggregates

```
GET /api/app/users/?select=id,name
GET /api/app/users/?select=username:name
GET /api/app/orders/?select=total:amount.sum(),order_date
GET /api/app/users/?select=count()
```

Allowed functions: `count`, `sum`, `avg`, `min`, `max`. Non-aggregated select fields become `GROUP BY`. Identifiers must match `[A-Za-z_][A-Za-z0-9_]*`.

## Filters and ordering

`where.<op>.<field>=value`, optional `not`:

| Operator | SQL |
| --- | --- |
| `eq` `neq` `lt` `lte` `gt` `gte` | `=` `!=` `<` `<=` `>` `>=` |
| `like` `ilike` `is` `in` | `LIKE` `ILIKE` `IS` `IN` |

```
GET /api/app/users/?where.eq.city=Berlin
GET /api/app/users/?where.gt.age=40
GET /api/app/users/?where.not.eq.name=Alice
GET /api/app/users/?where.in.id=1,2,3
GET /api/app/users/?where.eq.name=request.claims.sub
```

`ordering` is a comma-separated list of plain identifiers. The query language has no `ASC`/`DESC` token or any other way to set sort direction.

## Pagination

Default page size is `default_limit` (100 unless overridden per connection). `Prefer: page_size=N` (positive integer, space-separated like other Prefer tokens) replaces that default. Invalid, zero, or negative `page_size` is ignored.

You can page with the `limit` and `offset` query parameters, or with the headers `Range-Unit: items` plus `Range: 0-9` (inclusive). When both are present, the headers win.

JSON and XML GET are one shot. The page size comes from the first of these that is set: Range, `?limit=`, `page_size`, `default_limit`. Those responses include `Content-Range`, `Range-Unit: items`, and `Accept-Ranges: items`. `Content-Range` is `start-end/*` unless `prefer.count` produced a `total`, in which case the star is that number (`0-9/40`). An unsatisfiable range returns 416 with an empty body. CSV GET uses the same chunked read as NDJSON when `page_size` or `default_limit` is positive: the first chunk includes the header row, and later chunks are data rows only.

`GET` with `Accept: application/x-ndjson` (or `?format=ndjson`) streams matching rows as one JSON object per line. The same loop serves CSV. It repeats `TableGet` in chunks of `page_size` (or `default_limit` if Prefer did not set it), flushes headers as soon as the first page succeeds, flushes again after each page, and may fetch the next chunk while the current page is written. `?limit=` and Range do not disable paging: they cap how many rows are sent (`Range` also sets offset and still wins over query). The last `TableGet` uses `min(page size, remaining)`. The stream stops on a short page, when the cap is reached, when a count says the rows are exhausted, or when the client disconnects. With neither a cap nor a count, full pages continue. Pass `ordering` for a stable offset walk. A later-page failure appends an error object and leaves the status at 200. First-page plugin errors stay HTTP 500, rendered by the same content plugin. `WriteTimeout` is refreshed after each flushed page so a long export is not killed by the total response timer. `QUERY` still runs one `QueryCall`. Only the response renderer changes.

NDJSON responses do not send a `Content-Range` header, even when `limit` or Range caps the total. After the body they send two HTTP trailers: `X-Content-Range` (`start-end/*`, or `start-end/<total>` when the first page counted rows, same arithmetic as JSON `Content-Range`) and `Server-Timing` with the summed `TableGet` time. Later NDJSON pages do not repeat the count. The `Server-Timing` header at the top of the response still covers only the first page. Go's HTTP/2 stack cannot send `Content-Range` as a trailer, so the trailer name is `X-Content-Range`. Clients that hide HTTP/1.1 trailers should use HTTP/2 or inspect declared `Trailer` names.

Table GET still returns one object per NDJSON line and does not add a pagination envelope. A REST list is different: the first NDJSON line is `{count?, next, previous}` and later lines are rows. Later pages of that response do not repeat count, next, or previous. JSON REST lists stay one object, `{count?, next, previous, results}`. `next` is null unless a count is present and `offset+limit` is still below it. `previous` is null when `offset` is 0. CSV REST lists put pagination in a `Link` header (`rel="prev"`, `rel="next"`, and `rel="count"; total="N"` when a count is present) and the body is the result rows.

`POST` uses the renderer's `PrepareCreate`. JSON sends the body in one `TableCreate`. NDJSON splits an array into `page_size` chunks and writes each chunk after the first response headers. `PATCH` stays one object. `Server-Timing: db;dur=...` reports plugin time (NDJSON: first page in the header, total in the trailer).

## Formats

JSON is the default. Parsers and renderers are content plugins (`json`, `ndjson`, `xml`, `csv`, `form`). The five standards are always loaded in-process. A `content_plugins` entry with a `path` replaces that name with an RPC plugin (`easyrest-content-<name>`). `yaml` is not one of those five. `easyrest-server` keeps it in-process when `content_plugins.yaml` is set. Every other process, including tests, loads `easyrest-content-yaml` from `PATH` when that entry has an empty path. See [YAML](../../cmd/content-yaml/README.md).

The renderer is the first match in this order:

1. `?format=` (plugin format name or media type). An unknown value does not force JSON. Selection continues.
2. `Accept` tokens sorted by quality (`q`, default `1.0`, higher first). Equal `q` keeps header order. `q=0` is skipped. An empty `Accept` and an exact `*/*` are not matches. Other media-type parameters are passed to the renderer as `content.params`. JSON reads `indent` as a space count (`Accept: application/json; indent=2`).
3. The request `Content-Type`, so the response can match the body.
4. The first configured handler that can render.

The parser uses `Content-Type` only. An empty `Content-Type` selects the first allowed parser. A parser miss does not change the renderer.

Which names are allowed comes from the first non-empty list: the REST endpoint `content_handlers`, the REST app `content_handlers`, the db plugin `content_handlers`, then `default_content_handlers`. If every list is empty, the standards are `json`, `ndjson`, `xml`, `csv`, `form`.

REST create, update, state PUT, and POST actions can also accept `multipart/form-data` or `multipart/mixed` when the action schema has a field `type: string, format: binary`, or an array of those. That parser is built in and always available. It is not a content plugin and it does not render. One part has no filename. Its `Content-Type` selects the usual parser (`application/json` when the part omits a type). Every other part is a file whose form name is the field name. A list field repeats that name. The file bytes go to the action's storage plugin. `application/x-www-form-urlencoded` is the [form](../../plugins/content/form/README.md) content plugin, not this parser.

A field `type: string, format: base64` stays on the normal content parser. The string is standard base64. The decoded bytes go to the same storage plugin. An empty string leaves the field unset. Invalid base64 is 400.

`local` and `memory` store a relative path. A list is a JSON array of paths. Responses that return the field call `GetUrl` and send an absolute URL, or an array of URLs. GET schemas for list, retrieve, and state publish those fields as `format: uri`. POST, PATCH, and PUT request schemas keep `binary` or `base64`.

`dbglob` inline mode stores standard base64 in the column and returns it unchanged. Nothing is mounted at `/media/dbglob`. GET schemas then use `format: base64`. See [dbglob](../../plugins/storage/dbglob/README.md).

`local`, `memory`, and `s3` honor `settings.inline`. `true` still stores the bytes and makes `Put` return standard base64, so the column and the response are that string. `false` and a missing key keep the relative path.

Which storage instance a REST action uses is described in [Configuration](../config/README.md#application-and-restapi).

## Prefer

`Prefer: timezone=UTC tx=rollback page_size=50 count=exact`

- `timezone` is used when formatting timestamps and is stored on the context.
- `tx` is `commit` or `rollback`. It is honored only when the connection's `db_tx_end` ends in `-allow-override`.
- `page_size` sets the NDJSON and CSV `TableGet` chunk size. On JSON and XML GET it acts as the `limit` when Range and a positive `?limit=` are absent.
- `count` is `exact`, `planned`, or `estimated`. Any other value is ignored and is not echoed. A recognized mode is echoed as `count=` in `Preference-Applied`.

`count` asks the sqlite, postgres, and mysql plugins for `total`: the number of rows in the filtered result, including `WHERE` and `GROUP BY`, without `LIMIT`, `OFFSET`, or `ORDER BY`. The server writes that number into `Content-Range` and the NDJSON `X-Content-Range` trailer.

- `exact` asks the plugin for `SELECT count(*)` over that unbounded select in the same transaction as the page.
- `planned` asks for a planner estimate and does not count rows. Where the number comes from is documented on [SQLite](../../plugins/data/sqlite/README.md), [Postgres](../../plugins/data/postgres/README.md), and [MySQL](../../plugins/data/mysql/README.md). With no statistics, `total` is omitted and the range stays `*`.
- `estimated` takes the planned value. If that value is strictly less than `db_max_rows`, it is replaced by an exact count. Equality keeps the planned value. If there is no planned value, exact is not run.

When the client omits `count`, `db_prefer_count` is copied into `prefer.count` if it is one of those three modes. A client `count` token wins, including an unrecognized one. `db_max_rows` defaults to 10000 when omitted or zero. The server sends it to the plugin on every request.

The applied values are echoed in `Preference-Applied`. Other `Prefer` tokens are passed through as `ctx["prefer"]`.

YAML `db_tx_end` defaults to `commit`. Valid values: `commit`, `commit-allow-override`, `rollback`, `rollback-allow-override`.

## Auth and scopes

Plugins are tried in a fixed order: `jwt`, `jwtsession`, `basic`, `apikey`, `dbsession`, `oidc`, `awssigv4`, then any other names alphabetically. The first success wins. Claims are cached when `token_cache_ttl` is positive. The cache key is every loaded plugin's declared header or cookie value, sorted by plugin name. A request with no declared credential is not cached.

A plugin with `AuthInfo.IsCookie` true declares a cookie name in `AuthInfo.Key`. The host reads that cookie and copies the value into the header map before `Authenticate`. The plugin does not set the cookie. `jwtsession` and `dbsession` use this path. See [JWT session](../../plugins/auth/jwtsession/README.md) and [DB session](../../plugins/auth/dbsession/README.md).

If every plugin fails and `anon_claims` is set, the request continues with those claims and an empty user id. Without `anon_claims`, the response is 401.

`check_scope` (default on) requires a `scope` claim. A claim of `read` or `write` satisfies any required scope that ends with that word (`users-read`, `orders-write`). Per-table `public` lists skip the scope check but still go through `Authenticate`, so unauthenticated public access needs `anon_claims`.

`exclude` hides objects from the API. `allow` is an allow-list: when non-empty, only those tables or functions exist.

## See also

- [Server README](../../README.md)
- [Configuration](../config/README.md)
- [Plugin SDK](../../plugin/README.md)
