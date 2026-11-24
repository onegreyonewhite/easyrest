# Plugin SDK

This package is the contract between the HTTP server and a plugin process. A binary registers one or more RPC keys and serves them with `easyrest.Handshake`. `easyrest-server` registers in-process factories for the common data, auth, and middleware plugins, plus YAML and S3. The server package itself always registers the standard content plugins and the storage plugins `local`, `memory`, `dbglob`, and `static`, so `easyrest-gateway` has those too. Every other plugin is an executable.

A nil context map returned from a method means the caller keeps its existing map. A non-nil map replaces it.

## RPC keys

| Key | Interface | What it does |
| --- | --- | --- |
| `db` | `DBPlugin` | Table CRUD, functions, schema |
| `query` | `DBQueryPlugin` | One read-only SQL string |
| `auth` | `AuthPlugin` | Claims from a header or cookie |
| `middleware` | `MiddlewarePlugin` | `PreRequest` and `PostRequest` |
| `content` | `ContentPlugin` | Parse a body and render a response |
| `storage` | `StoragePlugin` | Store and serve object bytes |

A binary may register any subset of these keys. Cache backends are not a seventh key. They implement `cache.Store` and are wrapped as a middleware plugin. See [Cache store](#cache-store).

Interfaces live in [plugin.go](plugin.go), [content.go](content.go), and [storage.go](storage.go).

## How the server finds a binary

`easyrest-server` uses a preserved factory when `path` is empty and the name is registered in [cmd/server/main.go](../cmd/server/main.go) or by the server package (`json`, `ndjson`, `xml`, `csv`, `form`, `html`, `local`, `memory`, `dbglob`, `static`). A non-empty `path` always starts a subprocess, even when a factory exists. `easyrest-gateway` has those server-package factories and none of the `cmd/server` ones, so data, auth, middleware, YAML, and S3 take the subprocess path.

Search order when `path` is empty: `PATH`, the working directory, then the directory of the server executable. Each place is tried as the plain name and as `name-GOOS-GOARCH`.

| Family | Config source | Binary name |
| --- | --- | --- |
| Data | URI scheme | `easyrest-plugin-<scheme>` |
| Auth | `auth_plugins` key | `easyrest-auth-<key>` |
| Middleware | `middleware_plugins` key | `easyrest-middleware-<key>` |
| Content | `content_plugins` key | `easyrest-content-<key>` |
| Storage | `plugin`, or the key when `plugin` is empty | `easyrest-storage-<plugin>` |

Loading lives in [internal/server/plugin_load.go](../internal/server/plugin_load.go).

## Handshake

```go
var Handshake = plugin.HandshakeConfig{
    ProtocolVersion:  1,
    MagicCookieKey:   "EASYREST_PLUGIN",
    MagicCookieValue: "easyrest",
}
```

## Data and query

`InitConnection` receives the connection URI. `TableGet`, `TableCreate`, `TableUpdate`, `TableDelete`, `CallFunction`, and `GetSchema` may return an updated context. `QueryCall` returns rows only, so a query plugin cannot harvest session settings.

`QUERY` does not join a shared transaction. `DBQueryPlugin` has no begin, commit, or rollback method.

One process can register both keys, as [cmd/plugin-sqlite/main.go](../cmd/plugin-sqlite/main.go) does:

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "db":    &easyrest.DBPluginPlugin{Impl: sqlite.NewSqlitePlugin()},
        "query": &easyrest.DBQueryPluginPlugin{Impl: sqlite.NewSqliteQueryPlugin()},
    },
})
```

## Auth

```go
Init(settings map[string]any, host HostRPC) (AuthInfo, error)
Authenticate(headers map[string]string, method, path, query string) (map[string]any, error)
```

`AuthInfo.Schema` is an OpenAPI 3.0 security scheme. `AuthInfo.Key` is the header or cookie name. An empty key means `Authorization`. `IsCookie` true tells the host to read that cookie and copy its value into the header map passed to `Authenticate`. The plugin does not set the cookie.

[cmd/auth-jwt/main.go](../cmd/auth-jwt/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "auth": &easyrest.AuthPluginPlugin{Impl: &jwtAuth.JWTAuthPlugin{}},
    },
})
```

## Middleware

```go
Init(settings map[string]any, host HostRPC) (MiddlewareInfo, error)
PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error)
PostRequest(dbKey string, ctx map[string]any) (map[string]string, error)
```

A non-nil status from `PreRequest` stops the chain. `PostRequest` returns extra headers and cannot change the body. See [Request lifecycle](../README.md#request-lifecycle).

[cmd/middleware-ratelimit/main.go](../cmd/middleware-ratelimit/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "middleware": &easyrest.MiddlewarePluginPlugin{Impl: ratelimit.New()},
    },
})
```

## Content

```go
Init(settings map[string]any) (ContentInfo, error)
Parse(body []byte, ctx map[string]any) (any, map[string]any, error)
Render(data any, ctx map[string]any) (any, map[string]any, error)
PrepareGet(limit, offset, page int) (windows []ContentWindow, repeat bool)
PrepareCreate(body any, page int) []any
```

`ContentInfo` embeds `PluginMeta`, so `Metadata` and `Ctx` are empty maps when the plugin has nothing extra to report. `RenderMedia` is the response media type. `ParserMedia` is the request body media type. An empty media field means that direction is unsupported. `Format` is the `?format=` value. `PrepareGet` plans the next `TableGet` window. `repeat` true asks the host to call `PrepareGet` again after a full page. Embed `ContentBase` for the one-shot default.

[cmd/content-yaml/main.go](../cmd/content-yaml/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "content": &easyrest.ContentPluginPlugin{Impl: yamlcodec.New()},
    },
})
```

Name that binary `easyrest-content-yaml` for `content_plugins.yaml`.

## Storage

```go
Init(settings map[string]any, host HostRPC) (StorageInfo, error)
Put(path string, body []byte, ctx map[string]any) (rel string, ctxOut map[string]any, error)
PutStream(path string, r io.Reader, ctx map[string]any) (rel string, ctxOut map[string]any, error)
GetUrl(paths []string, ctx map[string]any) ([]StorageURL, error)
GetMetadata(path string, ctx map[string]any) (StorageMeta, error)
GetBin(path string, ctx map[string]any) (body []byte, mime string, ctxOut map[string]any, error)
GetStream(path string, offset int64, ctx map[string]any) (io.ReadCloser, mime string, ctxOut map[string]any, error)
List(path string, ctx map[string]any) ([]StorageEntry, error)
Delete(path string, ctx map[string]any) error
```

`Put` and `GetBin` are wrappers around `PutStream` and `GetStream`. The caller closes the reader it passes to `PutStream`. The implementation leaves that reader open. The caller closes the reader returned by `GetStream`. A negative `offset` is an error. An offset past the end yields a reader that returns EOF.

A preserved plugin loaded with an empty `path` reads and writes the stream in process. `local` copies into a temporary file in the destination directory and renames it. `s3` passes the reader to `PutObject` and returns `GetObject.Body`, using `Range: bytes=<offset>-` when the offset is greater than zero. `static` returns the open disk file or embedded file. `memory` and `dbglob` still store the whole object, then return a reader over those bytes. Inline mode still builds a data URL from the whole object.

An executable plugin keeps the `Put` and `GetBin` RPC methods. `StoragePluginRPC.PutStream` reads the reader and calls `Put`. `GetStream` calls `GetBin` and returns a reader over that slice.

`Init` returns the storage root and whether values are stored inline. A non-empty root with `inline` false mounts `GET /media/{name}/*`. The root string itself is not part of the URL. `inline` true means `Put`'s return value is the database cell and the response. That value is a data URL (`data:<media-type>;base64,<data>`). `ctx["storage.mime"]`, when it is a non-empty string, is the media type. The host does not call `GetUrl` and does not mount `/media` for that plugin.

There is no `cmd/storage-*` binary in this repo. A process that serves the memory driver looks like this:

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "storage": &easyrest.StoragePluginPlugin{Impl: memory.New()},
    },
})
```

Name it `easyrest-storage-memory`, or set `path` on the `storage_plugins` entry. The instance name is the map key. `plugin` selects the driver when it is set.

## Cache store

`cache.Store` is `InitConnection`, `Set`, and `Get`. Wrap it with `cache.New(store)` and register the result as `"middleware"`. [cmd/middleware-cache-redis/main.go](../cmd/middleware-cache-redis/main.go):

```go
hplugin.Serve(&hplugin.ServeConfig{
    HandshakeConfig: easyrest.Handshake,
    Plugins: map[string]hplugin.Plugin{
        "middleware": &easyrest.MiddlewarePluginPlugin{
            Impl: cachemw.New(redisPlugin.NewRedisCachePlugin()),
        },
    },
})
```

The binary name follows the middleware rule: `easyrest-middleware-cache-redis` for `middleware_plugins.cache-redis`.

## Shared transaction

Plugin API `v0.24.0` (`VersionMinor` 24) adds a transaction that outlives one `Table*` or `CallFunction` call. The driver connection stays in the database plugin process. Callers pass an opaque id. A `*sql.Tx`, a `pgx.Tx`, and a `context.Context` are not RPC values.

Postgres, MySQL, and SQLite implement this. A database plugin built with an older SDK does not serve `Plugin.BeginTx`, `Plugin.CommitTx`, or `Plugin.RollbackTx`. Rebuild it against this version. A current plugin that does not implement `DBTransactor` returns `shared transactions are not supported`.

The id is 16 random bytes, hex-encoded. The built-in plugins keep at most 16 open sessions. Another `Begin` returns `shared transaction limit reached`. The pool can still refuse a connection before that cap.

### Who calls it

An embed view or rest handler calls `call.Plugins.Begin`. That stays in the server process. See [Embed](../embed/README.md#shared-transaction).

Any other plugin that received `HostRPC` dials the same server and calls `Host.BeginSession`:

```go
session, err := host.BeginSession(ctx, "orders")
if err != nil {
    return err
}
defer session.Rollback(ctx)

created, err := session.TableCreate(easyrest.HostCall{
    Name:   "invoices",
    Header: map[string]string{"Content-Type": "application/json"},
    Body:   body,
})
if err != nil {
    return err
}
if created.Status >= 400 {
    return fmt.Errorf("invoices: %s", created.Body)
}
updated, err := session.TableUpdate(easyrest.HostCall{
    Name:   "stock",
    Header: map[string]string{"Content-Type": "application/json"},
    Body:   patch,
})
if err != nil {
    return err
}
if updated.Status >= 400 {
    return fmt.Errorf("stock: %s", updated.Body)
}
return session.Commit(ctx)
```

`BeginSession` stores the id. `TableGet`, `TableCreate`, `TableUpdate`, `TableDelete`, and `CallFunction` copy it into `HostCall.TxID`. An empty `HostCall.DB` becomes the session database. A different database returns `shared transaction is for database <key>`. `Host.Begin`, `Host.Commit`, and `Host.Rollback` are the same RPC calls without that helper. `Host.Commit` returns only an error. The harvested context from `CommitTx` is not sent back over internal RPC.

Those table methods return a nil error when the internal route wrote the failure as an HTTP status. Read `HostResult.Status`. A driver error is status 500 with a nil Go error, and it still aborts the session.

`internal_rpc` must be listening. A zero `HostRPC` fails with `host rpc is not configured`.

### What one session covers

One session is one config key, one driver transaction, and one pool connection. Two keys are two sessions. There is no two-phase commit and no savepoint API.

Joined calls still go through the internal table route: the same identifier checks, limits, content parsing, and middleware as `Host.TableCreate` without a session. The id travels in the internal header `X-Easyrest-Tx`. `buildPluginContext` copies that header into the plugin context key `_tx` only for an internal call. A public request that sends the header is unchanged. `_tx` starts with `_`, so [SkipDBSessionKey](helpers.go) does not write it into `set_config` or a MySQL session variable.

While `_tx` is set, the plugin uses the stored transaction and ignores `prefer.tx`, including `rollback`. The session ends only on commit, rollback, expiry, or plugin `Close`.

`DB` keys are matched case-insensitively and stored lowercased.

### Lifetime

`Begin` reads the deadline from the Go context. That absolute time is sent as `HostTxRequest.Deadline` and stored for the plugin as `_tx_deadline` (`time.Time` or an RFC3339Nano string). No deadline means 30 seconds (`SharedTxDefaultLifetime`), the same default as the Postgres query timeout. The reaper runs about once a second and rolls the session back. A call that still holds the session is left until it returns. `Close` rolls back every session still open.

For `database/sql`, the `BeginTx` context lives until commit, rollback, or that deadline. Canceling the caller's request context does not cancel it. Doing so would roll the driver transaction back on the next statement. pgx is begun with a background context and rolled back explicitly.

SQLite holds its writer lock for the whole session. Postgres and MySQL hold one pool connection for the whole session.

### Commit, rollback, and errors

Uncommitted rows are invisible to other connections. `Rollback` leaves none of them. `Commit` makes every statement from that session visible together.

`Rollback` after a successful `Commit` returns nil and does not call the plugin again. A second `Commit` returns `shared transaction finished`. `Rollback` of an id the registry no longer has also returns nil.

A statement error marks the session aborted. `Commit` returns `shared transaction aborted` and does not run the commit function. The next joined call is HTTP 500 with that text in the body. `Rollback` still releases the connection. A failure that happens before the plugin enters the stored transaction, such as a bad table name rejected by the HTTP handler, leaves the session open.

A second call on the same id while the first is running returns `shared transaction is in use` and does not wait. `database/sql` does not promise concurrent use of one `Tx`.

Postgres refuses bulk insert inside a session when the row count reaches `bulkThreshold`. The error is `bulk create is not supported inside a shared transaction`. That path does not open a second transaction. Smaller inserts use the shared transaction.

Error text is what crosses RPC. `errors.Is` with `ErrSharedTxAborted` and the other sentinels works for an in-process database plugin. A subprocess, and every `Host` client, returns `errors.New` of that same text.

| Text | When |
| --- | --- |
| `shared transactions are not supported` | The loaded database plugin does not implement `DBTransactor` |
| `shared transaction not found` | Unknown id, or the session expired or was finished |
| `shared transaction finished` | `Commit` or another call after this session object already finished |
| `shared transaction aborted` | A statement failed; commit is refused |
| `shared transaction is in use` | This id is inside another call |
| `shared transaction limit reached` | This plugin already holds 16 sessions |
| `database "<key>" is not loaded` | No database plugin for that config key |

### Hooks and harvested context

On Postgres and MySQL, session context (`set_config` or `SET @erctx_…`) is applied on every joined statement. `db.pre-request` runs on the first joined statement. `db.post-request` and the harvest of `response.*` and `cache.invalidate` run inside `CommitTx`, once. SQLite ignores those hooks, as it does for a normal request.

Joined calls return a nil context map, so the caller keeps the map it already had. Settings written by a trigger during an intermediate statement are not harvested until commit.

Response middleware still runs after each internal call, before `Commit`. A cache middleware can store that response, or bump an etag, while the database transaction is still open. `Rollback` does not delete that cache entry.

### Implementing DBTransactor

```go
type DBTransactor interface {
    BeginTx(ctx map[string]any) (string, map[string]any, error)
    CommitTx(id string, ctx map[string]any) (map[string]any, error)
    RollbackTx(id string) error
}
```

`DBPlugin` does not include these methods. Existing stubs still compile. `DBPluginRPC` implements `DBTransactor` and forwards the three calls. The server type-asserts the loaded plugin.

`BeginTx` starts the driver transaction and returns the id. Read the deadline with `SharedTxDeadline`. `CommitTx` commits that transaction and returns harvested context; a nil map means the caller keeps its existing map. `RollbackTx` of an unknown id returns nil.

On `TableGet`, `TableCreate`, `TableUpdate`, `TableDelete`, and `CallFunction`, read the id with `SharedTxID`. When it is set, run the statement on the stored transaction and do not commit or roll back there. `plugin.SharedTx[T]` is the registry the built-in drivers use: `Put`, `Use`, `Commit`, `Rollback`, and `Close`. `Use` marks the session aborted when the callback returns an error. `Commit` then refuses to run its callback. The registry does not store a `context.Context`.

`GetSchema` is not part of the session.

## Host RPC

`HostRPC` is the dial target for the internal RPC server. `Network` and `Address` are what a later call dials. A zero value does not dial. Calls then fail with `host rpc is not configured`. Auth, middleware, and storage `Init` receive this value. Plugins that read or write rows (`dbsession`, table-mode `dbglob`) need a listening `internal_rpc`. See [internal RPC](../internal/config/README.md#internal-rpc).

`HostCall.TxID` joins one of those row calls to a session started with `Begin`. The field is empty for an ordinary call. See [Shared transaction](#shared-transaction).

## See also

- [Server README](../README.md)
- [HTTP API](../internal/server/README.md)
- [Embed](../embed/README.md)
- [Configuration](../internal/config/README.md)
