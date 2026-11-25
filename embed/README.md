# Embed

`embed` runs the EasyREST server inside another program. `Serve` loads config and serves HTTP until the context is canceled. `Handler` returns that HTTP handler without listening. Options register routes, in-process plugin factories, rest handlers, and views before config is loaded.

```go
err := embed.Serve(ctx, "", []string{"config.yaml"},
    embed.WithView("invoice", invoiceView),
)
```

`Call`, `View`, `RestHandler`, and `PluginCaller` are the same types as the server package. A view registered with `WithView` is selected by the restapi `handler` field. Authentication, the scope check, and request middleware have already run. The function writes the status, headers, and body. Content plugins do not render that response, and response middleware of the view request does not run. The route contract is in [Rest views](../internal/server/README.md#rest-views).

`call.Plugins` is the in-process caller: table get, create, update, delete, a function call, cache, and storage. On a database connection with both `use_query: true` and `internal: true`, `Query(ctx, db, sql)` runs one writable SQL statement on that same connection. Statements without rows return an empty slice. `Query` does not join a shared transaction from `Begin` and does not bind parameters. Those calls do not forward the view's token. A rest handler from `WithRestHandler` receives the same caller and returns a value for the content plugins to render.

A task from `WithService` receives the same `PluginCaller` as its second argument after config and plugins load, for example `plugins.Query(ctx, "orders", "select 1")`. `Query` and the deadline passed into `Begin` follow the service context. Table get, create, update, delete, and function calls use the same internal dispatch as views and are not tied to that context.

## Shared transaction

`Begin` opens one database transaction on one config key. Later calls on the returned session run inside it. `Commit` makes them visible together. `Rollback` drops them. The driver connection stays in the database plugin. The session id is a random string.

```go
func invoiceView(w http.ResponseWriter, call embed.Call) {
    session, err := call.Plugins.Begin(call.Context, "orders")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer session.Rollback(call.Context)

    created, err := session.TableCreate(easyrest.HostCall{
        DB:     "orders",
        Name:   "invoices",
        Header: map[string]string{"Content-Type": "application/json"},
        Body:   invoiceJSON,
    })
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    if created.Status >= 400 {
        http.Error(w, string(created.Body), created.Status)
        return
    }
    updated, err := session.TableUpdate(easyrest.HostCall{
        DB:     "orders",
        Name:   "stock",
        Header: map[string]string{"Content-Type": "application/json"},
        Body:   stockJSON,
    })
    if err != nil || updated.Status >= 400 {
        return
    }
    harvested, err := session.Commit(call.Context)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    _ = harvested
    w.WriteHeader(http.StatusNoContent)
}
```

`defer session.Rollback` is safe after a successful `Commit`. That later rollback returns nil and does not call the plugin. A second `Commit` returns `shared transaction finished`.

`TableCreate` and the other session methods take the same `HostCall` as a single plugin call. `Body` is the raw request body the public route would accept. A JSON create is an array of objects and needs `Content-Type: application/json`. `Query` is the raw query string (`select=id,name&where.eq.status=open`). An empty `DB` is filled with the session key. A different key returns `shared transaction is for database <key>`.

The result is an HTTP status, headers, and body, because the call goes through the internal table route. `TableCreate` and the other session methods return a nil Go error when that route handled the failure itself. Read `Status`. A bad table name or a rejected body is a 4xx and leaves the session open. A driver error is a 500 and aborts the session. The Go error of that call is still nil. `Commit` then returns `shared transaction aborted`. Another joined call is also HTTP 500, and the body contains that text.

### What is included

One session is one database key and one transaction. Postgres, MySQL, and SQLite implement it. `QUERY` and `DBQueryPlugin` do not. Cache and storage calls on `PluginCaller` do not join the transaction. Two database keys need two sessions; there is no two-phase commit.

Public HTTP is unchanged. `Prefer: tx=commit` or `tx=rollback` still starts and ends its own transaction for that one request. A client header `X-Easyrest-Tx` is ignored. Only the internal dispatch of a session call sets that header, and only an internal call copies it into the plugin context key `_tx`.

While the session is open, `prefer.tx` on a joined call is ignored. The statements stay open until `Commit`, `Rollback`, expiry, or plugin close.

Uncommitted rows are not visible on another connection. After `Rollback`, none of the session's rows remain. After `Commit`, all of them do.

### Deadline and capacity

The deadline is `call.Context`'s deadline when it has one. Otherwise the session lives 30 seconds. The plugin checks about once a second and rolls an expired session back. Canceling the HTTP request does not by itself roll the driver transaction back; the deadline passed to `Begin` does.

Each open session holds one pool connection. SQLite holds the writer lock for the whole session. Each database plugin allows 16 open sessions. The next `Begin` returns `shared transaction limit reached`. The pool can refuse earlier.

A statement error marks the session aborted. `Commit` returns `shared transaction aborted` and does not commit. Call `Rollback` to release the connection. A rejection that never reaches the stored transaction, such as an unknown table at the HTTP layer, leaves the session usable.

Two calls on one session at the same time: the second gets `shared transaction is in use` and does not wait.

Postgres bulk insert at or above `bulkThreshold` returns `bulk create is not supported inside a shared transaction`. Inserts below that threshold use the shared transaction.

### Context, hooks, and cache

Joined calls return no replacement context map. On Postgres and MySQL, `set_config` or the MySQL session variables still run for every joined statement. `db.pre-request` runs on the first joined statement. `db.post-request` and the harvest of `response.*` and `cache.invalidate` run when `Commit` succeeds. `Commit` returns that harvested map. SQLite has no session variables and does not harvest; `Commit` returns a nil map.

The view writes its own response. Harvested `response.status` and `response.headers` are not applied to `ResponseWriter` for you. Read the map from `Commit` if the view needs them.

Each joined call still runs request and response middleware before `Commit` returns. A cache middleware can store the internal response while the database transaction is open. `Rollback` does not remove that cache entry.

### Errors

In-process Postgres, MySQL, and SQLite return the sentinels below, so `errors.Is` works. A wrapped driver failure, such as a commit error, keeps its own text.

| Text | Meaning |
| --- | --- |
| `shared transactions are not supported` | This database plugin has no `DBTransactor` |
| `shared transaction not found` | Unknown id, or it expired or was already finished |
| `shared transaction finished` | `Commit` or a later call on a session that already finished |
| `shared transaction aborted` | A statement failed; commit is refused |
| `shared transaction is in use` | Another call is using this session |
| `shared transaction limit reached` | 16 sessions are already open on this plugin |
| `database "<key>" is not loaded` | No plugin for that config key |
| `database name is empty` | `Begin` was called with an empty name |

A plugin process that was built before plugin API v0.24.0 does not serve begin, commit, or rollback. Rebuild it. The external-plugin form of this API is `Host.BeginSession` in the [Plugin SDK](../plugin/README.md#shared-transaction).

## See also

- [Server README](../README.md)
- [HTTP API](../internal/server/README.md)
- [Plugin SDK](../plugin/README.md)
- [Configuration](../internal/config/README.md)
