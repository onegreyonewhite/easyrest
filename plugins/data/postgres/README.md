# Postgres

Table CRUD, schema, and optional `QUERY`. The URI scheme is `postgres://`. `postgresql://` is rejected. `easyrest-server` keeps the plugin in-process. The external binary is `easyrest-plugin-postgres`. With both `use_query: true` and `internal: true`, the writable plugin also serves in-process `RawQuery` (no read-only transaction).

The plugin removes these query parameters before the rest of the URI is used as the pgx DSN:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `maxOpenConns` | `100` | Pool max connections (`MaxConns`) |
| `maxIdleConns` | `25` | Pool min connections (`MinConns`) |
| `connMaxLifetime` | `5` | Max connection lifetime, in minutes |
| `connMaxIdleTime` | `10` | Max idle time, in minutes |
| `timeout` | `30` | Query timeout, in seconds |
| `bulkThreshold` | `100` | Row count at which bulk insert switches strategy |
| `autoCleanup` | empty | Removed from a CRUD URI. On a `cache-postgres` URI, `true` or `1` deletes expired `easyrest_cache` rows. See [SQL cache](../sqlcache/README.md) |
| `search_path` | `public` | Schema search path |
| `require_auth` | empty | Passed to the pgx connection as `RequireAuth` and removed from the DSN |

Other query parameters, including `sslmode`, stay on the DSN.

```yaml
plugins:
  app:
    uri: postgres://user:pass@localhost:5432/app?sslmode=disable&search_path=public
    db_tx_end: commit-allow-override
    db_prefer_count: estimated
    db_max_rows: 10000
```

Example SQL for response settings is in [schemas/postgres.sql](../../../schemas/postgres.sql).

## Context

Before the statement, the plugin calls `set_config` (transaction-local) for each context key that [SkipDBSessionKey](../../../plugin/helpers.go) allows. Skipped keys are `response.*`, `cache.*`, hook names `db.pre-request` and `db.post-request`, and any key that starts with `_`. Each remaining key is stored twice: `request.<key>` (maps and slices as JSON) and `erctx.<key>`.

A leading underscore is middleware-to-middleware state for that request. Those keys stay on the context map. HTTP handlers read `response.header.*` from there.

Before `COMMIT`, the plugin harvests `response.*` (including `response.headers` and `response.status`) and `cache.invalidate` back into the context. `QUERY` does not return context, so it cannot harvest.

`db.pre-request` and `db.post-request` run as `SELECT name()`. The name comes from [dbqueryhook](../../middleware/dbqueryhook/README.md) or from anything else that set those context keys.

## JSON arrows

`->` and `->>` are sent to PostgreSQL as written (`json_data->'age'`, `json_data->>'blood_type'`). The filter value for `->` is cast on the right only (`?::jsonb`), so an index on `(json_data->'age')` can still match. The column must be `jsonb` for `>`, `<`, and the other ordering operators. `json` can still be selected and filtered with `->>`. The plugin does not wrap the column in `to_jsonb()`.

## Count

`exact` runs `SELECT count(*)` over the unbounded filtered select in the same transaction as the page.

`planned` reads `Plan Rows` from `EXPLAIN (FORMAT JSON)` and does not count rows. `estimated` starts from that value. The host replaces it with an exact count when it is strictly less than `db_max_rows`. See [Prefer](../../../internal/server/README.md#prefer).

## Shared transaction

`BeginTx` holds one `pgx.Tx` until `CommitTx`, `RollbackTx`, expiry, or `Close`. Later calls with `_tx` set run on that transaction. `prefer.tx` is ignored for those calls. `set_config` still runs on every joined statement. `db.pre-request` runs on the first one. `db.post-request` and the `response.*` / `cache.invalidate` harvest run in `CommitTx`.

At most 16 sessions stay open. Each one keeps a pool connection. The default lifetime is 30 seconds when the caller sets no deadline. A statement error aborts the session: `CommitTx` then returns `shared transaction aborted`.

Bulk insert at or above `bulkThreshold` returns `bulk create is not supported inside a shared transaction` and does not start another transaction. The caller contract is in [Plugin SDK](../../../plugin/README.md#shared-transaction) and [Embed](../../../embed/README.md#shared-transaction).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [SQLite](../sqlite/README.md)
- [MySQL](../mysql/README.md)
