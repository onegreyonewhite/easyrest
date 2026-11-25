# MySQL

Table CRUD, schema, and optional `QUERY` for a `mysql://` URI. `easyrest-server` keeps the plugin in-process. The external binary is `easyrest-plugin-mysql`. With both `use_query: true` and `internal: true`, the writable plugin also serves in-process `RawQuery` (no `START TRANSACTION READ ONLY`).

The plugin removes these query parameters before building the driver DSN:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `maxOpenConns` | `100` | Maximum open connections |
| `maxIdleConns` | `20` | Maximum idle connections |
| `connMaxLifetime` | `5` | Connection reuse time, in minutes |
| `connMaxIdleTime` | `10` | Connection idle time, in minutes |
| `timeout` | `30` | Query timeout, in seconds |
| `autoCleanup` | empty | Removed from a CRUD URI. On a `cache-mysql` URI, `true` or `1` deletes expired `easyrest_cache` rows. See [SQL cache](../sqlcache/README.md) |

`parseTime` is left on the DSN so the driver can parse `TIME`, `TIMESTAMP`, and `DATETIME` as `time.Time`. Other parameters stay on the DSN too.

```yaml
plugins:
  legacy:
    uri: mysql://user:pass@tcp(localhost:3306)/app?parseTime=true
    db_tx_end: commit
```

Example SQL for response settings is in [schemas/mysql.sql](../../../schemas/mysql.sql).

## Context

The plugin writes session variables `SET @erctx_<key> = ?, @request_<key> = ?` for keys that [SkipDBSessionKey](../../../plugin/helpers.go) allows. Skipped keys are `response.*`, `cache.*`, hook names, and keys that start with `_`. A `timezone` context value is also applied as `time_zone`.

Before the statement returns, known response variables are harvested: `response.headers`, `response.status`, and `cache.invalidate`. `QUERY` does not return context.

`db.pre-request` and `db.post-request` run as `CALL name()`. See [dbqueryhook](../../middleware/dbqueryhook/README.md).

## JSON arrows

MySQL has `->` and `->>`, but the right side is one JSON path. `json_data->'phones'->0->>'number'` is sent as `json_data->>'$.phones[0].number'`. `->` filters use `CAST(? AS JSON)`, so numbers compare numerically. `->>` compares as text. Quoted select aliases are rewritten with backticks.

## Count

`exact` runs `SELECT count(*)` over the unbounded filtered select in the same transaction as the page.

`planned` reads `rows_examined_per_scan` from `EXPLAIN FORMAT=JSON`. In a join, that is the last table. `estimated` starts from that value. See [Prefer](../../../internal/server/README.md#prefer).

## Shared transaction

`BeginTx` takes one connection from the pool and starts `*sql.Tx` on it. Later calls with `_tx` set use that pair. `prefer.tx` is ignored for those calls. Session variables are applied on every joined statement. `db.pre-request` runs on the first one. `db.post-request`, the harvest, and `clear` of the known response variables run in `CommitTx`.

At most 16 sessions stay open. Each one keeps its connection until commit, rollback, expiry, or `Close`. The default lifetime is 30 seconds when the caller sets no deadline. A statement error aborts the session. The caller contract is in [Plugin SDK](../../../plugin/README.md#shared-transaction) and [Embed](../../../embed/README.md#shared-transaction).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [SQLite](../sqlite/README.md)
- [Postgres](../postgres/README.md)
