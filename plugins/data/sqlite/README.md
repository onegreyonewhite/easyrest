# SQLite

Table CRUD, schema, and optional `QUERY` for a `sqlite://` URI. `easyrest-server` keeps the plugin in-process. The external binary is `easyrest-plugin-sqlite`, and it registers both `db` and `query`.

The URI is `sqlite://` plus a filesystem path, not a `file:` DSN. Query parameters the plugin consumes:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `cache_size` | `10000` | SQLite `cache_size` pragma |
| `mmap_size` | omitted | `mmap_size` pragma. Applied only when the value is greater than 0. Zero is accepted and leaves mmap unset. A negative value fails `InitConnection` |

Any other query string is passed through on the `file:` DSN the driver opens. A normal connection also sets `_busy_timeout=5000`. `use_query: true` opens the database read-only (`mode=ro`).

```yaml
plugins:
  crud:
    uri: sqlite:///var/lib/easyrest/app.db?cache_size=20000
    title: App
```

```yaml
plugins:
  query:
    uri: sqlite:///var/lib/easyrest/app.db
    use_query: true
```

`QUERY` is experimental. The body is still raw SQL. See [HTTP API](../../../internal/server/README.md#routes).

## Context

SQLite has no session variables. The plugin does not inject `request.*` or `erctx.*`, and it does not harvest `response.*` or `cache.invalidate`. A `QUERY` call never returns context. `db.pre-request` and `db.post-request` are ignored. Postgres and MySQL run those hooks. See [dbqueryhook](../../middleware/dbqueryhook/README.md).

Host flattening rules (`erctx.claims_sub`, dropping values that contain `;` or `--`) are in the [server README](../../../README.md#context-round-trip).

## JSON arrows

SQLite 3.38 and later accept the same `->` and `->>` chain as PostgreSQL, including `json_data->'phones'->0->>'number'`. Comparisons are parenthesized because those operators bind looser than `=` and `>`. `->>` compares as text. `->` equality uses `json(?)`. Ordering a `->` number uses `CAST((json_data->>'age') AS REAL)` so that `9` is not greater than `20`. Ordering a JSON string uses `->>`. Bool, null, object, and array values cannot be ordered this way. `->` results are decoded into JSON values after the query. `->>` numbers come back as text.

## Count

`exact` runs `SELECT count(*)` over the filtered select, including `WHERE` and `GROUP BY`, without `LIMIT`, `OFFSET`, or `ORDER BY`.

`planned` and the first step of `estimated` read the table estimate from `sqlite_stat1` (`ANALYZE`). That estimate is the whole table, not the filtered result. With no statistics, `total` is omitted and `Content-Range` stays `*`.

What the host does with `exact`, `planned`, and `estimated` is in [Prefer](../../../internal/server/README.md#prefer).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [Postgres](../postgres/README.md)
- [MySQL](../mysql/README.md)
