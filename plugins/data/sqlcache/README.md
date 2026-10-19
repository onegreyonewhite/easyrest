# SQL cache store

Shared store for the SQL cache middleware binaries:

| Config key | Binary | URI |
| --- | --- | --- |
| `cache-postgres` | `easyrest-middleware-cache-postgres` | Postgres DSN (`postgres://...`) |
| `cache-mysql` | `easyrest-middleware-cache-mysql` | MySQL DSN (`mysql://...`) |
| `cache-sqlite` | `easyrest-middleware-cache-sqlite` | SQLite URI (`sqlite://...`) |

`InitConnection` creates `easyrest_cache` (`key`, `value`, `expires_at`) if it does not exist. The SQLite cache always deletes expired rows. Postgres and MySQL do that when the cache URI includes `autoCleanup=true` or `autoCleanup=1`. A CRUD connection URI strips `autoCleanup` and does not use this table.

```yaml
middleware_plugins:
  cache-postgres:
    settings:
      uri: postgres://user:pass@localhost:5432/app?sslmode=disable
      ttl: 24h
  cache-mysql:
    settings:
      uri: mysql://user:pass@tcp(localhost:3306)/app
      ttl: 24h
  cache-sqlite:
    settings:
      uri: sqlite:///tmp/cache.db
      ttl: 24h
```

ETag headers and `invalidation_map` are in [cache middleware](../../middleware/cache/README.md). This table is the revision store. It is not the table CRUD cache.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
