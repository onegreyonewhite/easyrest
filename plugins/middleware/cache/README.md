# Cache middleware

ETag and lost-update checks for table routes. The plugin stores a revision UUID and wraps a [cache.Store](../../../plugin/README.md#cache-store). Schema and `QUERY` are not cached: a request with no table in the context is skipped.

`easyrest-server` preserves `cache-redis`, `cache-postgres`, `cache-mysql`, `cache-sqlite`, `cache-memcached`, and `cache-lru`. Each binary is `easyrest-middleware-<key>`.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `uri` | empty string | Passed to the store's `InitConnection`. Required by Redis, Memcached, and the SQL stores. See the store README |
| `ttl` | `24h` | Lifetime of a revision token. Must be greater than 0. A number is seconds |
| `invalidation_map` | empty | After a function call, bump the listed tables |

`invalidation_map` is a map of connection name to function name to table names:

```yaml
middleware_plugins:
  cache-redis:
    settings:
      uri: redis://localhost:6379/0
      ttl: 24h
      invalidation_map:
        app:
          refresh_orders: [orders, order_items]

plugins:
  app:
    uri: postgres://user:pass@localhost:5432/app?sslmode=disable
    request_middlewares: [cache-redis]
```

Attach the same name with `global_request_middlewares` or a connection's `request_middlewares`.

Stores: [Redis](../../data/redis/README.md), [Memcached](../../data/memcached/README.md), [in-memory](../../data/lru/README.md), [SQL](../../data/sqlcache/README.md).

## ETag

The store key is `etag:<dbKey>:<table>`. The value is a UUID.

The response `ETag` is a quoted tag whose opaque form is `<uuid>:<major>.<minor>:<fp>`. `major.minor` is the plugin API version (`plugin.VersionMajor` and `VersionMinor`). `fp` is the first 16 hex characters of the SHA-256 of the Vary fingerprint. `Resource-Version` is the UUID only.

The fingerprint is built by the host from `Accept`, `Content-Type`, `Prefer`, `Range`, and `Range-Unit`. It does not include `Accept-Language`.

Buffered JSON and XML GET/HEAD responses use a strong tag. NDJSON, CSV, a non-empty `Range`, and writes use a weak tag (`W/"..."`).

`If-None-Match` on GET/HEAD uses weak comparison and returns 304. Unquoted tags are not recognized, so they do not 304.

Lost-update checks, in order:

1. `If-Resource-Version` compared to the stored UUID.
2. A weak `If-Match: W/"<rev>"` compared to that UUID.
3. A strong `If-Match` compared to the request representation ETag.

A mismatch is 412.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [Configuration](../../../internal/config/README.md)
