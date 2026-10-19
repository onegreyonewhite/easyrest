# Redis cache store

Stores ETag revision tokens for the cache middleware. This package is not a database plugin. The binary is `easyrest-middleware-cache-redis`, registered as middleware key `cache-redis`.

`InitConnection` accepts `redis://` and `rediss://`. It parses the URL with the Redis client and pings the server. A failed ping closes the client and fails plugin init.

Put the URI on the middleware settings, not under `plugins:`:

```yaml
middleware_plugins:
  cache-redis:
    settings:
      uri: redis://localhost:6379/0
      ttl: 24h
```

ETag headers, `ttl`, and `invalidation_map` are documented in [cache middleware](../../middleware/cache/README.md).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [Memcached](../memcached/README.md)
- [LRU](../lru/README.md)
