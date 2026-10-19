# In-memory cache store

Stores ETag revision tokens in process memory. This package is not a database plugin and it is not an LRU cache. The binary is `easyrest-middleware-cache-lru`, registered as middleware key `cache-lru`. The name is historical.

The URI is not a server address. `InitConnection` reads two query parameters. The parameter named `maxOpenConns` is a Go duration used as the default expiration when `Set` is called with a non-positive TTL. `cleanupInterval` is how often expired items are removed.

| Parameter | Default |
| --- | --- |
| `maxOpenConns` | `5m` |
| `cleanupInterval` | `10m` |

An unparsable URI is ignored and the defaults are used.

```yaml
middleware_plugins:
  cache-lru:
    settings:
      uri: "memory://local?maxOpenConns=5m&cleanupInterval=10m"
      ttl: 24h
```

The middleware `ttl` is what `Set` receives for a revision token. The URI durations apply when that TTL is not positive, and to the janitor. ETag behavior is in [cache middleware](../../middleware/cache/README.md).

Data is lost when the process exits.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [Redis](../redis/README.md)
