# Memcached cache store

Stores ETag revision tokens for the cache middleware. This package is not a database plugin. The binary is `easyrest-middleware-cache-memcached`, registered as middleware key `cache-memcached`.

The URI must start with `memcached://`. The rest is a comma-separated list of `host:port` servers. An empty server list fails init.

```yaml
middleware_plugins:
  cache-memcached:
    settings:
      uri: memcached://127.0.0.1:11211
      ttl: 24h
```

Several servers:

```yaml
uri: memcached://10.0.0.1:11211,10.0.0.2:11211
```

ETag behavior is in [cache middleware](../../middleware/cache/README.md).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [Redis](../redis/README.md)
