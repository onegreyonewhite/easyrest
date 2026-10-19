# Rate limit

Fixed-window limiter. `easyrest-server` keeps it in-process. The external binary is `easyrest-middleware-ratelimit`.

| Key | Default | Meaning |
| --- | --- | --- |
| `limit` | `100` | Requests allowed in the window. Must be greater than 0 |
| `period` | `1m` | Window length. A number is seconds. A string is a Go duration (`1m`, `30s`). Must be greater than 0 |
| `cache_size` | `1024` | How many window counters to keep |
| `key` | `global` | `global`, `ip`, or `cookie` |
| `cookie` | empty | Cookie name. Required when `key` is `cookie` |

Over the limit, `PreRequest` returns 429. The response includes `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining`. `key: cookie` also sets a cookie when the client did not send one.

```yaml
middleware_plugins:
  ratelimit:
    settings:
      limit: 100
      period: 1m
      key: ip

global_request_middlewares:
  - ratelimit
```

The same name can sit on one connection's `request_middlewares` instead of the global list.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
