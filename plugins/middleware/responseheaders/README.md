# Response headers

Adds static response headers through the plugin context. `easyrest-server` keeps it in-process. The external binary is `easyrest-middleware-response_headers`.

`PreRequest` does nothing. `PostRequest` writes `response.header.*` keys (and adjusts `response.headers` when needed). The HTTP host emits those keys once, after all middleware runs. The plugin does not return a header map from `PostRequest`.

Conflict detection uses only the context: existing `response.header.*` values and `response.headers` entries for the same canonical header name. Headers already on the `ResponseWriter` (`Vary`, `Content-Type`, CORS) are not visible here.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `headers` | required | Map of header name to string value |
| `on_conflict` | `skip` | `skip`, `overwrite`, or `append` |

| Mode | Behavior |
| --- | --- |
| `skip` | Leave the header unchanged when any value already exists in the context (including an empty string). Set the configured value when the name is absent. |
| `overwrite` | Remove every context value for that name, then set one `response.header.*` value. |
| `append` | When absent, set the configured value. When present, join existing values and the new value with `", "` into one `response.header.*` key and drop duplicate sources. |

Use several `middleware_plugins` entries with `plugin: response_headers` when you want separate header groups (security, cache, and so on).

```yaml
middleware_plugins:
  security_headers:
    plugin: response_headers
    settings:
      on_conflict: skip
      headers:
        X-Content-Type-Options: nosniff
        X-Frame-Options: DENY
        Referrer-Policy: strict-origin-when-cross-origin

  cache_public:
    plugin: response_headers
    settings:
      on_conflict: overwrite
      headers:
        Cache-Control: public, max-age=3600

  cache_revalidate:
    plugin: response_headers
    settings:
      on_conflict: append
      headers:
        Cache-Control: must-revalidate

global_request_middlewares:
  - security_headers
  - cache_public
  - cache_revalidate
```

With `on_conflict: skip`, `security_headers` does not replace `X-Frame-Options` when SQL or another middleware already set it. `cache_public` replaces `Cache-Control` for that response. `cache_revalidate` appends `must-revalidate` to the value `cache_public` wrote.

The same names can sit on one connection's `request_middlewares` instead of the global list.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
