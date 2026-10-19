# API key

Header API key authentication. This plugin is preserved inside `easyrest-server` only. There is no `cmd/` binary.

| Key | Default | Meaning |
| --- | --- | --- |
| `keys` | required | Non-empty list of accepted keys. Blank entries are rejected |
| `header_name` | `X-API-Key` | Header to read. Blank is treated as unset |

A match returns `scope: "read write"`. The scope is not configurable. Swagger is `apiKey` in that header.

```yaml
auth_plugins:
  apikey:
    settings:
      header_name: X-API-Key
      keys:
        - dev-key
        - other-key
```

```bash
curl -H "X-API-Key: dev-key" http://localhost:8080/api/app/users/
```

Trial order is in [Auth and scopes](../../../internal/server/README.md#auth-and-scopes).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
