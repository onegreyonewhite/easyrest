# Basic auth

HTTP Basic authentication. This plugin is preserved inside `easyrest-server` only. There is no `cmd/` binary.

`userlist` is required and must be a non-empty map of username to password. A successful login returns claims `sub` (the username) and `scope: "read write"`. The scope is not configurable.

The header is `Authorization: Basic <base64(user:password)>`. Swagger is HTTP basic.

```yaml
auth_plugins:
  basic:
    settings:
      userlist:
        ada: secret
        bob: other
```

```bash
curl -u ada:secret http://localhost:8080/api/app/users/
```

Trial order is in [Auth and scopes](../../../internal/server/README.md#auth-and-scopes).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
