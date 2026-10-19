# JWT session

Reads claims from a JWT stored in a cookie. This plugin is preserved inside `easyrest-server` only. There is no `cmd/` binary. It does not set the cookie. The host copies the cookie value into the header map before `Authenticate`. See [Auth and scopes](../../../internal/server/README.md#auth-and-scopes).

| Key | Default | Meaning |
| --- | --- | --- |
| `jwt_secret` | empty | HMAC secret. A non-empty secret verifies HS256. An empty secret decodes the payload and does not check the signature |
| `cookie` | `session` | Cookie name. Blank falls back to `session` |

The cookie value may be a raw JWT or `Bearer <jwt>`. A bad signature or an expired `exp` fails authentication. Swagger is `apiKey` with `in: cookie`.

```yaml
auth_plugins:
  jwtsession:
    settings:
      jwt_secret: "change-me"
      cookie: session
```

Signature rules shared with the header plugin are in [JWT](../jwt/README.md).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [DB session](../dbsession/README.md)
