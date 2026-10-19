# JWT and OIDC

HMAC JWT and OpenID Connect userinfo share this package. `easyrest-server` keeps both in-process. The binaries are `easyrest-auth-jwt` ([cmd/auth-jwt](../../../cmd/auth-jwt/main.go)) and `easyrest-auth-oidc` ([cmd/auth-oidc](../../../cmd/auth-oidc/main.go)). A non-empty `path` still starts that binary.

Trial order and the claims cache are in [Auth and scopes](../../../internal/server/README.md#auth-and-scopes). A cookie that holds a JWT is [jwtsession](../jwtsession/README.md), not this plugin.

## JWT

`JWTAuthPlugin` reads `Authorization`. The value may be a raw JWT or `<token_type> <jwt>`. The default `token_type` is `Bearer`.

| Key | Default | Meaning |
| --- | --- | --- |
| `jwt_secret` | empty | HMAC secret. Empty decodes the payload and does not check the signature |
| `token_type` | `Bearer` | Expected prefix when the header contains a space |
| `token_endpoint` | `ER_TOKEN_AUTHURL` when the key is absent | OAuth2 token URL. A non-empty value switches the Swagger definition to `oauth2` |
| `authorization_endpoint` | empty | OAuth2 authorization URL |
| `flow` | `accessCode` when both endpoints are set, otherwise `password` | OAuth2 flow written into the security definition |

```yaml
auth_plugins:
  jwt:
    settings:
      jwt_secret: "change-me"
      token_type: Bearer
```

With a token endpoint:

```yaml
auth_plugins:
  jwt:
    settings:
      jwt_secret: "change-me"
      token_endpoint: https://idp.example/token
      authorization_endpoint: https://idp.example/authorize
      flow: accessCode
```

Without `token_endpoint`, Swagger is `apiKey` on the `Authorization` header. With it, Swagger is `oauth2` and includes `tokenUrl` and, when set, `authorizationUrl`.

If `auth_plugins` is omitted entirely, the server synthesizes this plugin with an empty `jwt_secret` and `flow: password`. There is no top-level `token_secret` key. See [Configuration](../../../internal/config/README.md).

## OIDC

`OIDCAuthPlugin` is the `oidc` config key. `open_id_connect_url` is required. `Init` fetches that discovery document and requires `userinfo_endpoint` and `authorization_endpoint`. `Authenticate` calls the userinfo endpoint with the bearer token.

| Key | Default | Meaning |
| --- | --- | --- |
| `open_id_connect_url` | required | Discovery document URL |
| `token_type` | `Bearer` | Scheme sent to userinfo |
| `request_timeout` | `10` seconds when omitted or not positive | HTTP client timeout, in seconds. YAML numbers arrive as float64 |
| `flow` | `accessCode` when discovery has a token endpoint, otherwise `implicit` | OAuth2 flow in the Swagger definition |

If the chosen flow needs a token URL and discovery did not provide one, `ER_TOKEN_AUTHURL` is used when that environment variable is set.

```yaml
auth_plugins:
  oidc:
    settings:
      open_id_connect_url: https://idp.example/.well-known/openid-configuration
      token_type: Bearer
      request_timeout: 10
```

Swagger is `oauth2` with `authorizationUrl` and, when known, `tokenUrl`.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [JWT session](../jwtsession/README.md)
