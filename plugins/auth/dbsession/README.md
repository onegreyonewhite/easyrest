# Database session

Loads claims from a session table through the internal RPC server. This plugin is preserved inside `easyrest-server` only. There is no `cmd/` binary. It does not set the cookie. The host copies the cookie value into the header map before `Authenticate`. See [Auth and scopes](../../../internal/server/README.md#auth-and-scopes).

`plugin` and `table` are required together. `plugin` is the connection name under `plugins:`, the same string you would use in `/api/{db}/`. It is not a storage driver and not a binary name.

| Key | Default | Meaning |
| --- | --- | --- |
| `plugin` | required | Database connection name |
| `table` | required | Session table |
| `id` | `id` | Column matched to the cookie value |
| `claims` | `claims` | Column that must be a JSON object |
| `exp` | `exp` | Column with an RFC3339 timestamp. Missing, unparsable, or past values fail |
| `cookie` | `session` | Cookie name |

`Authenticate` dials the host once and calls `TableGet` with `where.eq.<id>=<cookie>` and `select=<claims>,<exp>`. A later `Init` drops that client and dials again on the next request. A missing row fails. Swagger is `apiKey` with `in: cookie`.

The internal listener must be up. With no `internal_rpc` address, the call fails with `host rpc is not configured`. Those RPC calls do not authenticate. See [Internal RPC](../../../internal/config/README.md#internal-rpc).

```yaml
internal_rpc:
  network: unix
  address: /tmp/easyrest.sock

plugins:
  app:
    uri: sqlite:///tmp/app.db

auth_plugins:
  dbsession:
    settings:
      plugin: app
      table: sessions
      id: id
      claims: claims
      exp: exp
      cookie: session
```

The `claims` cell is a JSON object, for example `{"sub":"ada","scope":"read"}`. If the database returns that object as text, `Authenticate` decodes it. `exp` is a timestamp such as `2026-09-28T00:00:00Z`.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
- [JWT session](../jwtsession/README.md)
