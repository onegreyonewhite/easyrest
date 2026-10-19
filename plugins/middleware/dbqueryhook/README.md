# Database query hooks

Writes `db.pre-request` and `db.post-request` onto the request context. The database plugin runs that routine around the statement. `easyrest-server` keeps this middleware in-process. The external binary is `easyrest-middleware-dbqueryhook`.

`PostRequest` does not add headers.

## Settings

Both groups are optional. A missing group is empty. Invalid routine names fail `Init`.

| Group | Key | Meaning |
| --- | --- | --- |
| `by_type` | `postgres`, `mysql`, or `sqlite` | Rules for that database type |
| `by_key` | connection name, lowercased | Rules for that `plugins:` key |

Each rule has `pre_request` and `post_request`. A missing field leaves that hook unchanged. An empty string clears it. `by_key` overrides `by_type` per field, not as a whole group.

SQLite context is left unchanged: this middleware does not set hooks when `db.type` is sqlite, and the SQLite plugin would ignore them anyway.

```yaml
middleware_plugins:
  dbqueryhook:
    settings:
      by_type:
        postgres:
          pre_request: app_pre
          post_request: app_post
        mysql:
          pre_request: app_pre
      by_key:
        app:
          pre_request: ""
          post_request: app_post_only

plugins:
  app:
    uri: postgres://user:pass@localhost:5432/app?sslmode=disable
    request_middlewares: [dbqueryhook]
```

Postgres runs `SELECT name()`. MySQL runs `CALL name()`. See [Postgres](../../data/postgres/README.md) and [MySQL](../../data/mysql/README.md).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
