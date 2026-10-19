# dbglob

Preserved by the server package. Two modes. There is no `cmd/` binary.

Without `plugin` and `table`, `Put` returns standard base64. The host writes that string to the database and returns it unchanged. Nothing is mounted at `/media/dbglob`. GET schemas use `format: base64`.

With both `plugin` and `table`, the plugin stores a row through the internal RPC server and `Put` returns the relative path. `plugin` is a connection name under `plugins:`, not a binary name. Setting only one of them fails init. The listener must be configured. See [Internal RPC](../../../internal/config/README.md#internal-rpc).

| Key | Default | Meaning |
| --- | --- | --- |
| `plugin` | empty | Connection name. Required together with `table` |
| `table` | empty | Table name. Required together with `plugin` |
| `path` | `path` | Path column |
| `data` | `data` | Bytes column |
| `metadata` | `metadata` | Metadata column |
| `name` | set by the host | Instance name |

`settings.inline` on local, memory, and S3 is a different switch. dbglob inline mode is the absence of `plugin` and `table`.

```yaml
storage_plugins:
  blobs:
    plugin: dbglob
  files:
    plugin: dbglob
    settings:
      plugin: app
      table: uploads
      path: path
      data: data
      metadata: metadata
```

`static` cannot be `application.storage`. `dbglob` can. See [Configuration](../../../internal/config/README.md#application-and-restapi).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
