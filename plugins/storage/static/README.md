# Static storage

Read-only storage plugin, preserved by the server package. `Put` and `Delete` always fail. It cannot be `application.storage`, because that field must accept uploads. See [Configuration](../../../internal/config/README.md#application-and-restapi).

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `{workdir}/static` | Directory to read first |
| `name` | set by the host | Instance name |

A missing directory is not an error. Reads then use the Swagger UI files embedded in the plugin. Those files are the official Swagger UI v5.35.1 `dist` bundle, preset, and CSS. A file with the same name in `path` replaces that embedded copy. The HTTP server serves those files at `/media/static/`. See [Swagger UI](../../content/swaggerui/README.md).

```yaml
storage_plugins:
  static:
    settings:
      path: ./static
```

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
