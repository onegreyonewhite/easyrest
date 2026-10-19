# Local storage

Preserved by the server package, so `easyrest-server` and `easyrest-gateway` both load it in-process when `path` is empty. There is no separate `cmd/` binary. A non-empty `path` still starts `easyrest-storage-local`.

| Key | Default | Meaning |
| --- | --- | --- |
| `dir` | required | Directory to create if missing. Must be writable. A path that exists and is not a directory fails init |
| `inline` | false | `true` stores standard base64 in the column and the response. `false` stores a relative path |
| `name` | set by the host | Instance name. Do not set this yourself unless you are embedding the plugin |

With `inline: false`, `Put` returns a relative path. A list field is a JSON array of paths. Responses call `GetUrl` and send an absolute URL, or an array of URLs. The host mounts `GET /media/{name}/*` when the root is non-empty and inline is false. GET schemas publish the field as `format: uri`. POST, PATCH, and PUT schemas keep `format: binary` or `base64`. See [Formats](../../../internal/server/README.md#formats).

`default_storage_plugin: local` (the default when that key is empty) still needs `storage_plugins.local.settings.dir`.

```yaml
storage_plugins:
  local:
    settings:
      dir: /var/lib/easyrest/media
  thumbs:
    plugin: local
    settings:
      dir: /var/thumbs
      inline: true

default_storage_plugin: local
```

An empty `plugin` means the map key is the driver, so the `local:` entry loads this driver.

## See also

- [Server README](../../../README.md)
- [Memory](../memory/README.md)
- [Configuration](../../../internal/config/README.md#application-and-restapi)
