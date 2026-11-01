# Memory storage

Preserved by the server package, so both server binaries load it in-process. Bytes stay in the process and are gone after a restart. There is no `dir` and no `cmd/` binary.

| Key | Default | Meaning |
| --- | --- | --- |
| `inline` | false | `true` returns a data URL from `Put` and does not mount `/media`. `false` stores a relative path and mounts `GET /media/{name}/*` |
| `name` | set by the host | Instance name |

URL behavior matches [local](../local/README.md): responses call `GetUrl` and send an absolute URL unless inline is on.

```yaml
storage_plugins:
  scratch:
    plugin: memory

default_storage_plugin: scratch
```

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
