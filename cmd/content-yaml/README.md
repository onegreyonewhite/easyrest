# YAML content plugin

Media type `application/yaml`, format name `yaml`. It is not one of the five content plugins that are always loaded (`json`, `ndjson`, `xml`, `csv`, `form`).

`easyrest-server` registers an in-process factory. When `content_plugins.yaml` is set and `path` is empty, that process uses the factory. Every other process, including tests and `easyrest-gateway`, looks up `easyrest-content-yaml` on `PATH`, in the working directory, and next to the server binary. A non-empty `path` always starts that binary.

`Parse` accepts one mapping or one sequence. `content.expect_array` selects which of those two is allowed. Non-finite floats are rejected. `Render` writes one YAML document. `Init` ignores settings and returns `ContentInfo` with both media fields set to `application/yaml` and format `yaml`.

```yaml
content_plugins:
  yaml: {}

default_content_handlers: [json, yaml]
```

```bash
curl -H "Accept: application/yaml" \
  "http://localhost:8080/api/app/users/?limit=2"
```

Build the external binary with `make`, which writes `bin/easyrest-content-yaml` from this directory. See [Plugin SDK](../../plugin/README.md#content).

## See also

- [Server README](../../README.md)
- [Formats](../../internal/server/README.md#formats)
- [JSON](../../plugins/content/json/README.md)
