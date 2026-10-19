# JSON

Preserved content plugin. Media type `application/json`, format name `json`. `Init` takes no settings. It parses and renders.

`Parse` accepts one JSON object or array. Anything else is an error.

`Render` writes one JSON value and a trailing newline. A REST list with pagination context becomes one object `{count?, next, previous, results}`. `POST` sends the whole body in one `TableCreate`.

`Accept: application/json; indent=2` pretty-prints with that many spaces. Zero, missing, and invalid `indent` stay compact. The parameter arrives as `content.params`.

`<`, `>`, and `&` are escaped unless the server set `json.escape_html` to false. That happens when `server.disable_html_escape` is true. See [Configuration](../../../internal/config/README.md#server).

Which handlers run is decided by `content_handlers`. An empty list means all five standards. See [Formats](../../../internal/server/README.md#formats).

```yaml
default_content_handlers: [json]
```

```bash
curl -H "Accept: application/json; indent=2" \
  "http://localhost:8080/api/app/users/?limit=2"
```

## See also

- [Server README](../../../README.md)
- [NDJSON](../ndjson/README.md)
- [Plugin SDK](../../../plugin/README.md)
