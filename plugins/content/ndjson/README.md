# NDJSON

Preserved content plugin. Media type `application/x-ndjson`, format name `ndjson`. `Init` takes no settings.

`Parse` reads one JSON value per non-empty line and returns an array. An empty body is an empty array.

`PrepareGet` repeats. `limit` is the remaining row cap. `0` means there is no cap. The host calls `TableGet` in chunks of `page_size` (or `default_limit`). Trailers, `WriteTimeout` refresh, and a later-page error staying at HTTP 200 are host behavior. See [Pagination](../../../internal/server/README.md#pagination).

`PrepareCreate` splits an array into `page_size` chunks. Each chunk is one `TableCreate` after the first response headers.

Table GET renders one JSON object per line and does not add a pagination envelope. A REST list writes `{count?, next, previous}` as the first line when that page carries any of those fields, then one object per row. Later pages do not repeat that line because the host does not pass count, next, or previous again.

HTML escaping follows the same `json.escape_html` flag as [JSON](../json/README.md).

```bash
curl -H "Accept: application/x-ndjson" \
  -H "Prefer: page_size=50" \
  "http://localhost:8080/api/app/users/?ordering=id"
```

## See also

- [Server README](../../../README.md)
- [CSV](../csv/README.md)
- [Plugin SDK](../../../plugin/README.md)
