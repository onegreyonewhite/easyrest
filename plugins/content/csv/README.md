# CSV

Preserved content plugin. Media type `text/csv`, format name `csv`. `Init` takes no settings.

`Parse` reads a header row and data rows. A request that expects one object returns the first data row.

`PrepareGet` pages the same way as [NDJSON](../ndjson/README.md) when `page` is positive. `page <= 0` stays one shot. The first chunk includes the header row. When the host sets `content.continue`, later chunks omit the header.

A REST list does not put pagination in the body. `Render` writes a `Link` header on the context: `rel="prev"`, `rel="next"`, and `rel="count"; total="N"` when a count is present. The body is the result rows. Streaming caps, trailers, and `Content-Range` rules are in [Pagination](../../../internal/server/README.md#pagination).

```bash
curl -H "Accept: text/csv" \
  -H "Prefer: page_size=100" \
  "http://localhost:8080/api/app/users/?ordering=id"
```

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
