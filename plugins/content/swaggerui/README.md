# Swagger UI

Preserved content plugin. Media type `text/html`, format name `html`. It only renders. `Parse` returns an error. `Init` takes no settings.

The host sets `content.swagger` to `document` (one spec) or `catalog` (the `GET /` URL list). Any other value is refused, so a normal table response cannot be HTML. The page loads the spec from `content.swagger_url` with `content.swagger_format` (usually `json`). `content.swagger_embed` true inlines the document and clears that URL. `content.swagger_assets` is the public prefix for CSS and JavaScript, served from `/media/static/`. `content.swagger_auth` is `application.auth`, passed into the root page. `content.swagger_template` replaces the embedded template for `GET /`.

`/api/{db}/` and `/restapi/{name}/` keep the embedded page even when `application.template` is set. See [HTTP API](../../../internal/server/README.md#routes) and [static storage](../../storage/static/README.md).

```bash
curl -H "Accept: text/html" http://localhost:8080/api/app/
curl -H "Accept: application/json" http://localhost:8080/api/app/
```

The first response is the UI. The second is the document the UI fetches.

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
