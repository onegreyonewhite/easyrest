# Form

Preserved content plugin. Media type `application/x-www-form-urlencoded`, format name `form`. `Init` takes no settings.

`Parse` reads the body only. It does not merge the request query string. One value stays a string. Repeated keys become a list of strings. When the host sets `content.expect_array`, the object is wrapped in a one-element array.

`Render` writes one object, or the first row of a slice, as urlencoded text.

This is not `multipart/form-data`. File uploads use the built-in multipart parser described in [Formats](../../../internal/server/README.md#formats).

```yaml
# allow the form handler alongside JSON
default_content_handlers: [json, form]
```

```bash
curl -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=ada&city=Berlin" \
  http://localhost:8080/api/app/users/
```

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
