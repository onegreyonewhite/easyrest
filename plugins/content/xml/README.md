# XML

Preserved content plugin. Media type `application/xml`, format name `xml`. `Init` takes no settings. Responses are one shot, the same paging rules as JSON. See [Pagination](../../../internal/server/README.md#pagination).

`Parse` reads one object. When the host sets `content.expect_array`, it reads an `<items>` wrapper instead.

`Render` writes an XML declaration. A list of rows becomes `<items>` with one `<item>` per row. A single object is one element.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<items>
  <item>
    <id>1</id>
    <name>ada</name>
  </item>
</items>
```

```bash
curl -H "Accept: application/xml" \
  "http://localhost:8080/api/app/users/?limit=2"
```

## See also

- [Server README](../../../README.md)
- [JSON](../json/README.md)
- [Plugin SDK](../../../plugin/README.md)
