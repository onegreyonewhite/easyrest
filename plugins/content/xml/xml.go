// Package xmlcodec renders and parses the XML bodies EasyREST already accepts.
package xmlcodec

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the preserved XML content plugin.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns an XML content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports XML for both the response and the request body.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeXML, easyrest.MediaTypeXML, "xml"), nil
}

// Parse reads a single object, or an items wrapper when content.expect_array is set.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	if easyrest.ExpectArray(ctx) {
		items, err := decodeItems(body)
		if err != nil {
			return nil, ctx, fmt.Errorf("XML parse error: %w", err)
		}
		return items, ctx, nil
	}
	obj, err := decodeObject(body)
	if err != nil {
		return nil, ctx, fmt.Errorf("XML parse error: %w", err)
	}
	return obj, ctx, nil
}

// Render writes the same element shape as the historical XML encoder.
func (*Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	payload, _, err := easyrest.PaginationView(data, ctx)
	if err != nil {
		return nil, ctx, err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	if rows, ok := easyrest.MapRows(payload); ok {
		fmt.Fprintf(&buf, "<items>\n")
		for _, item := range rows {
			writeItem(&buf, item, "  ", "    ")
		}
		fmt.Fprintf(&buf, "</items>")
		return buf.Bytes(), ctx, nil
	}
	obj, ok := payload.(map[string]any)
	if !ok {
		return nil, ctx, fmt.Errorf("Data format not suitable for XML")
	}
	fmt.Fprintf(&buf, "<item>\n")
	for key, val := range obj {
		if rows, ok := easyrest.MapRows(val); ok {
			fmt.Fprintf(&buf, "  <%s>\n", key)
			for _, item := range rows {
				writeItem(&buf, item, "    ", "      ")
			}
			fmt.Fprintf(&buf, "  </%s>\n", key)
			continue
		}
		fmt.Fprintf(&buf, "  <%s>%v</%s>\n", key, val, key)
	}
	fmt.Fprintf(&buf, "</item>")
	return buf.Bytes(), ctx, nil
}

func writeItem(buf *bytes.Buffer, item map[string]any, itemIndent, fieldIndent string) {
	fmt.Fprintf(buf, "%s<item>\n", itemIndent)
	for key, val := range item {
		fmt.Fprintf(buf, "%s<%s>%v</%s>\n", fieldIndent, key, val, key)
	}
	fmt.Fprintf(buf, "%s</item>\n", itemIndent)
}

func decodeObject(body []byte) (map[string]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	if _, err := nextStart(dec); err != nil {
		return nil, err
	}
	return readFields(dec)
}

func decodeItems(body []byte) ([]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	if _, err := nextStart(dec); err != nil {
		return nil, err
	}
	var out []any
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "item" {
			if err := dec.Skip(); err != nil {
				return nil, err
			}
			continue
		}
		fields, err := readFields(dec)
		if err != nil {
			return nil, err
		}
		out = append(out, fields)
	}
}

func readText(dec *xml.Decoder) (string, error) {
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch el := tok.(type) {
		case xml.CharData:
			text.Write(el)
		case xml.EndElement:
			return text.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("nested element %s", el.Name.Local)
		}
	}
}

func readFields(dec *xml.Decoder) (map[string]any, error) {
	out := map[string]any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch el := tok.(type) {
		case xml.CharData:
			continue
		case xml.StartElement:
			text, err := readText(dec)
			if err != nil {
				return nil, err
			}
			out[el.Name.Local] = text
		case xml.EndElement:
			return out, nil
		}
	}
}

func nextStart(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start, nil
		}
	}
}
