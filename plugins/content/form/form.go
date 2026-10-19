// Package formcodec renders and parses application/x-www-form-urlencoded bodies.
package formcodec

import (
	"fmt"
	"net/url"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the preserved form content plugin.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns a form content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports form encoding for both the response and the request body.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeForm, easyrest.MediaTypeForm, "form"), nil
}

// Parse reads a urlencoded body. It does not merge the request query string.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, ctx, fmt.Errorf("form parse error: %w", err)
	}
	data := map[string]any{}
	for key, items := range values {
		if len(items) == 1 {
			data[key] = items[0]
		} else {
			data[key] = items
		}
	}
	if easyrest.ExpectArray(ctx) {
		return []any{data}, ctx, nil
	}
	return data, ctx, nil
}

// Render writes one object, or the first row of a slice, as urlencoded text.
func (*Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	payload, _, err := easyrest.PaginationView(data, ctx)
	if err != nil {
		return nil, ctx, err
	}
	values := url.Values{}
	if obj, ok := payload.(map[string]any); ok {
		for key, val := range obj {
			values.Set(key, fmt.Sprintf("%v", val))
		}
	} else if rows, ok := easyrest.MapRows(payload); ok && len(rows) > 0 {
		for key, val := range rows[0] {
			values.Set(key, fmt.Sprintf("%v", val))
		}
	} else {
		return nil, ctx, fmt.Errorf("Data format not suitable for form-urlencoded")
	}
	return []byte(values.Encode()), ctx, nil
}
