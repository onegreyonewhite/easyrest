// Package fixedform parses an application/x-www-form-urlencoded body into a fixed set of keys.
package fixedform

import (
	"fmt"
	"net/url"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is a parser-only content plugin.
// Parse returns every configured key. A missing key is nil. Keys that are not configured are dropped.
type Plugin struct {
	easyrest.ContentBase
	fields []string
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns a fixed-form parser.
func New() *Plugin { return &Plugin{} }

// Init stores settings.fields and reports a form parser that does not render.
func (p *Plugin) Init(settings map[string]any) (easyrest.ContentInfo, error) {
	fields, err := fieldList(settings)
	if err != nil {
		return easyrest.ContentInfo{}, err
	}
	p.fields = fields
	return easyrest.NewContentInfo("", easyrest.MediaTypeForm, "form"), nil
}

// Parse reads one urlencoded object. A repeated key is an error. Unconfigured keys are ignored.
func (p *Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	if easyrest.ExpectArray(ctx) {
		return nil, ctx, fmt.Errorf("fixedform: expected object")
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, ctx, fmt.Errorf("fixedform: %w", err)
	}
	for key, items := range values {
		if len(items) > 1 {
			return nil, ctx, fmt.Errorf("fixedform: repeated key %q", key)
		}
	}
	data := make(map[string]any, len(p.fields))
	for _, key := range p.fields {
		items := values[key]
		if len(items) == 0 {
			data[key] = nil
			continue
		}
		data[key] = items[0]
	}
	return data, ctx, nil
}

func fieldList(settings map[string]any) ([]string, error) {
	if settings == nil {
		return nil, fmt.Errorf("fixedform: fields is required")
	}
	raw, ok := settings["fields"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("fixedform: fields is required")
	}
	var fields []string
	switch v := raw.(type) {
	case []string:
		fields = append([]string(nil), v...)
	case []any:
		fields = make([]string, 0, len(v))
		for _, item := range v {
			name, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("fixedform: fields must be strings")
			}
			fields = append(fields, name)
		}
	default:
		return nil, fmt.Errorf("fixedform: fields must be a list")
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("fixedform: fields is required")
	}
	seen := make(map[string]struct{}, len(fields))
	for _, name := range fields {
		if name == "" {
			return nil, fmt.Errorf("fixedform: fields must be strings")
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("fixedform: repeated field %q", name)
		}
		seen[name] = struct{}{}
	}
	return fields, nil
}
