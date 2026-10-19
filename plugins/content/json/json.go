// Package json renders and parses JSON request and response bodies.
package json

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	gjson "github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the preserved JSON content plugin.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns a JSON content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports JSON for both the response and the request body.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeJSON, easyrest.MediaTypeJSON, "json"), nil
}

// Parse decodes one JSON object or array.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	dec := gjson.NewDecoder(bytes.NewReader(body))
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, ctx, fmt.Errorf("JSON parse error: %w", err)
	}
	switch value.(type) {
	case map[string]any, []any:
		return value, ctx, nil
	default:
		return nil, ctx, fmt.Errorf("JSON parse error: expected object or array")
	}
}

// Render encodes data. A pagination context becomes one object with count, next, previous, and results.
func (*Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	payload, meta, err := easyrest.PaginationView(data, ctx)
	if err != nil {
		return nil, ctx, err
	}
	value := payload
	if meta != nil {
		out := map[string]any{easyrest.PagResults: payload}
		if count, ok := meta[easyrest.PagCount]; ok {
			out[easyrest.PagCount] = count
		}
		if next, ok := meta[easyrest.PagNext]; ok {
			out[easyrest.PagNext] = next
		}
		if prev, ok := meta[easyrest.PagPrev]; ok {
			out["previous"] = prev
		}
		value = out
	}
	buf, err := encode(value, easyrest.JSONEscapeHTML(ctx), indentSpaces(ctx))
	if err != nil {
		return nil, ctx, err
	}
	return buf, ctx, nil
}

func encode(value any, escape bool, indent string) ([]byte, error) {
	if indent == "" && escape {
		raw, err := gjson.Marshal(value)
		if err != nil {
			return nil, err
		}
		return append(raw, '\n'), nil
	}
	var buf bytes.Buffer
	enc := gjson.NewEncoder(&buf)
	enc.SetEscapeHTML(escape)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// indentSpaces reads content.params indent. Zero, missing, and invalid values stay compact.
func indentSpaces(ctx map[string]any) string {
	if ctx == nil {
		return ""
	}
	params, ok := ctx[easyrest.CtxContentParams].(map[string]string)
	if !ok {
		return ""
	}
	n, err := strconv.Atoi(params["indent"])
	if err != nil || n <= 0 {
		return ""
	}
	// A huge indent would allocate a large prefix on every response.
	if n > 32 {
		n = 32
	}
	return strings.Repeat(" ", n)
}
