// Package yamlcodec parses and renders YAML for the content plugin contract.
package yamlcodec

import (
	"fmt"
	"math"
	"slices"

	"github.com/goccy/go-yaml"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the YAML content plugin. The server process keeps it in-process.
// Every other process loads the easyrest-content-yaml binary.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns a YAML content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports YAML for both the response and the request body. Settings are ignored.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeYAML, easyrest.MediaTypeYAML, "yaml"), nil
}

// Parse decodes one YAML mapping or sequence.
// content.expect_array selects which of those two is allowed.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	var value any
	if err := yaml.Unmarshal(body, &value); err != nil {
		return nil, ctx, fmt.Errorf("YAML parse error: %w", err)
	}
	if hasNonFinite(value) {
		return nil, ctx, fmt.Errorf("YAML parse error: non-finite float")
	}
	switch value.(type) {
	case map[string]any:
		if easyrest.ExpectArray(ctx) {
			return nil, ctx, fmt.Errorf("YAML parse error: expected array")
		}
		return value, ctx, nil
	case []any:
		if !easyrest.ExpectArray(ctx) {
			return nil, ctx, fmt.Errorf("YAML parse error: expected object")
		}
		return value, ctx, nil
	default:
		return nil, ctx, fmt.Errorf("YAML parse error: expected object or array")
	}
}

// Render encodes data. A pagination context becomes one document with count, next, previous, and results.
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
	raw, err := yaml.Marshal(value)
	if err != nil {
		return nil, ctx, fmt.Errorf("YAML render error: %w", err)
	}
	return raw, ctx, nil
}

func hasNonFinite(v any) bool {
	switch n := v.(type) {
	case float32:
		return math.IsNaN(float64(n)) || math.IsInf(float64(n), 0)
	case float64:
		return math.IsNaN(n) || math.IsInf(n, 0)
	case map[string]any:
		for _, item := range n {
			if hasNonFinite(item) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(n, hasNonFinite) {
			return true
		}
	}
	return false
}
