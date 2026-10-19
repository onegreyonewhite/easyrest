// Package ndjson renders newline-delimited JSON and slices list and create calls into pages.
package ndjson

import (
	"bytes"
	"fmt"

	gjson "github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the preserved NDJSON content plugin.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns an NDJSON content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports NDJSON for both the response and the request body.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeNDJSON, easyrest.MediaTypeNDJSON, "ndjson"), nil
}

// Parse decodes one JSON object per non-empty line.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return []any{}, ctx, nil
	}
	lines := bytes.Split(body, []byte("\n"))
	out := make([]any, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var value any
		if err := gjson.Unmarshal(line, &value); err != nil {
			return nil, ctx, fmt.Errorf("NDJSON parse error: %w", err)
		}
		out = append(out, value)
	}
	return out, ctx, nil
}

// Render writes one JSON object per row. The first paginated call also writes a count, next, and previous line.
func (*Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	payload, meta, err := easyrest.PaginationView(data, ctx)
	if err != nil {
		return nil, ctx, err
	}
	escape := easyrest.JSONEscapeHTML(ctx)
	var buf bytes.Buffer
	enc := gjson.NewEncoder(&buf)
	enc.SetEscapeHTML(escape)
	if metaLine(meta) {
		obj := map[string]any{}
		if count, ok := meta[easyrest.PagCount]; ok {
			obj[easyrest.PagCount] = count
		}
		if next, ok := meta[easyrest.PagNext]; ok {
			obj[easyrest.PagNext] = next
		}
		if prev, ok := meta[easyrest.PagPrev]; ok {
			obj["previous"] = prev
		}
		if err := enc.Encode(obj); err != nil {
			return nil, ctx, err
		}
	}
	if err := writeRows(enc, payload); err != nil {
		return nil, ctx, err
	}
	return buf.Bytes(), ctx, nil
}

// PrepareGet returns the next NDJSON page. limit is the remaining row cap; 0 means no cap.
func (*Plugin) PrepareGet(limit, offset, page int) ([]easyrest.ContentWindow, bool) {
	fetch := fetchSize(page, limit)
	if fetch <= 0 {
		return nil, false
	}
	return []easyrest.ContentWindow{{Limit: fetch, Offset: offset}}, true
}

// PrepareCreate splits a slice into chunks of page. Other values stay one chunk.
func (*Plugin) PrepareCreate(body any, page int) []any {
	if page <= 0 {
		return []any{body}
	}
	switch items := body.(type) {
	case []any:
		return chunk(len(items), page, body, func(i, j int) any { return items[i:j] })
	case []map[string]any:
		return chunk(len(items), page, body, func(i, j int) any { return items[i:j] })
	default:
		return []any{body}
	}
}

func metaLine(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	_, count := meta[easyrest.PagCount]
	_, next := meta[easyrest.PagNext]
	_, prev := meta[easyrest.PagPrev]
	return count || next || prev
}

func writeRows(enc *gjson.Encoder, payload any) error {
	if rows, ok := easyrest.MapRows(payload); ok {
		for i := range rows {
			if err := enc.Encode(rows[i]); err != nil {
				return err
			}
		}
		return nil
	}
	return enc.Encode(payload)
}

func fetchSize(page, maxRows int) int {
	if page <= 0 {
		return 0
	}
	if maxRows <= 0 {
		return page
	}
	if maxRows < page {
		return maxRows
	}
	return page
}

func chunk(n, page int, body any, slice func(i, j int) any) []any {
	if n == 0 {
		return []any{body}
	}
	out := make([]any, 0, (n+page-1)/page)
	for i := 0; i < n; i += page {
		j := min(i+page, n)
		out = append(out, slice(i, j))
	}
	return out
}
