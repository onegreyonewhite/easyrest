// Package csvcodec renders and parses CSV bodies, including REST pagination links.
package csvcodec

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// Plugin is the preserved CSV content plugin.
type Plugin struct {
	easyrest.ContentBase
}

var _ easyrest.ContentPlugin = (*Plugin)(nil)

// New returns a CSV content plugin.
func New() *Plugin { return &Plugin{} }

// Init reports CSV for both the response and the request body.
func (*Plugin) Init(map[string]any) (easyrest.ContentInfo, error) {
	return easyrest.NewContentInfo(easyrest.MediaTypeCSV, easyrest.MediaTypeCSV, "csv"), nil
}

// Parse reads a header row and data rows. A single object request returns the first row.
func (*Plugin) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, ctx, fmt.Errorf("CSV parse error: %w", err)
	}
	if len(records) < 1 {
		return nil, ctx, fmt.Errorf("empty CSV data")
	}
	headers := records[0]
	result := make([]any, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		row := make(map[string]any, len(headers))
		for j, header := range headers {
			if j < len(records[i]) {
				row[header] = records[i][j]
			} else {
				row[header] = ""
			}
		}
		result = append(result, row)
	}
	if !easyrest.ExpectArray(ctx) && len(result) > 0 {
		return result[0], ctx, nil
	}
	return result, ctx, nil
}

// PrepareGet slices a long CSV the same way NDJSON does. page <= 0 stays one shot.
func (*Plugin) PrepareGet(limit, offset, page int) ([]easyrest.ContentWindow, bool) {
	fetch := fetchSize(page, limit)
	if fetch <= 0 {
		return nil, false
	}
	return []easyrest.ContentWindow{{Limit: fetch, Offset: offset}}, true
}

// Render writes CSV. Pagination selects the results field and returns a Link header on ctx.
// A continuation render omits the header row and reuses the columns stored on ctx.
func (*Plugin) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	payload, meta, err := easyrest.PaginationView(data, ctx)
	if err != nil {
		return nil, ctx, err
	}
	outCtx := ctx
	if link := linkHeader(meta); link != "" {
		outCtx = withLink(ctx, link)
	}
	cont := false
	if ctx != nil {
		cont, _ = ctx[easyrest.CtxContinue].(bool)
	}
	records, err := recordsFor(payload, outCtx, cont)
	if err != nil {
		return nil, outCtx, err
	}
	var buf bytes.Buffer
	if err := writeAll(&buf, records); err != nil {
		return nil, outCtx, err
	}
	return buf.Bytes(), outCtx, nil
}

const headerCtxKey = "csv.headers"

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

var writeAll = writeRecords

func writeRecords(w io.Writer, records [][]string) error {
	if err := csv.NewWriter(w).WriteAll(records); err != nil {
		return fmt.Errorf("Error writing CSV: %w", err)
	}
	return nil
}

func savedHeader(ctx map[string]any) []string {
	if ctx == nil {
		return nil
	}
	header, _ := ctx[headerCtxKey].([]string)
	return header
}

func headerFrom(rows []map[string]any) []string {
	seen := map[string]bool{}
	header := make([]string, 0)
	for _, item := range rows {
		for key := range item {
			if seen[key] {
				continue
			}
			seen[key] = true
			header = append(header, key)
		}
	}
	return header
}

func recordsFor(payload any, ctx map[string]any, cont bool) ([][]string, error) {
	if rows, ok := easyrest.MapRows(payload); ok && (len(rows) > 0 || cont) {
		if len(rows) == 0 {
			return [][]string{}, nil
		}
		header := savedHeader(ctx)
		if len(header) == 0 {
			header = headerFrom(rows)
			if ctx != nil {
				ctx[headerCtxKey] = header
			}
		}
		records := make([][]string, 0, len(rows)+1)
		if !cont {
			records = append(records, header)
		}
		for _, item := range rows {
			row := make([]string, len(header))
			for i, name := range header {
				if val, ok := item[name]; ok {
					row[i] = fmt.Sprintf("%v", val)
				}
			}
			records = append(records, row)
		}
		return records, nil
	}
	if data, ok := payload.(map[string]any); ok {
		headers := make([]string, 0, len(data))
		values := make([]string, 0, len(data))
		for key, val := range data {
			headers = append(headers, key)
			values = append(values, fmt.Sprintf("%v", val))
		}
		return [][]string{headers, values}, nil
	}
	return nil, fmt.Errorf("Data format not suitable for CSV")
}

func linkHeader(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	var parts []string
	if prev, ok := stringValue(meta[easyrest.PagPrev]); ok {
		parts = append(parts, "<"+prev+`>; rel="prev"`)
	}
	if next, ok := stringValue(meta[easyrest.PagNext]); ok {
		parts = append(parts, "<"+next+`>; rel="next"`)
	}
	if count, ok := meta[easyrest.PagCount]; ok {
		if text, ok := countText(count); ok {
			parts = append(parts, `<>; rel="count"; total="`+text+`"`)
		}
	}
	return strings.Join(parts, ", ")
}

func stringValue(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func countText(v any) (string, bool) {
	switch n := v.(type) {
	case int:
		return strconv.Itoa(n), true
	case int64:
		return strconv.FormatInt(n, 10), true
	case float64:
		return strconv.FormatInt(int64(n), 10), true
	case string:
		if n == "" {
			return "", false
		}
		return n, true
	default:
		return "", false
	}
}

func withLink(ctx map[string]any, link string) map[string]any {
	out := map[string]any{}
	maps.Copy(out, ctx)
	entry := map[string]any{"Link": link}
	switch existing := out[easyrest.CtxResponseHeaders].(type) {
	case []map[string]any:
		out[easyrest.CtxResponseHeaders] = append(append([]map[string]any{}, existing...), entry)
	case []any:
		out[easyrest.CtxResponseHeaders] = append(append([]any{}, existing...), entry)
	default:
		out[easyrest.CtxResponseHeaders] = []map[string]any{entry}
	}
	return out
}
