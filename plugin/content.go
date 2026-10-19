package plugin

import (
	"errors"
	"fmt"
)

const (
	MediaTypeJSON   = "application/json"
	MediaTypeNDJSON = "application/x-ndjson"
	MediaTypeXML    = "application/xml"
	MediaTypeCSV    = "text/csv"
	MediaTypeForm   = "application/x-www-form-urlencoded"
	MediaTypeYAML   = "application/yaml"
	MediaTypeHTML   = "text/html"
)

const (
	// CtxExpectArray asks Parse for an array of objects. CSV then unwraps a single row when it is false.
	CtxExpectArray = "content.expect_array"
	// CtxJSONEscapeHTML, when false, disables HTML escaping in JSON and NDJSON output. The default is true.
	CtxJSONEscapeHTML = "json.escape_html"
	// CtxContentParams holds media-type parameters from the matched Accept token.
	// JSON reads indent as the number of spaces.
	CtxContentParams = "content.params"
	// CtxPagination holds count, next, prev, and the results field name for Render.
	CtxPagination = "pagination"
	// CtxResponseHeaders is the response.headers value already understood by the HTTP host.
	CtxResponseHeaders = "response.headers"
	// CtxContinue marks a render after the first page of a sliced read.
	// CSV omits its header row. NDJSON omits the metadata line when pagination
	// has no count, next, or previous.
	CtxContinue = "content.continue"
	// CtxSwagger is document or catalog. The HTML renderer refuses any other value.
	CtxSwagger = "content.swagger"
	// CtxSwaggerFormat is the first non-HTML format name for the spec URL.
	CtxSwaggerFormat = "content.swagger_format"
	// CtxSwaggerAssets is the public prefix for Swagger UI files.
	CtxSwaggerAssets = "content.swagger_assets"
	// CtxSwaggerURL is the absolute spec URL, or unused in catalog mode.
	CtxSwaggerURL = "content.swagger_url"
	// CtxSwaggerAuth is the application.auth plugin name for the root page.
	CtxSwaggerAuth = "content.swagger_auth"
	// CtxSwaggerEmbed asks the HTML renderer to include the schema document.
	CtxSwaggerEmbed = "content.swagger_embed"
	// CtxSwaggerTemplate is an optional *template.Template for the root page.
	CtxSwaggerTemplate = "content.swagger_template"
	// SwaggerDocument asks the HTML renderer for one spec page.
	SwaggerDocument = "document"
	// SwaggerCatalog asks the HTML renderer for a urls list.
	SwaggerCatalog = "catalog"
)

const (
	PagCount   = "count"
	PagNext    = "next"
	PagPrev    = "prev"
	PagResults = "results"
)

// ErrContentUnsupported is returned by ContentBase parse and render.
var ErrContentUnsupported = errors.New("content plugin does not support this operation")

// ContentWindow is one TableGet limit and offset pair.
type ContentWindow struct {
	Limit  int
	Offset int
}

// ContentPlugin parses request bodies and renders response bodies.
// PrepareGet plans the next TableGet window. repeat asks the host to call
// PrepareGet again after a full page. One-shot plugins leave repeat false.
// For one-shot plugins, limit 0 means "use page". For a repeating plugin,
// limit is the remaining row cap and 0 means there is no cap.
type ContentPlugin interface {
	Init(settings map[string]any) (ContentInfo, error)
	Parse(body []byte, ctx map[string]any) (any, map[string]any, error)
	Render(data any, ctx map[string]any) (any, map[string]any, error)
	PrepareGet(limit, offset, page int) (windows []ContentWindow, repeat bool)
	PrepareCreate(body any, page int) []any
}

// ContentBase is the one-shot default embedded by content plugins.
type ContentBase struct{}

// Parse reports that the embedded default cannot parse.
func (ContentBase) Parse(body []byte, ctx map[string]any) (any, map[string]any, error) {
	return nil, ctx, ErrContentUnsupported
}

// Render reports that the embedded default cannot render.
func (ContentBase) Render(data any, ctx map[string]any) (any, map[string]any, error) {
	return nil, ctx, ErrContentUnsupported
}

// PrepareGet returns one window. A zero limit with a positive page uses page as the limit.
func (ContentBase) PrepareGet(limit, offset, page int) ([]ContentWindow, bool) {
	if limit == 0 && page > 0 {
		limit = page
	}
	return []ContentWindow{{Limit: limit, Offset: offset}}, false
}

// PrepareCreate returns the body as a single chunk.
func (ContentBase) PrepareCreate(body any, page int) []any {
	return []any{body}
}

// ExpectArray reports whether ctx asks Parse to produce an array.
func ExpectArray(ctx map[string]any) bool {
	if ctx == nil {
		return false
	}
	b, ok := ctx[CtxExpectArray].(bool)
	return ok && b
}

// JSONEscapeHTML reports whether JSON output should escape &, <, and >.
func JSONEscapeHTML(ctx map[string]any) bool {
	if ctx == nil {
		return true
	}
	v, ok := ctx[CtxJSONEscapeHTML]
	if !ok {
		return true
	}
	b, ok := v.(bool)
	if !ok {
		return true
	}
	return b
}

// MapRows converts a slice of row maps. A non-slice or a slice with a non-map element returns false.
func MapRows(v any) ([]map[string]any, bool) {
	switch rows := v.(type) {
	case []map[string]any:
		return rows, true
	case []any:
		out := make([]map[string]any, len(rows))
		for i, item := range rows {
			row, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out[i] = row
		}
		return out, true
	default:
		return nil, false
	}
}

// PaginationView returns the value Render should write.
// Without pagination, payload is data and meta is nil.
// When pagination.results names a field, data must be a map that contains it.
func PaginationView(data any, ctx map[string]any) (payload any, meta map[string]any, err error) {
	if ctx == nil {
		return data, nil, nil
	}
	raw, ok := ctx[CtxPagination]
	if !ok || raw == nil {
		return data, nil, nil
	}
	meta, ok = raw.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("pagination must be an object")
	}
	field, _ := meta[PagResults].(string)
	if field == "" {
		return data, meta, nil
	}
	obj, ok := data.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("pagination results %q requires an object", field)
	}
	payload, ok = obj[field]
	if !ok {
		return nil, nil, fmt.Errorf("pagination results field %q is missing", field)
	}
	return payload, meta, nil
}

// StandardContentNames is the preserved parser and renderer set, in fallback order.
func StandardContentNames() []string {
	return []string{"json", "ndjson", "xml", "csv", "form"}
}

// RenderedBytes converts a Render result into bytes the HTTP host can write.
func RenderedBytes(v any) ([]byte, error) {
	switch body := v.(type) {
	case []byte:
		return body, nil
	case string:
		return []byte(body), nil
	default:
		return nil, fmt.Errorf("content plugin returned %T", v)
	}
}
