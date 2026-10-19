package server

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const contentTypeNDJSON = "application/x-ndjson"

func mediaType(s string) string {
	if idx := strings.Index(s, ";"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func queryFormat(r *http.Request, query url.Values) string {
	if query != nil {
		return query.Get("format")
	}
	return r.URL.Query().Get("format")
}

// parseRequest parses the request body according to the Content-Type.
// The parameter expectArray indicates whether an array of objects (true) or a single object (false) is expected.
// makeResponse transforms the data according to the Accept header and sends the response.
func makeResponse(w http.ResponseWriter, r *http.Request, status int, v any) {
	makeResponseWithQuery(w, r, status, v, nil)
}

func addResponseFormatVary(w http.ResponseWriter) {
	if slices.Contains(w.Header()["Vary"], "Accept") {
		return
	}
	w.Header().Add("Vary", "Accept")
	w.Header().Add("Vary", "Content-Type")
	w.Header().Add("Vary", "Prefer")
	w.Header().Add("Vary", "Range")
}

// makeResponseWithQuery picks the output format from query. A nil query falls
// back to r.URL.Query(); a non-nil map (including empty url.Values{}) is used
// as-is and does not merge with the URL.
func makeResponseWithQuery(w http.ResponseWriter, r *http.Request, status int, v any, query url.Values) {
	cw := newContentWriter(w, r, "", nil, query, contentPluginRef{}, false)
	var pag map[string]any
	if r != nil {
		pag, _ = r.Context().Value(contentPaginationCtxKey{}).(map[string]any)
	}
	_ = cw.Write(status, v, pag)
}
