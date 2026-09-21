package server

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	stdlog "log"
)

const contentTypeNDJSON = "application/x-ndjson"

var supportedTypes []string

const maxJSONBufferCap = 64 << 10

var jsonBufferPool sync.Pool

func init() {
	jsonBufferPool.New = func() any {
		return &bytes.Buffer{}
	}
}

func putJSONBuffer(buf *bytes.Buffer) {
	if buf.Cap() > maxJSONBufferCap {
		return
	}
	jsonBufferPool.Put(buf)
}

func mediaType(s string) string {
	if idx := strings.Index(s, ";"); idx != -1 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func firstSupportedAccept(acceptHeader string) string {
	for t := range strings.SplitSeq(acceptHeader, ",") {
		t = mediaType(t)
		for _, supported := range supportedTypes {
			if t == supported {
				return t
			}
		}
	}
	return ""
}

func queryFormat(r *http.Request, query url.Values) string {
	if query != nil {
		return query.Get("format")
	}
	return r.URL.Query().Get("format")
}

// negotiateResponseType returns the response media type and whether the
// Content-Type header was used as a fallback (so callers can set Vary).
func negotiateResponseType(r *http.Request, query url.Values) (typ string, varyContentType bool) {
	switch strings.ToLower(queryFormat(r, query)) {
	case "json":
		return "application/json", false
	case "xml":
		return "application/xml", false
	case "csv":
		return "text/csv", false
	case "ndjson":
		return contentTypeNDJSON, false
	case "":
		// Fall through to Accept / Content-Type.
	default:
		return mediaType(queryFormat(r, query)), false
	}

	acceptHeader := r.Header.Get("Accept")
	if acceptHeader == "" || acceptHeader == "*/*" {
		ct := mediaType(r.Header.Get("Content-Type"))
		if ct == "" {
			return "application/json", true
		}
		return ct, true
	}
	if strings.IndexByte(acceptHeader, ',') < 0 {
		t := mediaType(acceptHeader)
		if t == "" {
			return "application/json", false
		}
		return t, false
	}
	t := firstSupportedAccept(acceptHeader)
	if t == "" {
		return "application/json", false
	}
	return t, false
}

func newJSONEncoder(w http.ResponseWriter) *json.Encoder {
	enc := json.NewEncoder(w)
	if currentConfig().Server.DisableHTMLEscape {
		enc.SetEscapeHTML(false)
	}
	return enc
}

func writeNDJSON(enc *json.Encoder, v any) error {
	switch data := v.(type) {
	case []map[string]any:
		for i := range data {
			if err := enc.Encode(data[i]); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		return enc.Encode(data)
	default:
		return enc.Encode(v)
	}
}

func respondNDJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentTypeNDJSON)
	w.WriteHeader(status)
	if err := writeNDJSON(newJSONEncoder(w), v); err != nil {
		stdlog.Printf("Error encoding NDJSON response: %v", err)
	}
}

// respondJSON serializes v to JSON and writes it to w with Content-Type header.
func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	bufAny := jsonBufferPool.Get()
	buf, ok := bufAny.(*bytes.Buffer)
	if !ok {
		buf = &bytes.Buffer{}
	}
	buf.Reset()
	defer putJSONBuffer(buf)

	enc := json.NewEncoder(buf)
	if currentConfig().Server.DisableHTMLEscape {
		enc.SetEscapeHTML(false)
	}
	if err := enc.Encode(v); err != nil {
		stdlog.Printf("Error encoding JSON response: %v", err)
		return
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		stdlog.Printf("Error writing JSON response: %v", err)
	}
}

// parseRequest parses the request body according to the Content-Type.
// The parameter expectArray indicates whether an array of objects (true) or a single object (false) is expected.
// makeResponse transforms the data according to the Accept header and sends the response.
func makeResponse(w http.ResponseWriter, r *http.Request, status int, v any) {
	makeResponseWithQuery(w, r, status, v, nil)
}

func addResponseFormatVary(w http.ResponseWriter) {
	for _, v := range w.Header()["Vary"] {
		if v == "Accept" {
			return
		}
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
	acceptHeader, _ := negotiateResponseType(r, query)
	addResponseFormatVary(w)
	if acceptHeader == "" || acceptHeader == "application/json" {
		respondJSON(w, status, v)
		return
	}
	encoderFor(acceptHeader).Write(w, status, v)
}
