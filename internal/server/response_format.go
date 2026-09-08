package server

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	stdlog "log"
)

var supportedTypes = [4]string{
	"application/json",
	"application/xml",
	"text/csv",
	"application/x-www-form-urlencoded",
}

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

// makeResponseWithQuery picks the output format from query. A nil query falls
// back to r.URL.Query(); a non-nil map (including empty url.Values{}) is used
// as-is and does not merge with the URL.
func makeResponseWithQuery(w http.ResponseWriter, r *http.Request, status int, v any, query url.Values) {
	format := ""
	if query != nil {
		format = query.Get("format")
	} else {
		format = r.URL.Query().Get("format")
	}

	acceptHeader := ""
	switch strings.ToLower(format) {
	case "json":
		w.Header().Add("Vary", "Accept")
		respondJSON(w, status, v)
		return
	case "xml":
		acceptHeader = "application/xml"
	case "csv":
		acceptHeader = "text/csv"
	case "":
		// No format param, fall back to Accept and Content-Type headers below.
	default:
		acceptHeader = format
	}

	if acceptHeader == "" {
		acceptHeader = r.Header.Get("Accept")
		if acceptHeader == "" || acceptHeader == "*/*" {
			acceptHeader = mediaType(r.Header.Get("Content-Type"))
			w.Header().Add("Vary", "Content-Type")
			w.Header().Add("Vary", "Accept")
			if acceptHeader == "" || acceptHeader == "application/json" {
				respondJSON(w, status, v)
				return
			}
		} else if strings.IndexByte(acceptHeader, ',') < 0 {
			acceptHeader = mediaType(acceptHeader)
			w.Header().Add("Vary", "Accept")
			if acceptHeader == "" || acceptHeader == "application/json" {
				respondJSON(w, status, v)
				return
			}
		} else {
			acceptHeader = firstSupportedAccept(acceptHeader)
			w.Header().Add("Vary", "Accept")
			if acceptHeader == "" || acceptHeader == "application/json" {
				respondJSON(w, status, v)
				return
			}
		}
	} else {
		acceptHeader = mediaType(acceptHeader)
		w.Header().Add("Vary", "Accept")
		if acceptHeader == "" || acceptHeader == "application/json" {
			respondJSON(w, status, v)
			return
		}
	}

	switch acceptHeader {
	case "application/json", "":
		// By default, use JSON.
		respondJSON(w, status, v)
		return

	case "text/csv":
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(status)

		writer := csv.NewWriter(w)

		// Convert the data into the required format for CSV.
		var records [][]string

		// Handle the case of an array of objects.
		if data, ok := v.([]map[string]any); ok && len(data) > 0 {
			// Collect all headers from all objects.
			headers := make(map[string]bool)
			for _, item := range data {
				for key := range item {
					headers[key] = true
				}
			}

			// Convert the header map into a slice.
			headerSlice := make([]string, 0, len(headers))
			for header := range headers {
				headerSlice = append(headerSlice, header)
			}

			// Add the header row.
			records = append(records, headerSlice)

			// Add the data rows.
			for _, item := range data {
				row := make([]string, len(headerSlice))
				for i, header := range headerSlice {
					if val, ok := item[header]; ok {
						row[i] = fmt.Sprintf("%v", val)
					}
				}
				records = append(records, row)
			}
		} else if data, ok := v.(map[string]any); ok {
			// Handle the case of a single object.
			headers := make([]string, 0, len(data))
			values := make([]string, 0, len(data))

			for key, val := range data {
				headers = append(headers, key)
				values = append(values, fmt.Sprintf("%v", val))
			}

			records = append(records, headers, values)
		} else {
			// If the data type is not suitable for CSV.
			http.Error(w, "Data format not suitable for CSV", http.StatusInternalServerError)
			return
		}

		if err := writer.WriteAll(records); err != nil {
			http.Error(w, "Error writing CSV", http.StatusInternalServerError)
			return
		}

		return

	case "application/xml":
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)

		fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

		// Handle different types of data.
		if data, ok := v.([]map[string]any); ok {
			// For an array of objects.
			fmt.Fprintf(w, "<items>\n")
			for _, item := range data {
				fmt.Fprintf(w, "  <item>\n")
				for key, val := range item {
					fmt.Fprintf(w, "    <%s>%v</%s>\n", key, val, key)
				}
				fmt.Fprintf(w, "  </item>\n")
			}
			fmt.Fprintf(w, "</items>")
		} else if data, ok := v.(map[string]any); ok {
			// For a single object.
			fmt.Fprintf(w, "<item>\n")
			for key, val := range data {
				fmt.Fprintf(w, "  <%s>%v</%s>\n", key, val, key)
			}
			fmt.Fprintf(w, "</item>")
		} else {
			// If the data type is unknown.
			http.Error(w, "Data format not suitable for XML", http.StatusInternalServerError)
			return
		}

		return

	case "application/x-www-form-urlencoded":
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(status)

		var values url.Values = make(url.Values)

		if data, ok := v.(map[string]any); ok {
			for key, val := range data {
				values.Set(key, fmt.Sprintf("%v", val))
			}
		} else if data, ok := v.([]map[string]any); ok && len(data) > 0 {
			// For an array, take only the first object.
			for key, val := range data[0] {
				values.Set(key, fmt.Sprintf("%v", val))
			}
		} else {
			http.Error(w, "Data format not suitable for form-urlencoded", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(values.Encode()))
		return

	default:
		// If the format is not supported, use JSON.
		respondJSON(w, status, v)
	}
}
