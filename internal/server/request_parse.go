package server

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
)

// ParseCSV splits a comma-separated string.
func ParseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parseRequest parses the request body according to the Content-Type.
// The parameter expectArray indicates whether an array of objects (true) or a single object (false) is expected.
func parseRequest(w http.ResponseWriter, r *http.Request, expectArray bool) (interface{}, error) {
	cfg := currentConfig()
	// Limit request body size
	if cfg.Server.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize)
	}

	contentType := r.Header.Get("Content-Type")
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}
	contentType = strings.TrimSpace(contentType)

	switch contentType {
	case "application/json", "":
		// By default, use JSON.
		decoder := json.NewDecoder(r.Body)
		if expectArray {
			var data []map[string]any
			if err := decoder.Decode(&data); err != nil {
				return nil, fmt.Errorf("JSON parse error: %w", err)
			}
			return data, nil
		} else {
			var data map[string]any
			if err := decoder.Decode(&data); err != nil {
				return nil, fmt.Errorf("JSON parse error: %w", err)
			}
			return data, nil
		}

	case "text/csv":
		reader := csv.NewReader(r.Body)
		records, err := reader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("CSV parse error: %w", err)
		}

		if len(records) < 1 {
			return nil, fmt.Errorf("empty CSV data")
		}

		headers := records[0]
		result := make([]map[string]any, 0, len(records)-1)

		for i := 1; i < len(records); i++ {
			row := make(map[string]any)
			for j, header := range headers {
				if j < len(records[i]) {
					row[header] = records[i][j]
				} else {
					row[header] = ""
				}
			}
			result = append(result, row)
		}

		// If only a single object is expected, but CSV typically represents an array.
		if !expectArray && len(result) > 0 {
			return result[0], nil
		}
		return result, nil

	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("form parse error: %w", err)
		}

		if expectArray {
			// It is difficult to represent an array of objects for form-urlencoded.
			// Return an array with a single object if an array is expected.
			result := make([]map[string]any, 1)
			data := make(map[string]any)
			for key, values := range r.Form {
				if len(values) == 1 {
					data[key] = values[0]
				} else {
					data[key] = values
				}
			}
			result[0] = data
			return result, nil
		} else {
			data := make(map[string]any)
			for key, values := range r.Form {
				if len(values) == 1 {
					data[key] = values[0]
				} else {
					data[key] = values
				}
			}
			return data, nil
		}

	case "application/xml":
		if expectArray {
			// XML does not have a standard representation for an array of objects.
			// Expect something like <items><item>...</item><item>...</item></items>.
			var result struct {
				Items []map[string]any `xml:"item"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&result); err != nil {
				return nil, fmt.Errorf("XML parse error: %w", err)
			}
			return result.Items, nil
		} else {
			// For XML, a root element is required.
			var wrapper struct {
				Data map[string]any `xml:",any"`
			}
			if err := xml.NewDecoder(r.Body).Decode(&wrapper); err != nil {
				return nil, fmt.Errorf("XML parse error: %w", err)
			}
			return wrapper.Data, nil
		}

	default:
		return nil, fmt.Errorf("unsupported Content-Type: %s", contentType)
	}
}
