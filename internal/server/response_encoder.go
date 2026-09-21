package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"

	"github.com/goccy/go-json"
)

type responseEncoder interface {
	Write(w http.ResponseWriter, status int, v any)
}

type streamEncoder interface {
	Begin(w http.ResponseWriter, status int) pageWriter
}

type pageWriter interface {
	WritePage(rows []map[string]any) error
}

var (
	jsonEnc   jsonEncoder
	xmlEnc    xmlEncoder
	csvEnc    csvEncoder
	formEnc   formEncoder
	ndjsonEnc ndjsonEncoder

	responseEncoders map[string]responseEncoder
)

func init() {
	responseEncoders = map[string]responseEncoder{
		"application/json":                  &jsonEnc,
		"application/xml":                   &xmlEnc,
		"text/csv":                          &csvEnc,
		"application/x-www-form-urlencoded": &formEnc,
		contentTypeNDJSON:                   &ndjsonEnc,
	}
	supportedTypes = make([]string, 0, len(responseEncoders))
	for mediaType := range responseEncoders {
		supportedTypes = append(supportedTypes, mediaType)
	}
}

func encoderFor(mediaType string) responseEncoder {
	if enc, ok := responseEncoders[mediaType]; ok {
		return enc
	}
	return &jsonEnc
}

type jsonEncoder struct{}

func (*jsonEncoder) Write(w http.ResponseWriter, status int, v any) {
	respondJSON(w, status, v)
}

type csvEncoder struct{}

func (*csvEncoder) Write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/csv")
	w.WriteHeader(status)

	writer := csv.NewWriter(w)

	var records [][]string

	if data, ok := v.([]map[string]any); ok && len(data) > 0 {
		headers := make(map[string]bool)
		for _, item := range data {
			for key := range item {
				headers[key] = true
			}
		}

		headerSlice := make([]string, 0, len(headers))
		for header := range headers {
			headerSlice = append(headerSlice, header)
		}

		records = append(records, headerSlice)

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
		headers := make([]string, 0, len(data))
		values := make([]string, 0, len(data))

		for key, val := range data {
			headers = append(headers, key)
			values = append(values, fmt.Sprintf("%v", val))
		}

		records = append(records, headers, values)
	} else {
		http.Error(w, "Data format not suitable for CSV", http.StatusInternalServerError)
		return
	}

	if err := writer.WriteAll(records); err != nil {
		http.Error(w, "Error writing CSV", http.StatusInternalServerError)
		return
	}
}

type xmlEncoder struct{}

func (*xmlEncoder) Write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

	if data, ok := v.([]map[string]any); ok {
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
		fmt.Fprintf(w, "<item>\n")
		for key, val := range data {
			fmt.Fprintf(w, "  <%s>%v</%s>\n", key, val, key)
		}
		fmt.Fprintf(w, "</item>")
	} else {
		http.Error(w, "Data format not suitable for XML", http.StatusInternalServerError)
		return
	}
}

type formEncoder struct{}

func (*formEncoder) Write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	w.WriteHeader(status)

	var values url.Values = make(url.Values)

	if data, ok := v.(map[string]any); ok {
		for key, val := range data {
			values.Set(key, fmt.Sprintf("%v", val))
		}
	} else if data, ok := v.([]map[string]any); ok && len(data) > 0 {
		for key, val := range data[0] {
			values.Set(key, fmt.Sprintf("%v", val))
		}
	} else {
		http.Error(w, "Data format not suitable for form-urlencoded", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(values.Encode()))
}

type ndjsonEncoder struct{}

func (*ndjsonEncoder) Write(w http.ResponseWriter, status int, v any) {
	respondNDJSON(w, status, v)
}

func (*ndjsonEncoder) Begin(w http.ResponseWriter, status int) pageWriter {
	w.Header().Set("Content-Type", contentTypeNDJSON)
	w.WriteHeader(status)
	refreshNDJSONWriteDeadline(w)
	_ = http.NewResponseController(w).Flush()
	return &ndjsonPageWriter{w: w, enc: newJSONEncoder(w)}
}

type ndjsonPageWriter struct {
	w   http.ResponseWriter
	enc *json.Encoder
}

func (p *ndjsonPageWriter) WritePage(rows []map[string]any) error {
	return writeNDJSONPage(p.w, p.enc, rows)
}
