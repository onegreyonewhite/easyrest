package server

import (
	"net/http"
	"strings"
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

// parseRequest parses the request body with the selected content plugin.
// expectArray asks for an array of objects. A false value asks for one object.
func parseRequest(w http.ResponseWriter, r *http.Request, expectArray bool) (any, error) {
	cfg := currentConfig()
	if cfg.Server.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize)
	}
	choice := requestContentChoice(r, nil)
	return readParsedBody(r, choice, expectArray)
}
