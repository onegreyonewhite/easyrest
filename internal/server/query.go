package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// queryHandler processes read-only SQL queries via the QUERY HTTP method.
func queryHandler(w http.ResponseWriter, r *http.Request) {
	dbKey := strings.ToLower(chi.URLParam(r, "db"))

	config := GetConfig()

	currentQueryPlugins := *QueryPlugins.Load()
	queryPlug, ok := currentQueryPlugins[dbKey]
	if !ok {
		http.Error(w, "Query plugin not found", http.StatusNotFound)
		return
	}

	_, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if config.CheckScope {
		w.Header().Add("Vary", "Authorization")
		claims := getTokenClaims(r)
		if !CheckScope(claims, "read") {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	cfg := GetConfig()
	if cfg.Server.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize)
	}
	defer r.Body.Close()

	queryBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	query := strings.TrimSpace(string(queryBytes))
	if query == "" {
		http.Error(w, "Query body is empty", http.StatusBadRequest)
		return
	}

	pluginCtx := BuildPluginContext(r)
	applied := strings.Builder{}
	tx := pluginCtx["prefer"].(map[string]any)["tx"]
	if tx != nil {
		applied.WriteString("tx=" + tx.(string) + " ")
	}
	applied.WriteString("timezone=" + pluginCtx["timezone"].(string))
	w.Header().Set("Preference-Applied", applied.String())

	startTime := time.Now()
	rows, err := queryPlug.QueryCall(query, pluginCtx)
	queryTime := time.Since(startTime)

	w.Header().Set("Server-Timing", "db;dur="+strconv.FormatFloat(float64(queryTime.Milliseconds()), 'f', 3, 64))

	if err != nil {
		http.Error(w, "Error in QueryCall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == nil {
		rows = []map[string]any{}
	}

	makeResponse(w, r, http.StatusOK, rows)
}
