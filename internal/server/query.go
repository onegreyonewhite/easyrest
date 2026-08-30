package server

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// queryHandler processes read-only SQL queries via the QUERY HTTP method.
func queryHandler(w http.ResponseWriter, r *http.Request) {
	dbKey := strings.ToLower(chi.URLParam(r, "db"))

	config := currentConfig()

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

	if !enforceScope(w, r, config.CheckScope, false, "read") {
		return
	}

	if config.Server.MaxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, config.Server.MaxBodySize)
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
	pluginCtx, mwOK := runPreRequestMiddlewares(w, dbKey, pluginCtx)
	if !mwOK {
		return
	}
	setPreferenceApplied(w, pluginCtx)

	startTime := time.Now()
	rows, err := queryPlug.QueryCall(query, pluginCtx)
	queryTime := time.Since(startTime)

	setDBServerTiming(w, queryTime)

	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in QueryCall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if rows == nil {
		rows = []map[string]any{}
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusOK, rows, nil)
}
