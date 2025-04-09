package server

import (
	"fmt"
	"net/http"
	"strings"

	stdlog "log" // Added for logging cache invalidation errors

	"github.com/gorilla/mux"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// updateSwaggerSpecWithRPC adds paths for RPC functions based on rpcDefinitions.
func updateSwaggerSpecWithRPC(swaggerSpec map[string]any, rpcDefinitions map[string]any) {
	paths, ok := swaggerSpec["paths"].(map[string]any)
	if !ok {
		paths = make(map[string]any)
		swaggerSpec["paths"] = paths
	}
	for funcName, def := range rpcDefinitions {
		arr, ok := def.([]any)
		if !ok || len(arr) != 2 {
			continue
		}
		reqSchema := arr[0]
		respSchema := arr[1]
		path := "/rpc/" + funcName + "/"
		op := map[string]any{
			"summary":     fmt.Sprintf("Call RPC function %s", funcName),
			"description": fmt.Sprintf("Invoke the RPC function %s", funcName),
			"parameters": []any{
				map[string]any{
					"name":        "body",
					"in":          "body",
					"description": "RPC request payload",
					"required":    true,
					"schema":      reqSchema,
				},
			},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "RPC response",
					"schema":      respSchema,
				},
			},
			"security": []map[string]any{
				{"jwtToken": []string{}},
			},
		}
		paths[path] = map[string]any{
			"post": op,
		}
	}
}

// rpcHandler processes RPC calls to plugin functions.
func rpcHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	funcName := vars["func"]

	// Get current plugins map
	currentDbPlugins := *DbPlugins.Load()

	// Get the specific plugin
	dbPlug, ok := currentDbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	config := GetConfig() // Moved GetConfig call earlier to access PluginMap
	if config.CheckScope {
		requiredScope := funcName + "-write" // Assuming RPC calls are write operations for scope check
		claims := getTokenClaims(r)
		if !CheckScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	// Using parseRequest to handle different formats of incoming data
	parsedData, err := parseRequest(r, false) // expecting a single object
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Casting to the expected type
	data, ok := parsedData.(map[string]any)
	if !ok {
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	pluginCtx := BuildPluginContext(r)
	w.Header().Set("Preference-Applied", "timezone="+pluginCtx["timezone"].(string))
	flatCtx, err := easyrest.FormatToContext(pluginCtx)
	if err != nil {
		http.Error(w, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data = substituteValue(data, flatCtx, pluginCtx).(map[string]any)
	result, err := dbPlug.CallFunction(userID, funcName, data, pluginCtx)
	if err != nil {
		http.Error(w, "Error in CallFunction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ETag Cache Invalidation Logic START
	pluginCfg, cfgOk := config.PluginMap[dbKey]
	// Check if config exists, EnableCache is true, AND FuncInvalidationMap is present
	if cfgOk && pluginCfg.EnableCache && pluginCfg.FuncInvalidationMap != nil {
		if tablesToInvalidate, mapOk := pluginCfg.FuncInvalidationMap[funcName]; mapOk && len(tablesToInvalidate) > 0 {
			cachePlugin := getFirstCachePlugin(dbKey) // Assumes this helper is available
			if cachePlugin != nil {
				stdlog.Printf("Invalidating ETags for tables %v due to RPC call %s/%s", tablesToInvalidate, dbKey, funcName)
				for _, tableName := range tablesToInvalidate {
					etagKey := fmt.Sprintf("etag:%s:%s", dbKey, tableName)
					_ = updateETag(cachePlugin, etagKey) // Assumes this helper is available; ignore returned ETag
				}
			} else {
				stdlog.Printf("Warning: Cache invalidation configured and enabled for %s/%s, but no cache plugin is loaded.", dbKey, funcName)
			}
		}
	}
	// ETag Cache Invalidation Logic END

	makeResponse(w, r, http.StatusOK, result)
}
