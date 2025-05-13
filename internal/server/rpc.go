package server

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	stdlog "log" // Added for logging cache invalidation errors

	"github.com/gorilla/mux"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// rpcHandler processes RPC calls to plugin functions.
func rpcHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	funcName := vars["func"]

	// Get global config
	config := GetConfig()

	// Get plugin config
	pluginCfg, hasPluginCfg := config.PluginMap[dbKey]

	// Check if function is restricted for this dbKey
	if hasPluginCfg {
		if slices.Contains(pluginCfg.Exclude.Func, funcName) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		// Check AllowList if it's defined and not empty
		if len(pluginCfg.AllowList.Func) > 0 {
			if !slices.Contains(pluginCfg.AllowList.Func, funcName) {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
		}
	}

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

	// Check if function is public for this dbKey
	isPublicFunc := false
	if hasPluginCfg {
		isPublicFunc = slices.Contains(pluginCfg.Public.Func, funcName)
	}

	if config.CheckScope && !isPublicFunc {
		requiredScope := funcName + "-write" // Assuming RPC calls are write operations for scope check
		w.Header().Add("Vary", "Authorization")
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

	applied := strings.Builder{}
	tx := pluginCtx["prefer"].(map[string]any)["tx"]
	if tx != nil {
		applied.WriteString("tx=" + tx.(string) + " ")
	}
	applied.WriteString("timezone=" + pluginCtx["timezone"].(string))
	w.Header().Set("Preference-Applied", applied.String())

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
