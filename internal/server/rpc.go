package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// rpcHandler processes RPC calls to plugin functions.
func rpcHandler(w http.ResponseWriter, r *http.Request) {
	dbKey := strings.ToLower(chi.URLParam(r, "db"))
	funcName := chi.URLParam(r, "func")

	if err := sanitizeIdentifier(funcName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	preCfg := currentConfig()
	prePluginCfg := preCfg.PluginMap[dbKey]
	dbPlug, config, pluginCfg, ok := resolveDBPlugin(w, dbKey, funcName, prePluginCfg.Exclude.Func, prePluginCfg.AllowList.Func, nil)
	if !ok {
		return
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	isPublicFunc := slices.Contains(pluginCfg.Public.Func, funcName)
	if !enforceScope(w, r, config.CheckScope, isPublicFunc, funcName+"-write") {
		return
	}

	// Using parseRequest to handle different formats of incoming data
	parsedData, err := parseRequest(w, r, false) // expecting a single object
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
	pluginCtx, mwOK := runPreRequestMiddlewares(w, dbKey, pluginCtx)
	if !mwOK {
		return
	}
	setPreferenceApplied(w, pluginCtx)

	flatCtx, err := easyrest.FormatToContext(pluginCtx)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}
	data = substituteValue(data, flatCtx, pluginCtx).(map[string]any)
	if err := validateBodyColumns(data); err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, err.Error(), http.StatusBadRequest)
		return
	}
	result, returnedCtx, err := dbPlug.CallFunction(userID, funcName, data, pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	if err != nil {
		middlewareHTTPError(w, dbKey, pluginCtx, "Error in CallFunction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	middlewareMakeResponse(w, r, dbKey, pluginCtx, http.StatusOK, result, nil)
}
