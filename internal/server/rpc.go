package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
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

	dbPlug, ok := DbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	config := GetConfig()
	if config.CheckScope {
		requiredScope := funcName + "-write"
		claims := getTokenClaims(r)
		if !CheckScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	var data map[string]any
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	pluginCtx := BuildPluginContext(r)
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
	respondJSON(w, http.StatusOK, result)
}
