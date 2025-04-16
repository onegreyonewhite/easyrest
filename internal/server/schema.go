package server

import (
	"fmt"
	"net/http"
	"strings"

	"slices"

	"maps"

	"github.com/gorilla/mux"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// buildSwaggerSpec constructs a Swagger 2.0 specification based on table definitions and RPC definitions.
// dbKey is the current database key.
func buildSwaggerSpec(r *http.Request, dbKey string, tableDefs, viewDefs, rpcDefs map[string]any) map[string]any {
	cfg := GetConfig()
	pluginCfg, hasPluginCfg := cfg.PluginMap[dbKey]

	// Merge tables and views into one definitions map.
	mergedDefs := make(map[string]any)
	maps.Copy(mergedDefs, tableDefs)
	maps.Copy(mergedDefs, viewDefs)

	// Remove restricted tables
	if hasPluginCfg {
		for k := range mergedDefs {
			if slices.Contains(pluginCfg.Exclude.Table, k) {
				delete(mergedDefs, k)
			}
		}
	}

	var jwtTokenSecurity map[string]any
	if cfg.TokenURL != "" {
		jwtTokenSecurity = map[string]any{
			"type":     "oauth2",
			"flow":     cfg.AuthFlow,
			"tokenUrl": cfg.TokenURL,
			"scopes":   map[string]any{},
		}
	} else {
		jwtTokenSecurity = map[string]any{
			"type":        "apiKey",
			"name":        "Authorization",
			"in":          "header",
			"description": "Enter token in format 'Bearer {token}'",
		}
	}

	// Get public tables and funcs for this dbKey
	var publicTables, publicFuncs []string
	title := "EasyRest API"
	if pluginCfg, ok := cfg.PluginMap[dbKey]; ok {
		publicTables = pluginCfg.Public.Table
		publicFuncs = pluginCfg.Public.Func
		if pluginCfg.Title != "" {
			title = pluginCfg.Title
		}
	}

	swaggerDef := map[string]any{
		"swagger": "2.0",
		"info": map[string]any{
			"title":   title,
			"version": easyrest.Version,
		},
		"host":        r.Host,
		"basePath":    "/api/" + dbKey,
		"schemes":     []string{"http"},
		"consumes":    []string{"application/json"},
		"produces":    []string{"application/json"},
		"definitions": mergedDefs,
		"securityDefinitions": map[string]any{
			"jwtToken": jwtTokenSecurity,
		},
		"paths": map[string]any{},
	}
	paths := swaggerDef["paths"].(map[string]any)

	for tableName, modelSchemaRaw := range mergedDefs {
		modelSchema, ok := modelSchemaRaw.(map[string]any)
		if !ok {
			continue
		}
		properties, _ := modelSchema["properties"].(map[string]any)
		pathObject := make(map[string]any)

		// Determine if this table is public
		isPublicTable := slices.Contains(publicTables, tableName)

		getOp := buildGETEndpoint(tableName, properties)
		if isPublicTable {
			getOp["security"] = []map[string]any{} // No security for public
		}
		pathObject["get"] = getOp

		if _, ok := tableDefs[tableName]; ok {
			// Build additional endpoints (POST, PATCH, DELETE) only for tables.
			postOp := buildPOSTEndpoint(tableName)
			patchOp := buildPATCHEndpoint(tableName, properties)
			deleteOp := buildDELETEEndpoint(tableName, properties)
			if isPublicTable {
				postOp["security"] = []map[string]any{}
				patchOp["security"] = []map[string]any{}
				deleteOp["security"] = []map[string]any{}
			}
			pathObject["post"] = postOp
			pathObject["patch"] = patchOp
			pathObject["delete"] = deleteOp
		}
		paths["/"+tableName+"/"] = pathObject
	}

	// If RPC definitions exist, add them to the swaggerSpec.
	// Patch updateSwaggerSpecWithRPC to support public funcs
	for funcName, def := range rpcDefs {
		arr, ok := def.([]any)
		if !ok || len(arr) != 2 {
			continue
		}

		// Check if function is restricted for this dbKey
		if hasPluginCfg {
			if slices.Contains(pluginCfg.Exclude.Func, funcName) {
				continue
			}
		}
		reqSchema := arr[0]
		respSchema := arr[1]
		path := "/rpc/" + funcName + "/"
		isPublicFunc := slices.Contains(publicFuncs, funcName)
		security := []map[string]any{{"jwtToken": []string{}}}
		if isPublicFunc {
			security = []map[string]any{} // No security for public
		}
		op := map[string]any{
			"summary":     fmt.Sprintf("Call RPC function %s", funcName),
			"description": fmt.Sprintf("Invoke the RPC function %s", funcName),
			"parameters": []map[string]any{
				{
					"name":        "body",
					"in":          "body",
					"description": "RPC request payload",
					"required":    true,
					"schema":      reqSchema,
				},
			},
			"responses": map[string]map[string]any{
				"200": {
					"description": "RPC response",
					"schema":      respSchema,
				},
			},
			"security": security,
		}
		paths[path] = map[string]any{
			"post": op,
		}
	}

	return swaggerDef
}

// buildGETEndpoint constructs a GET operation map with query parameters for the given name and property set.
func buildGETEndpoint(name string, properties map[string]any) map[string]any {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}

	getParams := buildSchemaParams(fieldNames, properties, true)
	return map[string]any{
		"summary":     fmt.Sprintf("Get %s", name),
		"description": fmt.Sprintf("Retrieve rows from the %s", name),
		"parameters":  getParams,
		"responses": map[string]any{
			"200": map[string]any{
				"description": "Successful response",
				"schema": map[string]any{
					"type":  "array",
					"items": map[string]any{"$ref": "#/definitions/" + name},
				},
			},
		},
		"security": []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildGETParams creates the common query parameters (select, ordering, limit, offset)
// plus where-filters based on the field types.
func buildSchemaParams(fieldNames []string, properties map[string]any, isGet bool) []map[string]any {
	var params []map[string]any

	if isGet {
		orderingFieldNames := make([]string, 0)
		for _, fieldName := range fieldNames {
			orderingFieldNames = append(orderingFieldNames, fieldName)
			orderingFieldNames = append(orderingFieldNames, "-"+fieldName)
		}
		// Basic query parameters: select, ordering, limit, offset.
		params = append(params, []map[string]any{
			{
				"name":             "select",
				"in":               "query",
				"description":      "Comma-separated list of fields",
				"type":             "array",
				"items":            map[string]any{"type": "string", "enum": fieldNames},
				"required":         false,
				"collectionFormat": "csv",
			},
			{
				"name":             "ordering",
				"in":               "query",
				"description":      "Comma-separated ordering fields",
				"type":             "array",
				"items":            map[string]any{"type": "string", "enum": orderingFieldNames},
				"required":         false,
				"collectionFormat": "csv",
			},
			{
				"name":        "limit",
				"in":          "query",
				"description": "Maximum number of records to return",
				"type":        "integer",
				"required":    false,
			},
			{
				"name":        "offset",
				"in":          "query",
				"description": "Number of records to skip",
				"type":        "integer",
				"required":    false,
			},
		}...)
	}

	// Build where filters for each field and operator.
	for _, fieldName := range fieldNames {
		prop, _ := properties[fieldName].(map[string]any)
		paramType := "string"
		if propType, exists := prop["type"].(string); exists {
			paramType = propType
		}
		for op := range AllowedOps {
			// For string fields, skip lt, lte, gt, gte.
			if paramType == "string" {
				if op == "lt" || op == "lte" || op == "gt" || op == "gte" {
					continue
				}
			}
			// For numeric fields, skip like and ilike.
			if paramType == "integer" || paramType == "number" {
				if op == "like" || op == "ilike" {
					continue
				}
			}
			param := make(map[string]any)
			param["name"] = fmt.Sprintf("where.%s.%s", op, fieldName)
			param["description"] = fmt.Sprintf("Filter for field '%s' with operator %s", fieldName, op)
			param["in"] = "query"
			param["type"] = paramType
			param["required"] = false
			if op == "in" {
				param["collectionFormat"] = "csv"
			}
			params = append(params, param)
		}
	}

	return params
}

// buildPOSTEndpoint returns a POST operation map for the given table name.
func buildPOSTEndpoint(name string) map[string]any {
	return map[string]any{
		"summary":     fmt.Sprintf("Create rows in %s", name),
		"description": fmt.Sprintf("Insert new rows into %s", name),
		"parameters": []map[string]any{
			{
				"name":        "body",
				"in":          "body",
				"description": fmt.Sprintf("Array of %s objects", name),
				"required":    true,
				"schema": map[string]any{
					"type":  "array",
					"items": map[string]any{"$ref": "#/definitions/" + name},
				},
			},
		},
		"responses": map[string]any{
			"201": map[string]any{
				"description": "Rows created",
			},
		},
		"security": []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildPATCHEndpoint returns a PATCH operation map for the given table name.
func buildPATCHEndpoint(name string, properties map[string]any) map[string]any {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)
	return map[string]any{
		"summary":     fmt.Sprintf("Update rows in %s", name),
		"description": fmt.Sprintf("Update existing rows in %s", name),
		"parameters": append(getParams, map[string]any{
			"name":        "body",
			"in":          "body",
			"description": fmt.Sprintf("Partial update of a %s object", name),
			"required":    true,
			"schema":      map[string]any{"$ref": "#/definitions/" + name},
		}),
		"responses": map[string]any{
			"200": map[string]any{
				"description": "Rows updated",
				"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"updated": map[string]any{"type": "integer"},
					},
				},
			},
		},
		"security": []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildDELETEEndpoint returns a DELETE operation map for the given table name.
func buildDELETEEndpoint(name string, properties map[string]any) map[string]any {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)

	return map[string]any{
		"summary":     fmt.Sprintf("Delete rows from %s", name),
		"description": fmt.Sprintf("Delete rows from %s", name),
		"parameters":  getParams,
		"responses": map[string]any{
			"204": map[string]any{
				"description": "Rows deleted",
			},
		},
		"security": []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// schemaHandler now builds and returns a full swagger 2.0 spec.
func schemaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])

	// Get current plugins map
	currentDbPlugins := *DbPlugins.Load()
	// Get the specific plugin
	dbPlug, ok := currentDbPlugins[dbKey]
	if !ok {
		http.Error(w, "DB plugin not found", http.StatusNotFound)
		return
	}

	swaggerSpec, ok := schemaCache[dbKey]
	if !ok {
		pluginCtx := BuildPluginContext(r)
		schemaRaw, err := dbPlug.GetSchema(pluginCtx)
		if err != nil {
			http.Error(w, "GetSchema not implemented", http.StatusNotImplemented)
			return
		}
		schemaMap, ok := schemaRaw.(map[string]any)
		if !ok {
			http.Error(w, "Invalid schema format", http.StatusInternalServerError)
			return
		}
		tableDefs, ok := schemaMap["tables"].(map[string]any)
		if !ok {
			http.Error(w, "Invalid tables schema", http.StatusInternalServerError)
			return
		}
		var viewDefs map[string]any
		if raw, exists := schemaMap["views"]; exists && raw != nil {
			if m, ok := raw.(map[string]any); ok {
				viewDefs = m
			}
		}
		var rpcDefs map[string]any
		if raw, exists := schemaMap["rpc"]; exists && raw != nil {
			if m, ok := raw.(map[string]any); ok {
				rpcDefs = m
			}
		}
		schemaCacheMutex.Lock()
		swaggerSpec = buildSwaggerSpec(r, dbKey, tableDefs, viewDefs, rpcDefs)
		schemaCacheMutex.Unlock()
	}

	respondJSON(w, http.StatusOK, swaggerSpec)
}
