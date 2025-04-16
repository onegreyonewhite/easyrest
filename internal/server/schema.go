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

// SwaggerSpec represents the Swagger 2.0 specification structure.
type SwaggerSpec struct {
	Swagger             string         `json:"swagger"`
	Info                SwaggerInfo    `json:"info"`
	Host                string         `json:"host"`
	BasePath            string         `json:"basePath"`
	Schemes             []string       `json:"schemes"`
	Consumes            []string       `json:"consumes"`
	Produces            []string       `json:"produces"`
	Definitions         map[string]any `json:"definitions"`
	SecurityDefinitions map[string]any `json:"securityDefinitions"`
	Paths               map[string]any `json:"paths"`
}

type SwaggerInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

// PathItem represents a Swagger path item object.
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operation represents a Swagger operation object.
type Operation struct {
	Summary     string           `json:"summary"`
	Description string           `json:"description"`
	Parameters  []Parameter      `json:"parameters"`
	Security    []map[string]any `json:"security"`
	Responses   map[string]any   `json:"responses"`
}

// Parameter represents a Swagger parameter object.
type Parameter struct {
	Name             string `json:"name"`
	In               string `json:"in"`
	Description      string `json:"description"`
	Required         bool   `json:"required"`
	Type             string `json:"type,omitempty"`
	Items            any    `json:"items,omitempty"`
	Schema           any    `json:"schema,omitempty"`
	CollectionFormat string `json:"collectionFormat,omitempty"`
}

// buildSwaggerSpec constructs a Swagger 2.0 specification based on table definitions and RPC definitions.
// dbKey is the current database key.
func buildSwaggerSpec(r *http.Request, dbKey string, tableDefs, viewDefs, rpcDefs map[string]any) *SwaggerSpec {
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

	paths := make(map[string]*PathItem)

	for tableName, modelSchemaRaw := range mergedDefs {
		modelSchema, ok := modelSchemaRaw.(map[string]any)
		if !ok {
			continue
		}
		properties, _ := modelSchema["properties"].(map[string]any)
		pathItem := &PathItem{}

		// Determine if this table is public
		isPublicTable := slices.Contains(publicTables, tableName)

		getOp := buildGETEndpoint(tableName, properties)
		if isPublicTable {
			getOp.Security = []map[string]any{} // No security for public
		}
		pathItem.Get = getOp

		if _, ok := tableDefs[tableName]; ok {
			// Build additional endpoints (POST, PATCH, DELETE) only for tables.
			postOp := buildPOSTEndpoint(tableName)
			patchOp := buildPATCHEndpoint(tableName, properties)
			deleteOp := buildDELETEEndpoint(tableName, properties)
			if isPublicTable {
				postOp.Security = []map[string]any{}
				patchOp.Security = []map[string]any{}
				deleteOp.Security = []map[string]any{}
			}
			pathItem.Post = postOp
			pathItem.Patch = patchOp
			pathItem.Delete = deleteOp
		}
		paths["/"+tableName+"/"] = pathItem
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
		op := &Operation{
			Summary:     fmt.Sprintf("Call RPC function %s", funcName),
			Description: fmt.Sprintf("Invoke the RPC function %s", funcName),
			Parameters: []Parameter{
				{
					Name:        "body",
					In:          "body",
					Description: "RPC request payload",
					Required:    true,
					Schema:      reqSchema,
				},
			},
			Responses: map[string]any{
				"200": map[string]any{
					"description": "RPC response",
					"schema":      respSchema,
				},
			},
			Security: security,
		}
		paths[path] = &PathItem{Post: op}
	}

	swaggerDef := &SwaggerSpec{
		Swagger: "2.0",
		Info: SwaggerInfo{
			Title:   title,
			Version: easyrest.Version,
		},
		Host:        r.Host,
		BasePath:    "/api/" + dbKey,
		Schemes:     []string{"http"},
		Consumes:    []string{"application/json"},
		Produces:    []string{"application/json"},
		Definitions: mergedDefs,
		SecurityDefinitions: map[string]any{
			"jwtToken": jwtTokenSecurity,
		},
		Paths: make(map[string]any),
	}
	for k, v := range paths {
		swaggerDef.Paths[k] = v
	}

	return swaggerDef
}

// buildGETEndpoint constructs a GET operation map with query parameters for the given name and property set.
func buildGETEndpoint(name string, properties map[string]any) *Operation {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}

	getParams := buildSchemaParams(fieldNames, properties, true)
	return &Operation{
		Summary:     fmt.Sprintf("Get %s", name),
		Description: fmt.Sprintf("Retrieve rows from the %s", name),
		Parameters:  getParams,
		Responses: map[string]any{
			"200": map[string]any{
				"description": "Successful response",
				"schema": map[string]any{
					"type":  "array",
					"items": map[string]any{"$ref": "#/definitions/" + name},
				},
			},
		},
		Security: []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildGETParams creates the common query parameters (select, ordering, limit, offset)
// plus where-filters based on the field types.
func buildSchemaParams(fieldNames []string, properties map[string]any, isGet bool) []Parameter {
	var params []Parameter

	if isGet {
		orderingFieldNames := make([]string, 0)
		for _, fieldName := range fieldNames {
			orderingFieldNames = append(orderingFieldNames, fieldName)
			orderingFieldNames = append(orderingFieldNames, "-"+fieldName)
		}
		// Basic query parameters: select, ordering, limit, offset.
		params = append(params, []Parameter{
			{
				Name:             "select",
				In:               "query",
				Description:      "Comma-separated list of fields",
				Type:             "array",
				Items:            map[string]any{"type": "string", "enum": fieldNames},
				Required:         false,
				CollectionFormat: "csv",
			},
			{
				Name:             "ordering",
				In:               "query",
				Description:      "Comma-separated ordering fields",
				Type:             "array",
				Items:            map[string]any{"type": "string", "enum": orderingFieldNames},
				Required:         false,
				CollectionFormat: "csv",
			},
			{
				Name:        "limit",
				In:          "query",
				Description: "Maximum number of records to return",
				Type:        "integer",
				Required:    false,
			},
			{
				Name:        "offset",
				In:          "query",
				Description: "Number of records to skip",
				Type:        "integer",
				Required:    false,
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
			param := Parameter{
				Name:        fmt.Sprintf("where.%s.%s", op, fieldName),
				Description: fmt.Sprintf("Filter for field '%s' with operator %s", fieldName, op),
				In:          "query",
				Type:        paramType,
				Required:    false,
			}
			if op == "in" {
				param.CollectionFormat = "csv"
			}
			params = append(params, param)
		}
	}

	return params
}

// buildPOSTEndpoint returns a POST operation map for the given table name.
func buildPOSTEndpoint(name string) *Operation {
	return &Operation{
		Summary:     fmt.Sprintf("Create rows in %s", name),
		Description: fmt.Sprintf("Insert new rows into %s", name),
		Parameters: []Parameter{
			{
				Name:        "body",
				In:          "body",
				Description: fmt.Sprintf("Array of %s objects", name),
				Required:    true,
				Schema: map[string]any{
					"type":  "array",
					"items": map[string]any{"$ref": "#/definitions/" + name},
				},
			},
		},
		Responses: map[string]any{
			"201": map[string]any{
				"description": "Rows created",
			},
		},
		Security: []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildPATCHEndpoint returns a PATCH operation map for the given table name.
func buildPATCHEndpoint(name string, properties map[string]any) *Operation {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)
	return &Operation{
		Summary:     fmt.Sprintf("Update rows in %s", name),
		Description: fmt.Sprintf("Update existing rows in %s", name),
		Parameters: append(getParams, Parameter{
			Name:        "body",
			In:          "body",
			Description: fmt.Sprintf("Partial update of a %s object", name),
			Required:    true,
			Schema:      map[string]any{"$ref": "#/definitions/" + name},
		}),
		Responses: map[string]any{
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
		Security: []map[string]any{
			{"jwtToken": []string{}},
		},
	}
}

// buildDELETEEndpoint returns a DELETE operation map for the given table name.
func buildDELETEEndpoint(name string, properties map[string]any) *Operation {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)

	return &Operation{
		Summary:     fmt.Sprintf("Delete rows from %s", name),
		Description: fmt.Sprintf("Delete rows from %s", name),
		Parameters:  getParams,
		Responses: map[string]any{
			"204": map[string]any{
				"description": "Rows deleted",
			},
		},
		Security: []map[string]any{
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
