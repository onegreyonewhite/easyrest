package server

import (
	"fmt"
	"net/http"
	"strings"

	"slices"

	"maps"

	"github.com/go-chi/chi/v5"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// openAPISpec is the OpenAPI 3.0.3 document served at GET /api/{db}/.
// Servers is filled per request from the cached document.
type openAPISpec struct {
	OpenAPI    string            `json:"openapi"`
	Info       SwaggerInfo       `json:"info"`
	Servers    []openAPIServer   `json:"servers,omitempty"`
	Paths      map[string]any    `json:"paths"`
	Components openAPIComponents `json:"components"`
}

type SwaggerInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type openAPIServer struct {
	URL string `json:"url"`
}

type openAPIComponents struct {
	Schemas         map[string]any `json:"schemas"`
	SecuritySchemes map[string]any `json:"securitySchemes"`
}

// PathItem represents one OpenAPI path item.
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

// Operation represents one OpenAPI operation.
type Operation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *openAPIRequestBody `json:"requestBody,omitempty"`
	Security    []map[string]any    `json:"security"`
	Responses   map[string]any      `json:"responses"`
}

type openAPIRequestBody struct {
	Description string         `json:"description,omitempty"`
	Required    bool           `json:"required,omitempty"`
	Content     map[string]any `json:"content"`
}

// Parameter is an OpenAPI 3 query, header, or path parameter.
// Explode is a pointer so false is written for comma-separated arrays.
type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Schema      any    `json:"schema,omitempty"`
	Example     string `json:"example,omitempty"`
	Style       string `json:"style,omitempty"`
	Explode     *bool  `json:"explode,omitempty"`
}

// buildSwaggerSpec constructs an OpenAPI 3.0.3 document for one database key.
// The cached document has no servers. The caller stamps the request URL.
func buildSwaggerSpec(dbKey string, tableDefs, viewDefs, rpcDefs map[string]any) *openAPISpec {
	cfg := GetConfig()
	pluginCfg, hasPluginCfg := cfg.PluginMap[dbKey]

	mergedDefs := make(map[string]any)
	maps.Copy(mergedDefs, tableDefs)
	maps.Copy(mergedDefs, viewDefs)

	if hasPluginCfg {
		for k := range mergedDefs {
			if slices.Contains(pluginCfg.Exclude.Table, k) {
				delete(mergedDefs, k)
				continue
			}
			if len(pluginCfg.AllowList.Table) > 0 && !slices.Contains(pluginCfg.AllowList.Table, k) {
				delete(mergedDefs, k)
			}
		}
	}

	currentAuthSecDefs := *AuthSecurityDefinitions.Load()
	schemeNames := make([]string, 0, len(currentAuthSecDefs))
	for name := range currentAuthSecDefs {
		schemeNames = append(schemeNames, name)
	}
	slices.Sort(schemeNames)

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
		isPublicTable := slices.Contains(publicTables, tableName)

		getOp := buildGETEndpoint(tableName, properties)
		getOp.Security = buildOperationSecurity(isPublicTable, currentAuthSecDefs)
		pathItem.Get = getOp

		if _, ok := tableDefs[tableName]; ok {
			postOp := buildPOSTEndpoint(tableName)
			patchOp := buildPATCHEndpoint(tableName, properties)
			deleteOp := buildDELETEEndpoint(tableName, properties)
			postOp.Security = buildOperationSecurity(isPublicTable, currentAuthSecDefs)
			patchOp.Security = buildOperationSecurity(isPublicTable, currentAuthSecDefs)
			deleteOp.Security = buildOperationSecurity(isPublicTable, currentAuthSecDefs)
			pathItem.Post = postOp
			pathItem.Patch = patchOp
			pathItem.Delete = deleteOp
		}
		paths["/"+tableName+"/"] = pathItem
	}

	for funcName, def := range rpcDefs {
		arr, ok := def.([]any)
		if !ok || len(arr) != 2 {
			continue
		}
		if hasPluginCfg {
			if slices.Contains(pluginCfg.Exclude.Func, funcName) {
				continue
			}
			if len(pluginCfg.AllowList.Func) > 0 && !slices.Contains(pluginCfg.AllowList.Func, funcName) {
				continue
			}
		}
		reqSchema := arr[0]
		respSchema := arr[1]
		path := "/rpc/" + funcName + "/"
		isPublicFunc := slices.Contains(publicFuncs, funcName)
		security := buildOperationSecurity(isPublicFunc, currentAuthSecDefs)
		paths[path] = &PathItem{Post: &Operation{
			Summary:     fmt.Sprintf("Call RPC function %s", funcName),
			Description: fmt.Sprintf("Invoke the RPC function %s", funcName),
			Parameters:  []Parameter{preferParameter()},
			RequestBody: &openAPIRequestBody{
				Description: "RPC request payload",
				Required:    true,
				Content:     openAPIContent(reqSchema, easyrest.MediaTypeJSON),
			},
			Responses: map[string]any{
				"200": withPreferenceApplied(openAPIResponse("RPC response", respSchema, easyrest.MediaTypeJSON, easyrest.MediaTypeNDJSON)),
			},
			Security: security,
		}}
	}

	spec := &openAPISpec{
		OpenAPI: "3.0.3",
		Info: SwaggerInfo{
			Title:   title,
			Version: easyrest.Version,
		},
		Paths: make(map[string]any),
		Components: openAPIComponents{
			Schemas:         mergedDefs,
			SecuritySchemes: openAPISecuritySchemes(currentAuthSecDefs, schemeNames),
		},
	}
	for k, v := range paths {
		spec.Paths[k] = v
	}
	return spec
}

// buildOperationSecurity lists every loaded scheme, sorted by name.
// A public table or function gets an empty security array.
func buildOperationSecurity(isPublic bool, authSecurityDefinitions map[string]map[string]any) []map[string]any {
	if isPublic {
		return []map[string]any{}
	}
	names := make([]string, 0, len(authSecurityDefinitions))
	for key := range authSecurityDefinitions {
		names = append(names, key)
	}
	slices.Sort(names)
	securityRequirements := make([]map[string]any, 0, len(names))
	for _, key := range names {
		securityRequirements = append(securityRequirements, map[string]any{key: []string{}})
	}
	return securityRequirements
}

func schemaFieldNames(properties map[string]any) []string {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func formArrayParam(name, description string, items map[string]any) Parameter {
	explode := false
	return Parameter{
		Name:        name,
		In:          "query",
		Description: description,
		Style:       "form",
		Explode:     &explode,
		Schema: map[string]any{
			"type":  "array",
			"items": items,
		},
	}
}

// buildGETEndpoint constructs a GET operation for one table or view.
func buildGETEndpoint(name string, properties map[string]any) *Operation {
	schema := map[string]any{
		"type":  "array",
		"items": map[string]any{"$ref": "#/components/schemas/" + name},
	}
	return &Operation{
		Summary:     fmt.Sprintf("Get %s", name),
		Description: fmt.Sprintf("Retrieve rows from the %s", name),
		Parameters:  append(buildSchemaParams(properties, true), preferParameter()),
		Responses: map[string]any{
			"200": withPreferenceApplied(openAPIResponse("Successful response", schema, easyrest.MediaTypeJSON, easyrest.MediaTypeNDJSON)),
		},
	}
}

// buildSchemaParams creates select, ordering, limit, and offset for GET,
// plus where-filters for every field. Field names are sorted once.
func buildSchemaParams(properties map[string]any, isGet bool) []Parameter {
	fieldNames := schemaFieldNames(properties)
	var params []Parameter

	if isGet {
		orderingFieldNames := make([]string, 0, len(fieldNames)*2)
		for _, fieldName := range fieldNames {
			orderingFieldNames = append(orderingFieldNames, fieldName, "-"+fieldName)
		}
		params = append(params,
			formArrayParam("select", "Comma-separated list of fields", map[string]any{"type": "string", "enum": fieldNames}),
			formArrayParam("ordering", "Comma-separated ordering fields", map[string]any{"type": "string", "enum": orderingFieldNames}),
			Parameter{
				Name:        "limit",
				In:          "query",
				Description: "Maximum number of records to return",
				Schema:      map[string]any{"type": "integer"},
			},
			Parameter{
				Name:        "offset",
				In:          "query",
				Description: "Number of records to skip",
				Schema:      map[string]any{"type": "integer"},
			},
		)
	}

	for _, fieldName := range fieldNames {
		prop, _ := properties[fieldName].(map[string]any)
		paramType := "string"
		if propType, exists := prop["type"].(string); exists {
			paramType = propType
		}
		for op := range AllowedOps {
			if paramType == "string" && (op == "lt" || op == "lte" || op == "gt" || op == "gte") {
				continue
			}
			if (paramType == "integer" || paramType == "number") && (op == "like" || op == "ilike") {
				continue
			}
			param := Parameter{
				Name:        fmt.Sprintf("where.%s.%s", op, fieldName),
				Description: fmt.Sprintf("Filter for field '%s' with operator %s", fieldName, op),
				In:          "query",
				Schema:      map[string]any{"type": paramType},
			}
			if op == "in" {
				explode := false
				param.Style = "form"
				param.Explode = &explode
				param.Schema = map[string]any{
					"type":  "array",
					"items": map[string]any{"type": paramType},
				}
			}
			params = append(params, param)
		}
	}
	return params
}

func buildPOSTEndpoint(name string) *Operation {
	return &Operation{
		Summary:     fmt.Sprintf("Create rows in %s", name),
		Description: fmt.Sprintf("Insert new rows into %s", name),
		Parameters:  []Parameter{preferParameter()},
		RequestBody: &openAPIRequestBody{
			Description: fmt.Sprintf("Array of %s objects", name),
			Required:    true,
			Content: openAPIContent(map[string]any{
				"type":  "array",
				"items": map[string]any{"$ref": "#/components/schemas/" + name},
			}, easyrest.MediaTypeJSON),
		},
		Responses: map[string]any{
			"201": withPreferenceApplied(map[string]any{"description": "Rows created"}),
		},
	}
}

func buildPATCHEndpoint(name string, properties map[string]any) *Operation {
	updated := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"updated": map[string]any{"type": "integer"},
		},
	}
	return &Operation{
		Summary:     fmt.Sprintf("Update rows in %s", name),
		Description: fmt.Sprintf("Update existing rows in %s", name),
		Parameters:  append(buildSchemaParams(properties, false), preferParameter()),
		RequestBody: &openAPIRequestBody{
			Description: fmt.Sprintf("Partial update of a %s object", name),
			Required:    true,
			Content:     openAPIContent(map[string]any{"$ref": "#/components/schemas/" + name}, easyrest.MediaTypeJSON),
		},
		Responses: map[string]any{
			"200": withPreferenceApplied(openAPIResponse("Rows updated", updated, easyrest.MediaTypeJSON, easyrest.MediaTypeNDJSON)),
		},
	}
}

func buildDELETEEndpoint(name string, properties map[string]any) *Operation {
	return &Operation{
		Summary:     fmt.Sprintf("Delete rows from %s", name),
		Description: fmt.Sprintf("Delete rows from %s", name),
		Parameters:  append(buildSchemaParams(properties, false), preferParameter()),
		Responses: map[string]any{
			"204": withPreferenceApplied(map[string]any{"description": "Rows deleted"}),
		},
	}
}

// schemaHandler returns the OpenAPI 3.0.3 document for one database.
func schemaHandler(w http.ResponseWriter, r *http.Request) {
	dbKey := strings.ToLower(chi.URLParam(r, "db"))
	if denyInternalDB(w, r, dbKey) {
		return
	}
	swaggerSpec, pluginCtx, built, ok := ensureSwaggerSpec(w, r, dbKey)
	if !ok {
		return
	}
	names := defaultDocumentNames()
	format := firstDocumentFormat(names)
	writeSwagger(
		w,
		r,
		dbKey,
		pluginCtx,
		names,
		built,
		swaggerSpec,
		swaggerPageCtx(r, easyrest.SwaggerDocument, absoluteFormatURL(r, format)),
	)
}

func ensureSwaggerSpec(w http.ResponseWriter, r *http.Request, dbKey string) (any, map[string]any, bool, bool) {
	schemaCacheMutex.RLock()
	swaggerSpec, ok := schemaCache[dbKey]
	schemaCacheMutex.RUnlock()
	if ok {
		return stampedOpenAPI(swaggerSpec, r, dbKey), nil, false, true
	}

	dbPlug, ok := loadDBPlugin(w, dbKey)
	if !ok {
		return nil, nil, false, false
	}

	pluginCtx := buildPluginContext(r, dbKey, "", "")
	pluginCtx, mwOK := runPreRequestMiddlewares(w, dbKey, pluginCtx)
	if !mwOK {
		return nil, nil, false, false
	}
	schemaRaw, returnedCtx, err := dbPlug.GetSchema(pluginCtx)
	pluginCtx = applyReturnedPluginContext(pluginCtx, returnedCtx)
	if err != nil {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "GetSchema not implemented", http.StatusNotImplemented)
		return nil, nil, false, false
	}
	schemaMap, ok := schemaRaw.(map[string]any)
	if !ok {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Invalid schema format", http.StatusInternalServerError)
		return nil, nil, false, false
	}
	tableDefs, ok := schemaMap["tables"].(map[string]any)
	if !ok {
		middlewareHTTPError(w, r, dbKey, pluginCtx, "Invalid tables schema", http.StatusInternalServerError)
		return nil, nil, false, false
	}
	delete(tableDefs, "easyrest_cache")
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
	if cached, found := schemaCache[dbKey]; found {
		swaggerSpec = cached
	} else {
		swaggerSpec = buildSwaggerSpec(dbKey, tableDefs, viewDefs, rpcDefs)
		schemaCache[dbKey] = swaggerSpec
	}
	schemaCacheMutex.Unlock()
	return stampedOpenAPI(swaggerSpec, r, dbKey), pluginCtx, true, true
}

func stampedOpenAPI(spec any, r *http.Request, dbKey string) any {
	doc, ok := spec.(*openAPISpec)
	if !ok || doc == nil {
		return spec
	}
	out := *doc
	out.Servers = []openAPIServer{{
		URL: easyrest.BuildAbsoluteUri(BuildPluginContext(r), "/api/"+dbKey),
	}}
	return &out
}
