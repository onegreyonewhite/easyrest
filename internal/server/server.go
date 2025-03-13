package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type contextKey string

const TokenClaimsKey contextKey = "tokenClaims"

// Global configuration and dbPlugins loaded only once.
var (
	cfg        config.Config
	cfgOnce    sync.Once
	DbPlugins  = make(map[string]easyrest.DBPlugin)
	AllowedOps = map[string]string{
		"eq":    "=",
		"neq":   "!=",
		"lt":    "<",
		"lte":   "<=",
		"gt":    ">",
		"gte":   ">=",
		"like":  "LIKE",
		"ilike": "ILIKE",
		"is":    "IS",
		"in":    "IN",
	}
	allowedFuncs = [5]string{
		"count",
		"sum",
		"avg",
		"min",
		"max",
	}
)

// schemaCache caches GetSchema results per dbKey.
var (
	schemaCache      = make(map[string]interface{})
	schemaCacheMutex sync.RWMutex
)

// GetConfig loads configuration only once.
func GetConfig() config.Config {
	cfgOnce.Do(func() {
		cfg = config.Load()
	})
	return cfg
}

// SetConfig sets a new configuration.
func SetConfig(newConfig config.Config) {
	cfg = newConfig
}

// IsAllowedFunction checks if the provided function name is allowed.
func IsAllowedFunction(item string) bool {
	for _, v := range allowedFuncs {
		if v == item {
			return true
		}
	}
	return false
}

// escapeSQLLiteral escapes single quotes in SQL string literals.
func escapeSQLLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// getNestedValue traverses a nested map using dot-separated keys.
// If the full path is found, it returns the value and true; otherwise false.
func getNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = data
	for _, p := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[p]; exists {
				current = val
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}
	return current, true
}

// substitutePluginContext replaces values starting with "erctx." or "request."
// with the corresponding value from flatCtx or pluginCtx.
func substitutePluginContext(input string, flatCtx map[string]string, pluginCtx map[string]interface{}) string {
	if strings.HasPrefix(input, "erctx.") {
		key := input[len("erctx."):]
		normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if val, ok := flatCtx[normalizedKey]; ok {
			return val
		}
	} else if strings.HasPrefix(input, "request.") {
		key := input[len("request."):]
		if v, ok := getNestedValue(pluginCtx, key); ok {
			rv := reflect.ValueOf(v)
			switch rv.Kind() {
			case reflect.Map, reflect.Slice, reflect.Array:
				if bytes, err := json.Marshal(v); err == nil {
					return string(bytes)
				}
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return input
}

// substituteValue recursively substitutes string values in arbitrary data structures.
func substituteValue(val interface{}, flatCtx map[string]string, pluginCtx map[string]interface{}) interface{} {
	switch s := val.(type) {
	case string:
		if strings.HasPrefix(s, "erctx.") || strings.HasPrefix(s, "request.") {
			return substitutePluginContext(s, flatCtx, pluginCtx)
		}
		return s
	case map[string]interface{}:
		for k, v := range s {
			s[k] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	case []interface{}:
		for i, v := range s {
			s[i] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	default:
		return val
	}
}

// processSelectParam parses the "select" query parameter, performs context substitution,
// and assigns an alias (defaulting to the field name with dots replaced by underscores) if not provided.
func processSelectParam(param string, flatCtx map[string]string, pluginCtx map[string]interface{}) ([]string, []string, error) {
	if param == "" {
		return nil, nil, nil
	}
	parts := strings.Split(param, ",")
	var selectFields []string
	var groupBy []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var alias, raw string
		if strings.Contains(part, ":") {
			subParts := strings.SplitN(part, ":", 2)
			alias = strings.TrimSpace(subParts[0])
			raw = strings.TrimSpace(subParts[1])
		} else {
			alias = ""
			raw = part
		}
		var expr string
		if strings.Contains(raw, ".") && strings.HasSuffix(raw, "()") {
			// Process function syntax like "amount.sum()"
			subParts := strings.SplitN(raw, ".", 2)
			fieldPart := strings.TrimSpace(subParts[0])
			funcPart := strings.TrimSpace(subParts[1])
			if len(funcPart) < 3 || funcPart[len(funcPart)-2:] != "()" {
				return nil, nil, fmt.Errorf("Invalid function syntax in select field: %s", part)
			}
			funcName := funcPart[:len(funcPart)-2]
			if !IsAllowedFunction(funcName) {
				return nil, nil, fmt.Errorf("Function %s is not allowed", funcName)
			}
			if funcName == "count" && fieldPart == "" {
				expr = "COUNT(*)"
			} else {
				expr = strings.ToUpper(funcName) + "(" + fieldPart + ")"
			}
			if alias == "" {
				alias = funcName
			}
			// Append alias so that the SQL query becomes, for example, "SUM(amount) AS sum"
			expr = expr + " AS " + alias
		} else if raw == "count()" {
			expr = "COUNT(*)"
			if alias == "" {
				alias = "count"
			}
			expr = expr + " AS " + alias
		} else {
			// For plain fields - if the value is contextual, substitute it as a literal
			if strings.HasPrefix(raw, "erctx.") || strings.HasPrefix(raw, "request.") {
				substituted := substitutePluginContext(raw, flatCtx, pluginCtx)
				if alias == "" {
					alias = strings.ReplaceAll(raw, ".", "_")
				}
				expr = fmt.Sprintf("'%s' AS %s", escapeSQLLiteral(substituted), alias)
			} else {
				expr = raw
				if alias != "" {
					expr = expr + " AS " + alias
				}
				groupBy = append(groupBy, raw)
			}
		}
		selectFields = append(selectFields, expr)
	}
	return selectFields, groupBy, nil
}

// ParseWhereClause converts query parameters starting with "where." into a map,
// performing context substitution for values.
func ParseWhereClause(values map[string][]string, flatCtx map[string]string, pluginCtx map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for key, vals := range values {
		if strings.HasPrefix(key, "where.") {
			parts := strings.Split(key, ".")
			if len(parts) != 3 {
				return nil, fmt.Errorf("Invalid where key format: %s", key)
			}
			opCode := strings.ToLower(parts[1])
			field := parts[2]

			if _, ok := AllowedOps[opCode]; !ok {
				return nil, fmt.Errorf("Unknown operator: %s", opCode)
			}
			op := AllowedOps[opCode]

			substituted := ""
			if op == "IN" {
				val_arr := strings.Split(vals[0], ",")
				for idx, v := range val_arr {
					val_arr[idx] = substitutePluginContext(v, flatCtx, pluginCtx)
				}
				substituted = strings.Join(val_arr, ",")
			} else {
				substituted = substitutePluginContext(vals[0], flatCtx, pluginCtx)
			}

			if existing, found := result[field]; found {
				m, ok := existing.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("Type error for field %s", field)
				}
				m[op] = substituted
				result[field] = m
			} else {
				result[field] = map[string]interface{}{op: substituted}
			}
		}
	}
	return result, nil
}

// BuildPluginContext extracts context variables from the HTTP request.
func BuildPluginContext(r *http.Request) map[string]interface{} {
	cfg := GetConfig()
	headers := make(map[string]interface{})
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		headers[lk] = strings.Join(vals, " ")
	}
	claims := getTokenClaims(r)
	plainClaims := make(map[string]interface{})
	for k, v := range claims {
		plainClaims[strings.ToLower(k)] = v
	}

	timezone := ""
	prefer := make(map[string]interface{})
	if preferStr := r.Header.Get("Prefer"); preferStr != "" {
		tokens := strings.Split(preferStr, " ")
		for _, token := range tokens {
			parts := strings.SplitN(token, "=", 2)
			key := strings.ToLower(parts[0])
			val := parts[1]
			if key == "timezone" {
				timezone = val
			}
			prefer[key] = val
		}
	}
	if timezone == "" {
		timezone = cfg.DefaultTimezone
	}

	return map[string]interface{}{
		"timezone":   timezone,
		"headers":    headers,
		"claims":     plainClaims,
		"jwt.claims": plainClaims,
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"prefer":     prefer,
	}
}

// AccessLogMiddleware logs incoming HTTP requests if enabled.
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		stdlog.Printf("ACCESS: %s %s from %s in %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

// updateSwaggerSpecWithRPC adds paths for RPC functions based on rpcDefinitions.
func updateSwaggerSpecWithRPC(swaggerSpec map[string]interface{}, rpcDefinitions map[string]interface{}) {
	paths, ok := swaggerSpec["paths"].(map[string]interface{})
	if !ok {
		paths = make(map[string]interface{})
		swaggerSpec["paths"] = paths
	}
	for funcName, def := range rpcDefinitions {
		arr, ok := def.([]interface{})
		if !ok || len(arr) != 2 {
			continue
		}
		reqSchema := arr[0]
		respSchema := arr[1]
		path := "/rpc/" + funcName + "/"
		op := map[string]interface{}{
			"summary":     fmt.Sprintf("Call RPC function %s", funcName),
			"description": fmt.Sprintf("Invoke the RPC function %s", funcName),
			"parameters": []interface{}{
				map[string]interface{}{
					"name":        "body",
					"in":          "body",
					"description": "RPC request payload",
					"required":    true,
					"schema":      reqSchema,
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "RPC response",
					"schema":      respSchema,
				},
			},
			"security": []map[string]interface{}{
				{"jwtToken": []string{}},
			},
		}
		paths[path] = map[string]interface{}{
			"post": op,
		}
	}
}

// buildSwaggerSpec constructs a Swagger 2.0 specification based on table definitions and RPC definitions.
// dbKey is the current database key.
func buildSwaggerSpec(r *http.Request, dbKey string, tableDefs, viewDefs, rpcDefs map[string]interface{}) map[string]interface{} {
	cfg := GetConfig()

	// Merge tables and views into one definitions map.
	mergedDefs := make(map[string]interface{})
	for k, v := range tableDefs {
		mergedDefs[k] = v
	}
	for k, v := range viewDefs {
		mergedDefs[k] = v
	}

	jwtTokenSecurity := make(map[string]interface{})
	if cfg.TokenURL != "" {
		jwtTokenSecurity = map[string]interface{}{
			"type":     "oauth2",
			"flow":     cfg.AuthFlow,
			"tokenUrl": cfg.TokenURL,
			"scopes":   map[string]interface{}{},
		}
	} else {
		jwtTokenSecurity = map[string]interface{}{
			"type":        "apiKey",
			"name":        "Authorization",
			"in":          "header",
			"description": "Enter token in format 'Bearer {token}'",
		}
	}

	swaggerDef := map[string]interface{}{
		"swagger": "2.0",
		"info": map[string]interface{}{
			"title":   "EasyRest API",
			"version": easyrest.Version,
		},
		"host":        r.Host,
		"basePath":    "/api/" + dbKey,
		"schemes":     []string{"http"},
		"consumes":    []string{"application/json"},
		"produces":    []string{"application/json"},
		"definitions": mergedDefs,
		"securityDefinitions": map[string]interface{}{
			"jwtToken": jwtTokenSecurity,
		},
		"paths": map[string]interface{}{},
	}
	paths := swaggerDef["paths"].(map[string]interface{})

	for tableName, modelSchemaRaw := range mergedDefs {
		modelSchema, ok := modelSchemaRaw.(map[string]interface{})
		if !ok {
			continue
		}
		properties, _ := modelSchema["properties"].(map[string]interface{})
		pathObject := make(map[string]interface{})
		pathObject["get"] = buildGETEndpoint(tableName, properties)

		if _, ok := tableDefs[tableName]; ok {
			// Build additional endpoints (POST, PATCH, DELETE)
			// only for tables.
			pathObject["post"] = buildPOSTEndpoint(tableName)
			pathObject["patch"] = buildPATCHEndpoint(tableName, properties)
			pathObject["delete"] = buildDELETEEndpoint(tableName, properties)
		}
		paths["/"+tableName+"/"] = pathObject
	}

	// If RPC definitions exist, add them to the swaggerSpec.
	if rpcDefs != nil {
		updateSwaggerSpecWithRPC(swaggerDef, rpcDefs)
	}

	return swaggerDef
}

// buildGETEndpoint constructs a GET operation map with query parameters for the given name and property set.
func buildGETEndpoint(name string, properties map[string]interface{}) map[string]interface{} {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}

	getParams := buildSchemaParams(fieldNames, properties, true)
	return map[string]interface{}{
		"summary":     fmt.Sprintf("Get %s", name),
		"description": fmt.Sprintf("Retrieve rows from the %s", name),
		"parameters":  getParams,
		"responses": map[string]interface{}{
			"200": map[string]interface{}{
				"description": "Successful response",
				"schema": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"$ref": "#/definitions/" + name},
				},
			},
		},
		"security": []map[string]interface{}{
			{"jwtToken": []string{}},
		},
	}
}

// buildGETParams creates the common query parameters (select, ordering, limit, offset)
// plus where-filters based on the field types.
func buildSchemaParams(fieldNames []string, properties map[string]interface{}, isGet bool) []map[string]interface{} {
	var params []map[string]interface{}

	if isGet {
		// Basic query parameters: select, ordering, limit, offset.
		params = append(params, []map[string]interface{}{
			{
				"name":             "select",
				"in":               "query",
				"description":      "Comma-separated list of fields",
				"type":             "string",
				"required":         false,
				"enum":             fieldNames,
				"collectionFormat": "csv",
			},
			{
				"name":             "ordering",
				"in":               "query",
				"description":      "Comma-separated ordering fields",
				"type":             "string",
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
		prop, _ := properties[fieldName].(map[string]interface{})
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
			param := make(map[string]interface{})
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
func buildPOSTEndpoint(name string) map[string]interface{} {
	return map[string]interface{}{
		"summary":     fmt.Sprintf("Create rows in %s", name),
		"description": fmt.Sprintf("Insert new rows into %s", name),
		"parameters": []map[string]interface{}{
			{
				"name":        "body",
				"in":          "body",
				"description": fmt.Sprintf("Array of %s objects", name),
				"required":    true,
				"schema": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"$ref": "#/definitions/" + name},
				},
			},
		},
		"responses": map[string]interface{}{
			"201": map[string]interface{}{
				"description": "Rows created",
			},
		},
		"security": []map[string]interface{}{
			{"jwtToken": []string{}},
		},
	}
}

// buildPATCHEndpoint returns a PATCH operation map for the given table name.
func buildPATCHEndpoint(name string, properties map[string]interface{}) map[string]interface{} {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)
	return map[string]interface{}{
		"summary":     fmt.Sprintf("Update rows in %s", name),
		"description": fmt.Sprintf("Update existing rows in %s", name),
		"parameters": append(getParams, map[string]interface{}{
			"name":        "body",
			"in":          "body",
			"description": fmt.Sprintf("Partial update of a %s object", name),
			"required":    true,
			"schema":      map[string]interface{}{"$ref": "#/definitions/" + name},
		}),
		"responses": map[string]interface{}{
			"200": map[string]interface{}{
				"description": "Rows updated",
				"schema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"updated": map[string]interface{}{"type": "integer"},
					},
				},
			},
		},
		"security": []map[string]interface{}{
			{"jwtToken": []string{}},
		},
	}
}

// buildDELETEEndpoint returns a DELETE operation map for the given table name.
func buildDELETEEndpoint(name string, properties map[string]interface{}) map[string]interface{} {
	var fieldNames []string

	for fieldName := range properties {
		fieldNames = append(fieldNames, fieldName)
	}
	getParams := buildSchemaParams(fieldNames, properties, false)

	return map[string]interface{}{
		"summary":     fmt.Sprintf("Delete rows from %s", name),
		"description": fmt.Sprintf("Delete rows from %s", name),
		"parameters":  getParams,
		"responses": map[string]interface{}{
			"204": map[string]interface{}{
				"description": "Rows deleted",
			},
		},
		"security": []map[string]interface{}{
			{"jwtToken": []string{}},
		},
	}
}

// schemaHandler now builds and returns a full swagger 2.0 spec.
func schemaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	dbPlug, ok := DbPlugins[dbKey]
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
		schemaMap, ok := schemaRaw.(map[string]interface{})
		if !ok {
			http.Error(w, "Invalid schema format", http.StatusInternalServerError)
			return
		}
		tableDefs, ok := schemaMap["tables"].(map[string]interface{})
		if !ok {
			http.Error(w, "Invalid tables schema", http.StatusInternalServerError)
			return
		}
		var viewDefs map[string]interface{}
		if raw, exists := schemaMap["views"]; exists && raw != nil {
			if m, ok := raw.(map[string]interface{}); ok {
				viewDefs = m
			}
		}
		var rpcDefs map[string]interface{}
		if raw, exists := schemaMap["rpc"]; exists && raw != nil {
			if m, ok := raw.(map[string]interface{}); ok {
				rpcDefs = m
			}
		}
		schemaCacheMutex.Lock()
		swaggerSpec = buildSwaggerSpec(r, dbKey, tableDefs, viewDefs, rpcDefs)
		schemaCacheMutex.Unlock()
	}

	respondJSON(w, http.StatusOK, swaggerSpec)
}

// tableHandler processes CRUD operations on tables.
func tableHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	table := vars["table"]

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
	var requiredScope string
	if r.Method == http.MethodGet {
		requiredScope = table + "-read"
	} else {
		requiredScope = table + "-write"
	}
	if config.CheckScope {
		claims := getTokenClaims(r)
		if !CheckScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	pluginCtx := BuildPluginContext(r)
	flatCtx, err := easyrest.FormatToContext(pluginCtx)
	if err != nil {
		http.Error(w, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		selectParam := r.URL.Query().Get("select")
		selectFields, groupBy, err := processSelectParam(selectParam, flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing select parameter: "+err.Error(), http.StatusBadRequest)
			return
		}
		where, err := ParseWhereClause(r.URL.Query(), flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		ordering := ParseCSV(r.URL.Query().Get("ordering"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

		rows, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusOK, rows)
	case http.MethodPost:
		var data []map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		for i, row := range data {
			data[i] = substituteValue(row, flatCtx, pluginCtx).(map[string]interface{})
		}
		rows, err := dbPlug.TableCreate(userID, table, data, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableCreate: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusCreated, rows)
	case http.MethodPatch:
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "JSON parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		data = substituteValue(data, flatCtx, pluginCtx).(map[string]interface{})
		where, err := ParseWhereClause(r.URL.Query(), flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		updated, err := dbPlug.TableUpdate(userID, table, data, where, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableUpdate: "+err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, http.StatusOK, map[string]int{"updated": updated})
	case http.MethodDelete:
		where, err := ParseWhereClause(r.URL.Query(), flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, err = dbPlug.TableDelete(userID, table, where, pluginCtx)
		if err != nil {
			http.Error(w, "Error in TableDelete: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	var data map[string]interface{}
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
	data = substituteValue(data, flatCtx, pluginCtx).(map[string]interface{})
	result, err := dbPlug.CallFunction(userID, funcName, data, pluginCtx)
	if err != nil {
		http.Error(w, "Error in CallFunction: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, result)
}

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

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Authenticate extracts and validates the JWT token.
func Authenticate(r *http.Request) (string, *http.Request, error) {
	tokenStr := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		return "", r, errors.New("missing bearer token")
	}

	config := GetConfig()
	if config.TokenSecret != "" {
		parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.TokenSecret), nil
		})
		if err != nil || !parsed.Valid {
			return "", r, errors.New("invalid token")
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			return "", r, errors.New("invalid claims")
		}
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return "", r, errors.New("token expired")
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
		return extractUserIDFromClaims(claims), r, nil
	}

	tokenURL := os.Getenv("ER_TOKEN_URL")
	if tokenURL != "" {
		resp, err := http.Get(tokenURL + "?access_token=" + tokenStr)
		if err != nil || resp.StatusCode != http.StatusOK {
			return "", r, errors.New("invalid token (via URL)")
		}
		var authResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
			return "", r, errors.New("invalid response from auth server")
		}
		resp.Body.Close()
		r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, jwt.MapClaims(authResponse)))
		return extractUserIDFromClaims(jwt.MapClaims(authResponse)), r, nil
	}
	claims, err := DecodeTokenWithoutValidation(tokenStr)
	if err != nil {
		return "", r, err
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return "", r, errors.New("token expired")
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, claims))
	return extractUserIDFromClaims(claims), r, nil
}

func getTokenClaims(r *http.Request) jwt.MapClaims {
	if claims, ok := r.Context().Value(TokenClaimsKey).(jwt.MapClaims); ok {
		return claims
	}
	return nil
}

func extractUserIDFromClaims(claims jwt.MapClaims) string {
	config := GetConfig()
	searchPath := config.TokenUserSearch
	if val, ok := claims[searchPath]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// DecodeTokenWithoutValidation decodes a JWT token without validating its signature.
func DecodeTokenWithoutValidation(tokenStr string) (jwt.MapClaims, error) {
	firstDot := strings.Index(tokenStr, ".")
	if firstDot < 0 {
		return nil, errors.New("invalid token format")
	}
	secondDot := strings.Index(tokenStr[firstDot+1:], ".")
	if secondDot < 0 {
		return nil, errors.New("invalid token format")
	}
	payload := tokenStr[firstDot+1 : firstDot+1+secondDot]
	decoder := base64.URLEncoding.WithPadding(base64.NoPadding)
	decoded, err := decoder.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	err = json.Unmarshal(decoded, &claims)
	return jwt.MapClaims(claims), err
}

func CheckScope(claims jwt.MapClaims, required string) bool {
	scopeVal, ok := claims["scope"]
	if !ok {
		return false
	}
	scopesStr, ok := scopeVal.(string)
	if !ok {
		return false
	}
	scopes := strings.Fields(scopesStr)
	for _, s := range scopes {
		if s == required {
			return true
		}
		if (strings.HasSuffix(required, "read") && s == "read") ||
			(strings.HasSuffix(required, "write") && s == "write") {
			return true
		}
	}
	return false
}

// SetupRouter initializes the router and endpoints.
func SetupRouter() *mux.Router {
	LoadDBPlugins()
	r := mux.NewRouter()
	// Schema endpoint.
	r.HandleFunc("/api/{db}/", schemaHandler).Methods("GET")
	r.HandleFunc("/api/{db}/rpc/{func}/", rpcHandler).Methods("POST")
	r.HandleFunc("/api/{db}/{table}/", tableHandler)
	return r
}

// Run starts the HTTP server.
func Run() {
	config := GetConfig()
	router := SetupRouter()
	if config.AccessLogOn {
		router.Use(AccessLogMiddleware)
	}
	stdlog.Printf("Server listening on port %s...", config.Port)
	srv := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	stdlog.Fatal(srv.ListenAndServe())
}

// LoadDBPlugins scans environment variables and initializes plugins.
func LoadDBPlugins() {
	config := GetConfig()
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ER_DB_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			envName := parts[0]
			uri := parts[1]
			connName := strings.ToLower(strings.TrimPrefix(envName, "ER_DB_"))
			splitURI := strings.SplitN(uri, "://", 2)
			if len(splitURI) != 2 {
				stdlog.Printf("Invalid URI for %s: %s", connName, uri)
				continue
			}
			pluginType := splitURI[0]
			pluginExec := "easyrest-plugin-" + pluginType
			pluginPath, err := exec.LookPath(pluginExec)
			if err != nil {
				stdlog.Printf("Plugin %s not found: %v", pluginExec, err)
				continue
			}
			absPluginPath, err := filepath.Abs(pluginPath)
			if err != nil {
				stdlog.Printf("Error getting absolute path for plugin %s: %v", pluginExec, err)
				continue
			}
			pluginConfig := hplugin.ClientConfig{
				HandshakeConfig: easyrest.Handshake,
				Plugins: map[string]hplugin.Plugin{
					"db": &easyrest.DBPluginPlugin{},
				},
				Cmd:              exec.Command(absPluginPath),
				AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolNetRPC},
			}
			if config.NoPluginLog {
				pluginConfig.Logger = hclog.New(&hclog.LoggerOptions{
					Output: io.Discard,
					Level:  hclog.Error,
					Name:   "plugin",
				})
			}
			client := hplugin.NewClient(&pluginConfig)
			rpcClient, err := client.Client()
			if err != nil {
				stdlog.Printf("Error starting plugin %s: %v", pluginExec, err)
				continue
			}
			raw, err := rpcClient.Dispense("db")
			if err != nil {
				stdlog.Printf("Error obtaining plugin %s: %v", pluginExec, err)
				continue
			}
			dbPlug, ok := raw.(easyrest.DBPlugin)
			if !ok {
				stdlog.Printf("Invalid plugin type for %s", pluginExec)
				continue
			}
			err = dbPlug.InitConnection(uri)
			if err != nil {
				stdlog.Printf("Error initializing connection for plugin %s: %v", connName, err)
				continue
			}
			DbPlugins[connName] = dbPlug
			stdlog.Printf("Connection %s initialized using plugin %s", connName, pluginExec)
		}
	}
}
