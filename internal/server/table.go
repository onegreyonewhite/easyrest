package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"slices"

	"github.com/gorilla/mux"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// processSelectParam parses the "select" query parameter, performs context substitution,
// and assigns an alias (defaulting to the field name with dots replaced by underscores) if not provided.
func processSelectParam(param string, flatCtx map[string]string, pluginCtx map[string]any) ([]string, []string, error) {
	if param == "" {
		return nil, nil, nil
	}
	parts := strings.Split(param, ",")
	// Preallocate with a reasonable initial capacity.
	selectFields := make([]string, 0, len(parts))
	groupBy := make([]string, 0, len(parts))
	var exprBuilder strings.Builder

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

		exprBuilder.Reset() // Reset builder for each part

		if strings.Contains(raw, ".") && strings.HasSuffix(raw, "()") {
			// Process function syntax like "amount.sum()"
			subParts := strings.SplitN(raw, ".", 2)
			fieldPart := strings.TrimSpace(subParts[0])
			funcPart := strings.TrimSpace(subParts[1])
			if len(funcPart) < 3 || funcPart[len(funcPart)-2:] != "()" {
				return nil, nil, fmt.Errorf("invalid function syntax in select field: %s", part)
			}
			funcName := funcPart[:len(funcPart)-2]
			if !IsAllowedFunction(funcName) {
				return nil, nil, fmt.Errorf("function %s is not allowed", funcName)
			}
			if funcName == "count" && fieldPart == "" {
				exprBuilder.WriteString("COUNT(*)")
			} else {
				exprBuilder.WriteString(strings.ToUpper(funcName))
				exprBuilder.WriteByte('(')
				exprBuilder.WriteString(fieldPart)
				exprBuilder.WriteByte(')')
			}
			if alias == "" {
				alias = funcName
			}
			// Append alias so that the SQL query becomes, for example, "SUM(amount) AS sum"
			exprBuilder.WriteString(" AS ")
			exprBuilder.WriteString(alias)
		} else if raw == "count()" {
			exprBuilder.WriteString("COUNT(*)")
			if alias == "" {
				alias = "count"
			}
			exprBuilder.WriteString(" AS ")
			exprBuilder.WriteString(alias)
		} else {
			// For plain fields - if the value is contextual, substitute it as a literal
			if strings.HasPrefix(raw, "erctx.") || strings.HasPrefix(raw, "request.") {
				substituted := substitutePluginContext(raw, flatCtx, pluginCtx)
				if alias == "" {
					alias = strings.ReplaceAll(raw, ".", "_")
				}
				// Use builder instead of fmt.Sprintf
				exprBuilder.WriteString("'")
				exprBuilder.WriteString(escapeSQLLiteral(substituted))
				exprBuilder.WriteString("' AS ")
				exprBuilder.WriteString(alias)
			} else {
				exprBuilder.WriteString(raw)
				if alias != "" {
					exprBuilder.WriteString(" AS ")
					exprBuilder.WriteString(alias)
				}
				// Only add raw field to groupBy if it's not a context variable
				groupBy = append(groupBy, raw)
			}
		}
		selectFields = append(selectFields, exprBuilder.String())
	}
	return selectFields, groupBy, nil
}

// ParseWhereClause converts query parameters starting with "where." into a map,
// performing context substitution for values.
func ParseWhereClause(values map[string][]string, flatCtx map[string]string, pluginCtx map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(values))
	for key, vals := range values {
		if strings.HasPrefix(key, "where.") {
			prefix, rest, found := strings.Cut(key, ".")
			if !found || prefix != "where" {
				return nil, fmt.Errorf("invalid where key format: %s", key)
			}

			// Check for 'not' modifier
			opCode := ""
			field := ""
			isNot := false
			if strings.HasPrefix(rest, "not.") {
				isNot = true
				rest = rest[len("not."):]
			}
			opCode, field, found = strings.Cut(rest, ".")
			if !found {
				return nil, fmt.Errorf("invalid where key format: %s", key)
			}
			opCode = strings.ToLower(opCode)

			if _, ok := AllowedOps[opCode]; !ok {
				return nil, fmt.Errorf("unknown operator: %s", opCode)
			}
			op := AllowedOps[opCode]

			mapKey := field
			if isNot {
				mapKey = "NOT " + field
			}

			substituted := ""
			if len(vals) > 0 {
				if op == "IN" {
					val_arr := strings.Split(vals[0], ",")
					substituted_arr := make([]string, len(val_arr))
					for idx, v := range val_arr {
						substituted_arr[idx] = substitutePluginContext(v, flatCtx, pluginCtx)
					}
					substituted = strings.Join(substituted_arr, ",")
				} else {
					substituted = substitutePluginContext(vals[0], flatCtx, pluginCtx)
				}
			}

			if existing, found := result[mapKey]; found {
				m, ok := existing.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("conflicting condition types for field %s", mapKey)
				}
				m[op] = substituted
			} else {
				result[mapKey] = map[string]any{op: substituted}
			}
		}
	}
	return result, nil
}

// tableHandler processes CRUD operations on tables.
func tableHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbKey := strings.ToLower(vars["db"])
	table := vars["table"]

	// Get global config
	config := GetConfig()

	// Get plugin config
	pluginCfg, hasPluginCfg := config.PluginMap[dbKey]

	// Check if table restricted for this dbKey
	if hasPluginCfg {
		if table == "easyrest_cache" || slices.Contains(pluginCfg.Exclude.Table, table) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
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

	// Check if table is public for this dbKey
	isPublicTable := false
	if hasPluginCfg {
		if slices.Contains(pluginCfg.Public.Table, table) {
			isPublicTable = true
		}
	}

	userID, r, err := Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var requiredScope string
	if r.Method == http.MethodGet {
		requiredScope = table + "-read"
	} else {
		requiredScope = table + "-write"
	}
	if config.CheckScope && !isPublicTable {
		w.Header().Add("Vary", "Authorization")
		claims := getTokenClaims(r)
		if !CheckScope(claims, requiredScope) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}
	}

	// ETag handling START - Only if EnableCache is true for this plugin
	var currentETag string
	var cachePlugin easyrest.CachePlugin = getFirstCachePlugin(dbKey)
	var etagKey string

	if cachePlugin != nil {
		etagKey = fmt.Sprintf("etag:%s:%s", dbKey, table)
		ifMatch := r.Header.Get("If-Match")
		ifNoneMatch := r.Header.Get("If-None-Match")
		cachePlugin = getFirstCachePlugin(dbKey)

		// Only get cache plugin and ETag if cache is enabled AND relevant headers are present/needed
		if ifMatch != "" || ifNoneMatch != "" || r.Method == http.MethodGet || r.Method == http.MethodHead {
			if cachePlugin != nil {
				currentETag = getOrGenerateETag(cachePlugin, etagKey)
			}
		}

		// Check If-None-Match for GET/HEAD requests (only if cache is enabled)
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && ifNoneMatch != "" {
			if cachePlugin != nil && ifNoneMatch == currentETag {
				w.Header().Set("ETag", currentETag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		// Check If-Match for write operations (POST, PATCH, DELETE) (only if cache is enabled)
		if (r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodDelete) && ifMatch != "" {
			if cachePlugin == nil || ifMatch != currentETag {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
	} // End of if pluginCfg.EnableCache
	// ETag handling END

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

	queryValues := r.URL.Query()

	switch r.Method {
	case http.MethodGet:
		// Set ETag header before sending response (only if cache was enabled and plugin found)
		if cachePlugin != nil {
			w.Header().Set("ETag", currentETag)
		}

		// --- Range header parsing for pagination ---
		limit := 0
		offset := 0
		rangeUnitHeader := r.Header.Get("Range-Unit")
		rangeHeader := r.Header.Get("Range")
		usedHeaderRange := false
		if strings.ToLower(rangeUnitHeader) == "items" && rangeHeader != "" {
			// Expecting format: offset-last (e.g., 0-9)
			parts := strings.SplitN(rangeHeader, "-", 2)
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 == nil && err2 == nil && start >= 0 && end >= start {
					offset = start
					limit = end - start + 1
					usedHeaderRange = true
				}
			}
		}
		if !usedHeaderRange {
			limit, _ = strconv.Atoi(queryValues.Get("limit"))
			offset, _ = strconv.Atoi(queryValues.Get("offset"))
			if offset < 0 {
				offset = 0
			}
		}
		if limit == 0 {
			limit = pluginCfg.DefaultLimit
		}

		selectParam := queryValues.Get("select")

		selectFields, groupBy, err := processSelectParam(selectParam, flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing select parameter: "+err.Error(), http.StatusBadRequest)
			return
		}

		where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}

		ordering := ParseCSV(queryValues.Get("ordering"))

		startTime := time.Now()
		rows, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, pluginCtx)
		queryTime := time.Since(startTime)

		w.Header().Set("Server-Timing", fmt.Sprintf("db;dur=%.3f", float64(queryTime.Milliseconds())))

		if err != nil {
			http.Error(w, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
			return
		}

		status := http.StatusOK

		// --- Add Content-Range and Range-Unit headers ---
		rowCount := len(rows)
		startIdx := offset
		endIdx := offset + rowCount - 1
		if rowCount == 0 {
			endIdx = offset - 1 // for empty result, E < S
		}

		// Out of range: use requested end for Content-Range, always return []
		if startIdx > endIdx {
			status = http.StatusRequestedRangeNotSatisfiable
			if usedHeaderRange {
				parts := strings.SplitN(rangeHeader, "-", 2)
				if len(parts) == 2 {
					end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
					if err2 == nil {
						startIdx = end
						endIdx = end
					}
				}
			}
			rows = []map[string]any{} // always return [] for JSON
		}
		w.Header().Set("Content-Range", fmt.Sprintf("%d-%d/*", startIdx, endIdx))
		w.Header().Set("Range-Unit", "items")
		w.Header().Set("Accept-Ranges", "items")

		makeResponse(w, r, status, rows)

	case http.MethodPost:
		parsedData, err := parseRequest(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data, ok := parsedData.([]map[string]any)
		if !ok {
			http.Error(w, "Invalid data format", http.StatusBadRequest)
			return
		}

		for i, row := range data {
			data[i] = substituteValue(row, flatCtx, pluginCtx).(map[string]any)
		}
		startTime := time.Now()
		rows, err := dbPlug.TableCreate(userID, table, data, pluginCtx)
		queryTime := time.Since(startTime)
		w.Header().Set("Server-Timing", fmt.Sprintf("db;dur=%.3f", float64(queryTime.Milliseconds())))
		if err != nil {
			http.Error(w, "Error in TableCreate: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update ETag after successful write operation (only if cache was enabled and plugin found)
		if cachePlugin != nil {
			newETag := updateETag(cachePlugin, etagKey)
			w.Header().Set("ETag", newETag)
		}

		makeResponse(w, r, http.StatusCreated, rows)
	case http.MethodPatch:
		parsedData, err := parseRequest(r, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data, ok := parsedData.(map[string]any)
		if !ok {
			http.Error(w, "Invalid data format", http.StatusBadRequest)
			return
		}

		data = substituteValue(data, flatCtx, pluginCtx).(map[string]any)
		where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		startTime := time.Now()
		updated, err := dbPlug.TableUpdate(userID, table, data, where, pluginCtx)
		queryTime := time.Since(startTime)
		w.Header().Set("Server-Timing", fmt.Sprintf("db;dur=%.3f", float64(queryTime.Milliseconds())))
		if err != nil {
			http.Error(w, "Error in TableUpdate: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update ETag after successful write operation (only if cache was enabled and plugin found)
		if cachePlugin != nil {
			newETag := updateETag(cachePlugin, etagKey)
			w.Header().Set("ETag", newETag)
		}

		makeResponse(w, r, http.StatusOK, map[string]int{"updated": updated})

	case http.MethodDelete:
		where, err := ParseWhereClause(queryValues, flatCtx, pluginCtx)
		if err != nil {
			http.Error(w, "Error processing where clause: "+err.Error(), http.StatusBadRequest)
			return
		}
		startTime := time.Now()
		_, err = dbPlug.TableDelete(userID, table, where, pluginCtx)
		queryTime := time.Since(startTime)
		w.Header().Set("Server-Timing", fmt.Sprintf("db;dur=%.3f", float64(queryTime.Milliseconds())))
		if err != nil {
			http.Error(w, "Error in TableDelete: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Update ETag after successful write operation (only if cache was enabled and plugin found)
		if cachePlugin != nil {
			newETag := updateETag(cachePlugin, etagKey)
			w.Header().Set("ETag", newETag) // Set ETag even for 204
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
