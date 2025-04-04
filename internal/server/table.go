package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
				return nil, nil, fmt.Errorf("invalid function syntax in select field: %s", part)
			}
			funcName := funcPart[:len(funcPart)-2]
			if !IsAllowedFunction(funcName) {
				return nil, nil, fmt.Errorf("function %s is not allowed", funcName)
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
func ParseWhereClause(values map[string][]string, flatCtx map[string]string, pluginCtx map[string]any) (map[string]any, error) {
	result := make(map[string]any)
	for key, vals := range values {
		if strings.HasPrefix(key, "where.") {
			parts := strings.Split(key, ".")
			if len(parts) != 3 {
				return nil, fmt.Errorf("Invalid where key format: %s", key)
			}
			opCode := strings.ToLower(parts[1])
			field := parts[2]

			if _, ok := AllowedOps[opCode]; !ok {
				return nil, fmt.Errorf("unknown operator: %s", opCode)
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
				m, ok := existing.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("type error for field %s", field)
				}
				m[op] = substituted
				result[field] = m
			} else {
				result[field] = map[string]any{op: substituted}
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
	w.Header().Set("Preference-Applied", "timezone="+pluginCtx["timezone"].(string))
	flatCtx, err := easyrest.FormatToContext(pluginCtx)
	if err != nil {
		http.Error(w, "Error formatting context: "+err.Error(), http.StatusInternalServerError)
		return
	}

	queryValues := r.URL.Query()

	switch r.Method {
	case http.MethodGet:
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
		limit, _ := strconv.Atoi(queryValues.Get("limit"))
		offset, _ := strconv.Atoi(queryValues.Get("offset"))

		startTime := time.Now()
		rows, err := dbPlug.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, pluginCtx)
		queryTime := time.Since(startTime)

		w.Header().Set("Server-Timing", fmt.Sprintf("db;dur=%.3f", float64(queryTime.Milliseconds())))

		if err != nil {
			http.Error(w, "Error in TableGet: "+err.Error(), http.StatusInternalServerError)
			return
		}
		makeResponse(w, r, http.StatusOK, rows)

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
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
