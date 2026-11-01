package server

import (
	"errors"
	"fmt"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func validateSelectAlias(alias, part string) error {
	if alias == "" {
		return nil
	}
	if err := sanitizeIdentifier(alias); err != nil {
		return fmt.Errorf("invalid alias in select field: %s", part)
	}
	return nil
}

// processSelectParam parses the "select" query parameter, performs context substitution,
// and assigns an alias (defaulting to the field name with dots replaced by underscores) if not provided.
// JSON arrow paths are rendered as PostgreSQL expressions and alias to the last object key.
func processSelectParam(param string, flatCtx map[string]string, pluginCtx map[string]any) ([]string, []string, error) {
	if param == "" {
		return nil, nil, nil
	}
	if !strings.ContainsAny(param, ",:.()") && !strings.Contains(param, "->") {
		raw := strings.TrimSpace(param)
		if raw == "" {
			return nil, nil, nil
		}
		if err := sanitizeIdentifier(raw); err != nil {
			return nil, nil, fmt.Errorf("invalid field name in select field: %s", param)
		}
		return []string{raw}, []string{raw}, nil
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

		if strings.Contains(raw, "->") {
			if alias != "" {
				if err := validateSelectAlias(alias, part); err != nil {
					return nil, nil, err
				}
			}
			item, groupExpr, err := easyrest.RenderJSONSelect(raw, alias)
			if err != nil {
				if errors.Is(err, easyrest.ErrJSONIndexAlias) {
					return nil, nil, fmt.Errorf("%w: %s", err, part)
				}
				return nil, nil, fmt.Errorf("invalid field name in select field: %s", part)
			}
			selectFields = append(selectFields, item)
			groupBy = append(groupBy, groupExpr)
			continue
		}
		if strings.Contains(raw, ".") && strings.HasSuffix(raw, "()") {
			// Process function syntax like "amount.sum()"
			subParts := strings.SplitN(raw, ".", 2)
			fieldPart := strings.TrimSpace(subParts[0])
			if err := sanitizeIdentifier(fieldPart); err != nil {
				return nil, nil, fmt.Errorf("invalid field name in select field: %s", part)
			}
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
			if err := validateSelectAlias(alias, part); err != nil {
				return nil, nil, err
			}
			// Append alias so that the SQL query becomes, for example, "SUM(amount) AS sum"
			exprBuilder.WriteString(" AS ")
			exprBuilder.WriteString(alias)
		} else if raw == "count()" {
			exprBuilder.WriteString("COUNT(*)")
			if alias == "" {
				alias = "count"
			}
			if err := validateSelectAlias(alias, part); err != nil {
				return nil, nil, err
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
				if err := validateSelectAlias(alias, part); err != nil {
					return nil, nil, err
				}
				// Use builder instead of fmt.Sprintf
				exprBuilder.WriteString("'")
				exprBuilder.WriteString(escapeSQLLiteral(substituted))
				exprBuilder.WriteString("' AS ")
				exprBuilder.WriteString(alias)
			} else {
				if err := sanitizeIdentifier(raw); err != nil {
					return nil, nil, fmt.Errorf("invalid field name in select field: %s", part)
				}
				exprBuilder.WriteString(raw)
				if alias != "" {
					if err := validateSelectAlias(alias, part); err != nil {
						return nil, nil, err
					}
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

			asText := true
			if strings.Contains(field, "->") {
				expr, text, err := easyrest.PostgresJSONExpr(field)
				if err != nil {
					return nil, fmt.Errorf("invalid field name in where clause: %s", key)
				}
				if !text && (op == "LIKE" || op == "ILIKE") {
					return nil, fmt.Errorf("like and ilike require ->>")
				}
				field = expr
				asText = text
			} else if err := sanitizeIdentifier(field); err != nil {
				return nil, fmt.Errorf("invalid field name in where clause: %s", key)
			}

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
			if !asText && op != "IS" {
				if err := easyrest.ValidateJSONArrowValue(op, substituted, easyrest.DialectFromContext(pluginCtx)); err != nil {
					return nil, err
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
