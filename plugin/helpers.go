package plugin

import (
	"fmt"
	"strings"
)

// BuildWhereClause constructs a SQL WHERE clause from a given where map.
// The where map is expected to be in the form:
//
//	{ "field": {"=": value}, ... }
//
// It returns the SQL string (starting with " WHERE ") and the list of arguments.
// This is the original logic.
func BuildWhereClause(where map[string]any) (string, []any, error) {
	conds := make([]string, 0, len(where))
	args := make([]any, 0, len(where))
	for field, val := range where {
		switch v := val.(type) {
		case map[string]any:
			for op, operand := range v {
				if op == "IN" {
					arr := strings.Split(operand.(string), ",")
					for i := range arr {
						arr[i] = strings.TrimSpace(arr[i])
					}
					if len(arr) == 0 {
						conds = append(conds, fmt.Sprintf("%s IN (NULL)", field))
					} else {
						placeholders := make([]string, len(arr))
						for i := range arr {
							placeholders[i] = "?"
						}
						conds = append(conds, fmt.Sprintf("%s IN (%s)", field, strings.Join(placeholders, ",")))
						inVals := make([]any, len(arr))
						for i, val := range arr {
							inVals[i] = val
						}
						args = append(args, inVals...)
					}
				} else {
					conds = append(conds, fmt.Sprintf("%s %s ?", field, op))
					args = append(args, operand)
				}
			}
		default:
			conds = append(conds, fmt.Sprintf("%s = ?", field))
			args = append(args, v)
		}
	}
	if len(conds) > 0 {
		return " WHERE " + strings.Join(conds, " AND "), args, nil
	}
	return "", args, nil
}

// FormatToContext flattens an arbitrarily nested map into a flat map with keys joined by underscores.
// It replaces dots and dashes with underscores and converts keys to lowercase.
// For arrays, it uses the index as part of the key.
// It also validates that the final values do not contain dangerous characters.
func FormatToContext(input map[string]any) (map[string]string, error) {
	output := make(map[string]string)
	var flatten func(prefix string, val any) error
	flatten = func(prefix string, val any) error {
		switch v := val.(type) {
		case map[string]any:
			for k, v2 := range v {
				normalizedKey := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, ".", "_"), "-", "_"))
				var newPrefix string
				if prefix == "" {
					newPrefix = normalizedKey
				} else {
					newPrefix = prefix + "_" + normalizedKey
				}
				if err := flatten(newPrefix, v2); err != nil {
					return err
				}
			}
		case []any:
			for i, item := range v {
				newPrefix := fmt.Sprintf("%s_%d", prefix, i)
				if err := flatten(newPrefix, item); err != nil {
					return err
				}
			}
		default:
			s := fmt.Sprintf("%v", v)
			if !(strings.Contains(s, ";") || strings.Contains(s, "--")) {
				output[prefix] = s
			}
		}
		return nil
	}
	for k, v := range input {
		normalizedKey := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, ".", "_"), "-", "_"))
		if err := flatten(normalizedKey, v); err != nil {
			return nil, err
		}
	}
	return output, nil
}
