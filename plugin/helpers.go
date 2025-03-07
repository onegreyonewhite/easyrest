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
func BuildWhereClause(where map[string]interface{}) (string, []interface{}, error) {
	conds := make([]string, 0, len(where))
	args := make([]interface{}, 0, len(where))
	for field, val := range where {
		switch v := val.(type) {
		case map[string]interface{}:
			for op, operand := range v {
				// If operand is a string and starts with "erctx.", inject it directly.
				if s, ok := operand.(string); ok && strings.HasPrefix(s, "erctx.") {
					conds = append(conds, fmt.Sprintf("%s %s %s", field, op, s))
				} else {
					conds = append(conds, fmt.Sprintf("%s %s ?", field, op))
					args = append(args, operand)
				}
			}
		default:
			if s, ok := v.(string); ok && strings.HasPrefix(s, "erctx.") {
				conds = append(conds, fmt.Sprintf("%s = %s", field, s))
			} else {
				conds = append(conds, fmt.Sprintf("%s = ?", field))
				args = append(args, v)
			}
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
func FormatToContext(input map[string]interface{}) (map[string]string, error) {
	output := make(map[string]string)
	var flatten func(prefix string, val interface{}) error
	flatten = func(prefix string, val interface{}) error {
		switch v := val.(type) {
		case map[string]interface{}:
			for k, v2 := range v {
				normalizedKey := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, ".", "_"), "-", "_"))
				newPrefix := normalizedKey
				if prefix != "" {
					newPrefix = prefix + "_" + normalizedKey
				}
				if err := flatten(newPrefix, v2); err != nil {
					return err
				}
			}
		case []interface{}:
			for i, item := range v {
				newPrefix := fmt.Sprintf("%s_%d", prefix, i)
				if err := flatten(newPrefix, item); err != nil {
					return err
				}
			}
		default:
			s := fmt.Sprintf("%v", v)
			// Validate that the value does not contain dangerous characters.
			if strings.Contains(s, ";") || strings.Contains(s, "--") {
				return fmt.Errorf("invalid value in context: %s", s)
			}
			output[prefix] = s
		}
		return nil
	}
	if err := flatten("", input); err != nil {
		return nil, err
	}
	return output, nil
}
