package server

import (
	"fmt"
	"strings"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

var (
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

func sanitizeIdentifier(id string) error {
	if easyrest.IsValidIdentifier(id) {
		return nil
	}
	return fmt.Errorf("invalid identifier: %s", id)
}

func sanitizeIdentifierList(list []string) error {
	for _, raw := range list {
		err := sanitizeIdentifier(raw)
		if err != nil {
			return err
		}
	}
	return nil
}

// validateBodyColumns rejects JSON object keys that are not safe SQL identifiers.
func validateBodyColumns(data any) error {
	switch d := data.(type) {
	case map[string]any:
		for k := range d {
			if err := sanitizeIdentifier(k); err != nil {
				return err
			}
		}
	case []map[string]any:
		for _, row := range d {
			for k := range row {
				if err := sanitizeIdentifier(k); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
