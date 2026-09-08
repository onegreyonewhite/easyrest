package server

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// getNestedValue traverses a nested map using dot-separated keys.
// If the full path is found, it returns the value and true; otherwise false.
func getNestedValue(data map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var current any = data
	for _, p := range parts {
		if m, ok := current.(map[string]any); ok {
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

func hasContextRef(s string) bool {
	return strings.Contains(s, "erctx.") || strings.Contains(s, "request.")
}

func queryNeedsContextSubst(query map[string][]string) bool {
	for _, vals := range query {
		if slices.ContainsFunc(vals, hasContextRef) {
			return true
		}
	}
	return false
}

func valueNeedsContextSubst(val any) bool {
	switch s := val.(type) {
	case string:
		return hasContextRef(s)
	case map[string]any:
		for _, v := range s {
			if valueNeedsContextSubst(v) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(s, valueNeedsContextSubst) {
			return true
		}
	case []map[string]any:
		for _, row := range s {
			if valueNeedsContextSubst(row) {
				return true
			}
		}
	}
	return false
}

func formatContextForSubst(pluginCtx map[string]any, existing map[string]string, data any) (map[string]string, error) {
	if existing != nil {
		return existing, nil
	}
	if !valueNeedsContextSubst(data) {
		return nil, nil
	}
	return easyrest.FormatToContext(pluginCtx)
}

// substitutePluginContext replaces values starting with "erctx." or "request."
// with the corresponding value from flatCtx or pluginCtx.
func substitutePluginContext(input string, flatCtx map[string]string, pluginCtx map[string]any) string {
	if strings.HasPrefix(input, "erctx.") {
		key := input[len("erctx."):]
		normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if val, ok := flatCtx[normalizedKey]; ok {
			return val
		}
	} else if strings.HasPrefix(input, "request.") {
		key := input[len("request."):]
		if v, ok := getNestedValue(pluginCtx, key); ok {
			switch vv := v.(type) {
			case string:
				return vv
			case int:
				return strconv.Itoa(vv)
			case int64:
				return strconv.FormatInt(vv, 10)
			case float64:
				return strconv.FormatFloat(vv, 'f', -1, 64)
			case bool:
				return strconv.FormatBool(vv)
			case map[string]any, []any:
				if b, err := json.Marshal(v); err == nil {
					return string(b)
				}
			default:
				return fmt.Sprintf("%v", vv)
			}
		}
	}
	return input
}

// substituteValue recursively substitutes string values in arbitrary data structures.
func substituteValue(val any, flatCtx map[string]string, pluginCtx map[string]any) any {
	switch s := val.(type) {
	case string:
		if strings.HasPrefix(s, "erctx.") || strings.HasPrefix(s, "request.") {
			return substitutePluginContext(s, flatCtx, pluginCtx)
		}
		return s
	case map[string]any:
		for k, v := range s {
			s[k] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	case []any:
		for i, v := range s {
			s[i] = substituteValue(v, flatCtx, pluginCtx)
		}
		return s
	default:
		return val
	}
}
