package plugin

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// isValidWhereField reports whether field may appear as a WHERE column expression.
// It accepts plain identifiers and ILIKE rewrite forms produced by data plugins.
func isValidWhereField(field string) bool {
	if IsValidIdentifier(field) {
		return true
	}
	const lowerPrefix = "LOWER("
	if strings.HasPrefix(field, lowerPrefix) && strings.HasSuffix(field, ")") {
		return IsValidIdentifier(field[len(lowerPrefix) : len(field)-1])
	}
	const collateSuffix = " COLLATE NOCASE"
	if strings.HasSuffix(field, collateSuffix) {
		return IsValidIdentifier(field[:len(field)-len(collateSuffix)])
	}
	return false
}

// ValidateColumnName returns an error when name is not a safe SQL column identifier.
func ValidateColumnName(name string) error {
	if !IsValidIdentifier(name) {
		return fmt.Errorf("invalid column name: %q", name)
	}
	return nil
}

// IsValidIdentifier reports whether id is a safe SQL identifier: [A-Za-z_][A-Za-z0-9_]*.
func IsValidIdentifier(id string) bool {
	if len(id) == 0 {
		return false
	}
	c := id[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
		return false
	}
	for i := 1; i < len(id); i++ {
		c = id[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// Context keys for optional zero-argument DB routines run inside the data transaction.
const (
	CtxDBType          = "db.type"
	CtxDBPreRequest    = "db.pre-request"
	CtxDBPostRequest   = "db.post-request"
	CtxTable           = "table"
	CtxFunction        = "function"
	CtxHandlerStatus   = "handler.status"
	CtxCacheInvalidate = "cache.invalidate"
)

// dbTypeAliases maps URI schemes to a stable type name. Unknown schemes stay as-is.
var dbTypeAliases = map[string]string{
	"postgresql": "postgres",
}

// URIScheme returns the lowercase scheme before "://", or "" if the URI has no scheme.
func URIScheme(uri string) string {
	scheme, _, ok := strings.Cut(uri, "://")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(scheme))
}

// CanonicalDBType maps a URI scheme to a stable DB type name.
func CanonicalDBType(scheme string) string {
	s := strings.ToLower(strings.TrimSpace(scheme))
	if s == "" {
		return ""
	}
	if alias, ok := dbTypeAliases[s]; ok {
		return alias
	}
	return s
}

// DBTypeFromURI returns the canonical DB type for a connection URI.
func DBTypeFromURI(uri string) string {
	return CanonicalDBType(URIScheme(uri))
}

// IsContextRoutineKey reports whether key is a plugin-only hook name that must
// not be written as a session GUC (hyphens are invalid in PostgreSQL GUC names).
func IsContextRoutineKey(key string) bool {
	return key == CtxDBPreRequest || key == CtxDBPostRequest
}

// isSafeRoutineName allows ident or schema.ident.
func isSafeRoutineName(name string) bool {
	schema, ident, ok := strings.Cut(name, ".")
	if !ok {
		return IsValidIdentifier(name)
	}
	if schema == "" || ident == "" || strings.Contains(ident, ".") {
		return false
	}
	return IsValidIdentifier(schema) && IsValidIdentifier(ident)
}

// ContextRoutineName returns a safe zero-argument routine name from ctx[key].
// Missing, blank, non-string, or unsafe names return "" (caller skips the hook).
func ContextRoutineName(ctx map[string]any, key string) string {
	if ctx == nil {
		return ""
	}
	raw, ok := ctx[key]
	if !ok {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" || !isSafeRoutineName(s) {
		return ""
	}
	return s
}

// CacheInvalidateNames returns comma-separated table/view names from ctx[cache.invalidate].
// Missing, non-string, blank, and unsafe tokens are skipped.
func CacheInvalidateNames(ctx map[string]any) []string {
	s, ok := CtxString(ctx, CtxCacheInvalidate)
	if !ok {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" || !isSafeRoutineName(name) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// internal helper for building condition entries from the where map.
type whereCondEntry struct {
	cond    string
	args    []any
	sortKey string
}

// buildWhereCondEntries processes the where map and returns a slice of whereCondEntry.
func buildWhereCondEntries(where map[string]any) ([]whereCondEntry, error) {
	entries := make([]whereCondEntry, 0, len(where))
	var sb strings.Builder

	addEntry := func(cond string, args []any, sortKey string) {
		entries = append(entries, whereCondEntry{
			cond:    cond,
			args:    args,
			sortKey: sortKey,
		})
	}

	for field, val := range where {
		isNot := false
		baseField := field
		if strings.HasPrefix(field, "NOT ") {
			isNot = true
			baseField = field[4:]
		}
		if !isValidWhereField(baseField) {
			return nil, fmt.Errorf("invalid field name: %q", field)
		}
		switch v := val.(type) {
		case map[string]any:
			for op, operand := range v {
				if op == "IN" {
					arr := strings.Split(operand.(string), ",")
					for i := range arr {
						if trimmed := strings.TrimSpace(arr[i]); trimmed != "" {
							arr[i] = trimmed
						} else {
							arr = slices.Delete(arr, i, i+1)
						}
					}
					sb.Reset()
					if isNot {
						sb.WriteString("NOT (")
					}
					sb.WriteString(baseField)
					if len(arr) == 0 {
						sb.WriteString(" IN (NULL)")
						if isNot {
							sb.WriteByte(')')
						}
						addEntry(sb.String(), nil, field+"|IN")
					} else {
						sb.WriteString(" IN (")
						for i := range arr {
							if i > 0 {
								sb.WriteByte(',')
							}
							sb.WriteByte('?')
						}
						sb.WriteByte(')')
						if isNot {
							sb.WriteByte(')')
						}
						inVals := make([]any, len(arr))
						for i, val := range arr {
							inVals[i] = val
						}
						addEntry(sb.String(), inVals, field+"|IN")
					}
				} else {
					sb.Reset()
					if isNot {
						sb.WriteString("NOT (")
						sb.WriteString(baseField)
						sb.WriteByte(' ')
						sb.WriteString(op)
						sb.WriteString(" ?)")
						addEntry(sb.String(), []any{operand}, field+"|NOT "+op)
					} else {
						sb.WriteString(baseField)
						sb.WriteByte(' ')
						sb.WriteString(op)
						sb.WriteString(" ?")
						addEntry(sb.String(), []any{operand}, field+"|"+op)
					}
				}
			}
		default:
			sb.Reset()
			if isNot {
				sb.WriteString("NOT (")
				sb.WriteString(baseField)
				sb.WriteString(" = ?)")
				addEntry(sb.String(), []any{v}, field+"|NOT =")
			} else {
				sb.WriteString(baseField)
				sb.WriteString(" = ?")
				addEntry(sb.String(), []any{v}, field+"|=")
			}
		}
	}
	return entries, nil
}

// BuildWhereClause constructs a SQL WHERE clause from a given where map.
// The where map is expected to be in the form:
//
//	{ "field": {"=": value}, ... }
//
// It returns the SQL string (starting with " WHERE ") and the list of arguments.
func BuildWhereClause(where map[string]any) (string, []any, error) {
	entries, err := buildWhereCondEntries(where)
	if err != nil {
		return "", nil, err
	}
	if len(entries) == 0 {
		return "", nil, nil
	}
	clause, args := joinWhereEntries(entries)
	return clause, args, nil
}

func joinWhereEntries(entries []whereCondEntry) (string, []any) {
	var sb strings.Builder
	args := make([]any, 0, len(entries))
	sb.WriteString(" WHERE ")
	for i, entry := range entries {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		sb.WriteString(entry.cond)
		args = append(args, entry.args...)
	}
	return sb.String(), args
}

// BuildWhereClauseSorted constructs a SQL WHERE clause from a given where map,
// but sorts the conditions (and their arguments) by field name and operator for deterministic output.
func BuildWhereClauseSorted(where map[string]any) (string, []any, error) {
	entries, err := buildWhereCondEntries(where)
	if err != nil {
		return "", nil, err
	}
	slices.SortFunc(entries, func(a, b whereCondEntry) int {
		return strings.Compare(a.sortKey, b.sortKey)
	})
	if len(entries) == 0 {
		return "", nil, nil
	}
	clause, args := joinWhereEntries(entries)
	return clause, args, nil
}

// FormatToContext flattens an arbitrarily nested map into a flat map with keys joined by underscores.
// It replaces dots and dashes with underscores and converts keys to lowercase.
// For arrays, it uses the index as part of the key.
// It also validates that the final values do not contain dangerous characters.
var keyNormalizer = strings.NewReplacer(".", "_", "-", "_")

func normalizeKey(k string) string {
	return strings.ToLower(keyNormalizer.Replace(k))
}

func joinContextPrefix(prefix, part string) string {
	if prefix == "" {
		return part
	}
	var b strings.Builder
	b.Grow(len(prefix) + 1 + len(part))
	b.WriteString(prefix)
	b.WriteByte('_')
	b.WriteString(part)
	return b.String()
}

func scalarToContextString(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return strconv.FormatFloat(vv, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(vv)
	case int:
		return strconv.Itoa(vv)
	case int64:
		return strconv.FormatInt(vv, 10)
	case int32:
		return strconv.FormatInt(int64(vv), 10)
	default:
		return fmt.Sprintf("%v", vv)
	}
}

func FormatToContext(input map[string]any) (map[string]string, error) {
	output := make(map[string]string, len(input))
	var flatten func(prefix string, val any) error
	flatten = func(prefix string, val any) error {
		switch v := val.(type) {
		case map[string]any:
			for k, v2 := range v {
				nk := normalizeKey(k)
				if err := flatten(joinContextPrefix(prefix, nk), v2); err != nil {
					return err
				}
			}
		case []any:
			for i, item := range v {
				if err := flatten(joinContextPrefix(prefix, strconv.Itoa(i)), item); err != nil {
					return err
				}
			}
		default:
			s := scalarToContextString(v)
			if !(strings.Contains(s, ";") || strings.Contains(s, "--")) {
				output[prefix] = s
			}
		}
		return nil
	}
	for k, v := range input {
		nk := normalizeKey(k)
		if err := flatten(nk, v); err != nil {
			return nil, err
		}
	}
	return output, nil
}

// MergeResponseSettings copies non-empty response settings into ctx and returns
// that map. An empty settings map (or only blank keys/values) returns nil so the
// caller can keep its existing context. When ctx is non-nil it is mutated in place.
func MergeResponseSettings(ctx map[string]any, settings map[string]string) map[string]any {
	if len(settings) == 0 {
		return nil
	}
	out := ctx
	if out == nil {
		out = make(map[string]any, len(settings))
	}
	wrote := false
	for k, v := range settings {
		if k == "" || v == "" {
			continue
		}
		out[k] = v
		wrote = true
	}
	if !wrote {
		return nil
	}
	return out
}

// GetTxPreference extracts the transaction preference ('commit' or 'rollback') from the context.
// Defaults to 'commit' if not specified. Returns an error for invalid values.
func GetTxPreference(ctx map[string]any) (string, error) {
	txPreference := "commit" // Default behavior
	if ctx != nil {
		// Use type assertion with checking for existence
		if preferAny, preferExists := ctx["prefer"]; preferExists {
			// Check if prefer is a map
			if prefer, ok := preferAny.(map[string]any); ok {
				// Check if tx exists within prefer
				if txPrefAny, txPrefExists := prefer["tx"]; txPrefExists {
					// Check if tx is a string
					if txPref, ok := txPrefAny.(string); ok && txPref != "" { // Ensure it's a non-empty string
						// Validate the value
						if txPref == "commit" || txPref == "rollback" {
							txPreference = txPref
						} else {
							return "", fmt.Errorf("invalid value for prefer.tx: '%s', must be 'commit' or 'rollback'", txPref)
						}
					} else if !ok {
						// If prefer.tx exists but is not a string
						return "", fmt.Errorf("invalid type for prefer.tx: expected string, got %T", txPrefAny)
					}
					// If txPref is an empty string, we keep the default "commit"
				}
			} else {
				// If prefer exists but is not a map[string]any
				return "", fmt.Errorf("invalid type for prefer: expected map[string]any, got %T", preferAny)
			}
		}
	}
	return txPreference, nil
}
