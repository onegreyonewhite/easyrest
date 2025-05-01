package plugin

import (
	"fmt"
	"slices"
	"strings"
)

// internal helper for building condition entries from the where map.
type whereCondEntry struct {
	cond    string
	args    []any
	sortKey string
}

// buildWhereCondEntries processes the where map and returns a slice of whereCondEntry.
func buildWhereCondEntries(where map[string]any) []whereCondEntry {
	entries := make([]whereCondEntry, 0, len(where))

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
			baseField = strings.TrimPrefix(field, "NOT ")
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
					placeholders := make([]string, len(arr))
					for i := range arr {
						placeholders[i] = "?"
					}
					inVals := make([]any, len(arr))
					for i, val := range arr {
						inVals[i] = val
					}
					if len(arr) == 0 {
						if isNot {
							addEntry(fmt.Sprintf("NOT (%s IN (NULL))", baseField), nil, field+"|IN")
						} else {
							addEntry(fmt.Sprintf("%s IN (NULL)", baseField), nil, field+"|IN")
						}
					} else {
						if isNot {
							addEntry(fmt.Sprintf("NOT (%s IN (%s))", baseField, strings.Join(placeholders, ",")), inVals, field+"|IN")
						} else {
							addEntry(fmt.Sprintf("%s IN (%s)", baseField, strings.Join(placeholders, ",")), inVals, field+"|IN")
						}
					}
				} else {
					if isNot {
						addEntry(fmt.Sprintf("NOT (%s %s ?)", baseField, op), []any{operand}, field+"|NOT "+op)
					} else {
						addEntry(fmt.Sprintf("%s %s ?", baseField, op), []any{operand}, field+"|"+op)
					}
				}
			}
		default:
			if isNot {
				addEntry(fmt.Sprintf("NOT (%s = ?)", baseField), []any{v}, field+"|NOT =")
			} else {
				addEntry(fmt.Sprintf("%s = ?", baseField), []any{v}, field+"|=")
			}
		}
	}
	return entries
}

// BuildWhereClause constructs a SQL WHERE clause from a given where map.
// The where map is expected to be in the form:
//
//	{ "field": {"=": value}, ... }
//
// It returns the SQL string (starting with " WHERE ") and the list of arguments.
func BuildWhereClause(where map[string]any) (string, []any, error) {
	entries := buildWhereCondEntries(where)
	if len(entries) == 0 {
		return "", nil, nil
	}
	var sb strings.Builder
	args := make([]any, 0, len(entries))
	for i, entry := range entries {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		sb.WriteString(entry.cond)
		args = append(args, entry.args...)
	}
	return " WHERE " + sb.String(), args, nil
}

// BuildWhereClauseSorted constructs a SQL WHERE clause from a given where map,
// but sorts the conditions (and their arguments) by field name and operator for deterministic output.
func BuildWhereClauseSorted(where map[string]any) (string, []any, error) {
	entries := buildWhereCondEntries(where)
	// Sort entries by sortKey (insertion sort for no extra imports)
	for i := 1; i < len(entries); i++ {
		j := i
		for j > 0 && entries[j-1].sortKey > entries[j].sortKey {
			entries[j-1], entries[j] = entries[j], entries[j-1]
			j--
		}
	}
	if len(entries) == 0 {
		return "", nil, nil
	}
	var sb strings.Builder
	args := make([]any, 0, len(entries))
	for i, entry := range entries {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		sb.WriteString(entry.cond)
		args = append(args, entry.args...)
	}
	return " WHERE " + sb.String(), args, nil
}

// FormatToContext flattens an arbitrarily nested map into a flat map with keys joined by underscores.
// It replaces dots and dashes with underscores and converts keys to lowercase.
// For arrays, it uses the index as part of the key.
// It also validates that the final values do not contain dangerous characters.
func FormatToContext(input map[string]any) (map[string]string, error) {
	output := make(map[string]string, len(input))
	var flatten func(prefix string, val any) error
	flatten = func(prefix string, val any) error {
		switch v := val.(type) {
		case map[string]any:
			for k, v2 := range v {
				var keyBuilder strings.Builder
				keyBuilder.WriteString(strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, ".", "_"), "-", "_")))
				var newPrefix string
				if prefix == "" {
					newPrefix = keyBuilder.String()
				} else {
					newPrefix = prefix + "_" + keyBuilder.String()
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
		var keyBuilder strings.Builder
		keyBuilder.WriteString(strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, ".", "_"), "-", "_")))
		if err := flatten(keyBuilder.String(), v); err != nil {
			return nil, err
		}
	}
	return output, nil
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
