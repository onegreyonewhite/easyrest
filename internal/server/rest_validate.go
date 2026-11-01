package server

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

func compileFieldChecks(props map[string]any) (map[string]*jsonschema.Resolved, error) {
	if len(props) == 0 {
		return nil, nil
	}
	out := make(map[string]*jsonschema.Resolved, len(props))
	for name, raw := range props {
		prop, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		resolved, err := compileProperty(prop)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}
		out[name] = resolved
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func compileProperty(prop map[string]any) (*jsonschema.Resolved, error) {
	raw, err := json.Marshal(normalizeProperty(prop))
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := schema.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
}

func normalizeProperty(prop map[string]any) map[string]any {
	out := maps.Clone(prop)
	if out["x-nullable"] == true {
		delete(out, "x-nullable")
		if typ, ok := out["type"].(string); ok && typ != "" {
			out["type"] = []any{typ, "null"}
		}
	}
	if nested, ok := out["properties"].(map[string]any); ok {
		copied := make(map[string]any, len(nested))
		for key, raw := range nested {
			child, ok := raw.(map[string]any)
			if !ok {
				copied[key] = raw
				continue
			}
			copied[key] = normalizeProperty(child)
		}
		out["properties"] = copied
	}
	if items, ok := out["items"].(map[string]any); ok {
		out["items"] = normalizeProperty(items)
	}
	return out
}

func (a restTableAction) acceptWrite(w http.ResponseWriter, row map[string]any) bool {
	return a.acceptWriteFiles(w, row, nil)
}

func (a restTableAction) acceptWriteFiles(w http.ResponseWriter, row map[string]any, files []string) bool {
	if a.rejectUnknownWriteKeys(w, row) {
		return false
	}
	a.omitReadOnly(row)
	return a.checkFields(w, row, files)
}

func (a restTableAction) checkFields(w http.ResponseWriter, row map[string]any, files []string) bool {
	for _, name := range a.required {
		if _, ok := row[name]; ok {
			continue
		}
		if slices.Contains(files, name) {
			continue
		}
		http.Error(w, "missing field "+name, http.StatusBadRequest)
		return false
	}
	if len(a.checks) == 0 {
		return true
	}
	for key, value := range row {
		resolved := a.checks[key]
		if resolved == nil {
			continue
		}
		if err := resolved.Validate(value); err != nil {
			http.Error(w, "invalid field "+key, http.StatusBadRequest)
			return false
		}
	}
	return true
}

func restCreateRequired(schema map[string]any, props map[string]any, pathParams []string, filters []restQueryFilter, readOnly map[string]struct{}) []string {
	names := schemaStrings(schema["required"])
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := props[name]; !ok {
			continue
		}
		if _, ok := readOnly[name]; ok {
			continue
		}
		if slices.Contains(pathParams, name) {
			continue
		}
		if filterClaimsField(filters, name) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func filterClaimsField(filters []restQueryFilter, name string) bool {
	for _, filter := range filters {
		if filter.claim != "" && filter.field == name {
			return true
		}
	}
	return false
}

func schemaStrings(raw any) []string {
	switch values := raw.(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			name, ok := value.(string)
			if !ok {
				continue
			}
			out = append(out, name)
		}
		return out
	default:
		return nil
	}
}

func restFilterProps(props map[string]any, filters []restQueryFilter) map[string]any {
	out := make(map[string]any, len(filters))
	for _, filter := range filters {
		if strings.Contains(filter.field, "->") || filter.claim != "" {
			continue
		}
		prop, ok := props[filter.field]
		if !ok {
			continue
		}
		out[filter.field] = prop
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a restTableAction) checkFilters(w http.ResponseWriter, r *http.Request) bool {
	if len(a.checks) == 0 {
		return true
	}
	query := r.URL.Query()
	for _, filter := range a.filters {
		if filterSkipsType(filter) {
			continue
		}
		resolved := a.checks[filter.field]
		if resolved == nil {
			continue
		}
		values, ok := query[filter.name]
		if !ok || len(values) == 0 {
			continue
		}
		if filter.op == "IN" {
			for _, part := range strings.Split(values[0], ",") {
				if !validFilterValue(w, filter.name, resolved, part) {
					return false
				}
			}
			continue
		}
		if !validFilterValue(w, filter.name, resolved, values[0]) {
			return false
		}
	}
	return true
}

func filterSkipsType(filter restQueryFilter) bool {
	if filter.claim != "" || strings.Contains(filter.field, "->") {
		return true
	}
	switch filter.op {
	case "LIKE", "ILIKE", "IS":
		return true
	default:
		return false
	}
}

func validFilterValue(w http.ResponseWriter, name string, resolved *jsonschema.Resolved, raw string) bool {
	value, err := coerceFilterValue(raw, resolved)
	if err != nil || resolved.Validate(value) != nil {
		http.Error(w, "invalid filter "+name, http.StatusBadRequest)
		return false
	}
	return true
}

func coerceFilterValue(raw string, resolved *jsonschema.Resolved) (any, error) {
	switch schemaType(resolved.Schema()) {
	case "integer":
		return strconv.ParseInt(raw, 10, 64)
	case "number":
		return strconv.ParseFloat(raw, 64)
	case "boolean":
		switch raw {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, strconv.ErrSyntax
		}
	default:
		return raw, nil
	}
}

func schemaType(schema *jsonschema.Schema) string {
	if schema == nil {
		return ""
	}
	if schema.Type != "" {
		return schema.Type
	}
	for _, typ := range schema.Types {
		if typ != "null" {
			return typ
		}
	}
	return ""
}
