package server

import "log"

// openAPISecuritySchemes copies Swagger 2 security definitions into OpenAPI 3
// security scheme objects. names selects and orders the schemes.
func openAPISecuritySchemes(defs map[string]map[string]any, names []string) map[string]any {
	out := map[string]any{}
	for _, name := range names {
		schema, ok := defs[name]
		if !ok {
			continue
		}
		out[name] = openAPISecurityScheme(schema)
	}
	return out
}

func openAPISecurityScheme(def map[string]any) map[string]any {
	if def == nil {
		return map[string]any{}
	}
	switch def["type"] {
	case "basic":
		return map[string]any{"type": "http", "scheme": "basic"}
	case "http", "openIdConnect":
		return cloneSecurityScheme(def)
	case "apiKey":
		out := map[string]any{"type": "apiKey"}
		if name, ok := def["name"].(string); ok {
			out["name"] = name
		}
		if in, ok := def["in"].(string); ok {
			out["in"] = in
		}
		if description, ok := def["description"].(string); ok && description != "" {
			out["description"] = description
		}
		return out
	case "oauth2":
		if _, hasFlows := def["flows"]; hasFlows && def["flow"] == nil {
			return cloneSecurityScheme(def)
		}
		return openAPIOAuth2Scheme(def)
	default:
		return cloneSecurityScheme(def)
	}
}

func cloneSecurityScheme(def map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range def {
		out[key] = value
	}
	return out
}

func openAPIOAuth2Scheme(def map[string]any) map[string]any {
	flow, _ := def["flow"].(string)
	name, ok := openAPIFlowName(flow)
	out := map[string]any{"type": "oauth2", "flows": map[string]any{}}
	if !ok {
		if flow != "" {
			log.Printf("openapi: unknown oauth2 flow %q", flow)
		}
		return out
	}
	flowObject := map[string]any{"scopes": openAPIScopes(def["scopes"])}
	if url, ok := def["authorizationUrl"].(string); ok && url != "" {
		flowObject["authorizationUrl"] = url
	}
	if url, ok := def["tokenUrl"].(string); ok && url != "" {
		flowObject["tokenUrl"] = url
	}
	out["flows"] = map[string]any{name: flowObject}
	return out
}

func openAPIFlowName(flow string) (string, bool) {
	switch flow {
	case "accessCode":
		return "authorizationCode", true
	case "application":
		return "clientCredentials", true
	case "implicit", "password", "clientCredentials":
		return flow, true
	default:
		return "", false
	}
}

func openAPIScopes(raw any) map[string]any {
	out := map[string]any{}
	switch scopes := raw.(type) {
	case map[string]string:
		for key, value := range scopes {
			out[key] = value
		}
	case map[string]any:
		for key, value := range scopes {
			out[key] = value
		}
	}
	return out
}

// openAPIContent puts one schema under each media type. The schema value is shared.
func openAPIContent(schema any, mediaTypes ...string) map[string]any {
	content := map[string]any{}
	for _, mediaType := range mediaTypes {
		content[mediaType] = map[string]any{"schema": schema}
	}
	return content
}

const preferHeaderDescription = "Space-separated preferences. timezone is an IANA name used when formatting timestamps; an empty value falls back to default_timezone. tx is commit or rollback and changes the transaction only when db_tx_end ends in -allow-override. page_size is a positive integer: the JSON or XML page size when Range and limit are absent, and the NDJSON or CSV chunk size. Zero, negative, and non-integers are ignored. count is count=exact, count=planned, or count=estimated. Any other count value is kept on the context and is not echoed. Table retrieve and later NDJSON pages drop count. When the client omits count, db_prefer_count is copied in if it is one of those three modes. Any other token is stored on the plugin context and is not echoed."

const preferHeaderExample = "timezone=UTC tx=rollback page_size=50 count=exact"

const preferAppliedDescription = "Echo of applied preferences. tx= is the effective transaction end, commit when the client did not override it. timezone= is always present. count= is included only for exact, planned, or estimated. page_size=N is added on GET when the value was a positive integer."

const preferAppliedExample = "tx=commit count=exact timezone=UTC page_size=50"

func preferHeaderParam() map[string]any {
	return map[string]any{
		"name":        "Prefer",
		"in":          "header",
		"description": preferHeaderDescription,
		"schema":      map[string]any{"type": "string"},
		"example":     preferHeaderExample,
	}
}

func preferParameter() Parameter {
	return Parameter{
		Name:        "Prefer",
		In:          "header",
		Description: preferHeaderDescription,
		Schema:      map[string]any{"type": "string"},
		Example:     preferHeaderExample,
	}
}

func preferenceAppliedHeader() map[string]any {
	return map[string]any{
		"description": preferAppliedDescription,
		"schema":      map[string]any{"type": "string"},
		"example":     preferAppliedExample,
	}
}

func withPreferenceApplied(resp map[string]any) map[string]any {
	resp["headers"] = map[string]any{
		"Preference-Applied": preferenceAppliedHeader(),
	}
	return resp
}

func openAPIResponse(description string, schema any, mediaTypes ...string) map[string]any {
	resp := map[string]any{"description": description}
	if schema == nil || len(mediaTypes) == 0 {
		return resp
	}
	resp["content"] = openAPIContent(schema, mediaTypes...)
	return resp
}
