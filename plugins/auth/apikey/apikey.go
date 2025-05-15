package apikey

import (
	"fmt"
	"strings"
)

// APIKeyAuthPlugin implements the AuthPlugin interface for API Key authentication.
type APIKeyAuthPlugin struct {
	validKeys  map[string]struct{} // Using a map for efficient lookup
	headerName string
}

// Init initializes the APIKeyAuthPlugin.
// It expects "keys" in settings as a []string and optionally "header_name" as string.
func (p *APIKeyAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	keysSetting, ok := settings["keys"]
	if !ok {
		return nil, fmt.Errorf("keys setting is required and must be a []string")
	}

	keysSlice, ok := keysSetting.([]string)
	if !ok {
		// Attempt to convert []any to []string
		if keysAnySlice, okAny := keysSetting.([]any); okAny {
			keysSlice = make([]string, len(keysAnySlice))
			for i, v := range keysAnySlice {
				if vStr, okStr := v.(string); okStr {
					keysSlice[i] = vStr
				} else {
					return nil, fmt.Errorf("keys array contains non-string element at index %d", i)
				}
			}
		} else {
			return nil, fmt.Errorf("keys setting must be a []string or []any (with string elements)")
		}
	}

	if len(keysSlice) == 0 {
		return nil, fmt.Errorf("keys list cannot be empty")
	}

	p.validKeys = make(map[string]struct{}, len(keysSlice))
	for _, key := range keysSlice {
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("API key cannot be empty or just whitespace")
		}
		p.validKeys[key] = struct{}{}
	}

	p.headerName = "X-API-Key" // Default header name
	if hn, ok := settings["header_name"].(string); ok && strings.TrimSpace(hn) != "" {
		p.headerName = hn
	}

	// Return Swagger security definition for API Key Auth
	return map[string]any{
		"type": "apiKey",
		"name": p.headerName,
		"in":   "header",
	}, nil
}

// Authenticate validates the API key from the configured header.
func (p *APIKeyAuthPlugin) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("missing headers")
	}

	// Try to find the header, being case-insensitive for the key but respecting plugin's configured case for lookup
	apiKey := ""
	found := false
	for k, v := range headers {
		if strings.EqualFold(k, p.headerName) {
			apiKey = v
			found = true
			break
		}
	}

	if !found || strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("missing or empty API key in header %s", p.headerName)
	}

	if _, isValid := p.validKeys[apiKey]; !isValid {
		return nil, fmt.Errorf("invalid API key")
	}

	claims := map[string]any{
		"sub":   apiKey,
		"scope": "read write", // As per user request
	}
	return claims, nil
}
