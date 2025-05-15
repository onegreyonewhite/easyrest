package basic

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// BasicAuthPlugin implements the AuthPlugin interface for Basic HTTP authentication.
type BasicAuthPlugin struct {
	userlist map[string]string
}

// Init initializes the BasicAuthPlugin.
// It expects a "userlist" in settings as a map[string]string.
func (p *BasicAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	ul, ok := settings["userlist"].(map[string]string)
	if !ok {
		// Attempt to convert map[string]any to map[string]string if possible
		if ulMapAny, okMapAny := settings["userlist"].(map[string]any); okMapAny {
			ul = make(map[string]string)
			for k, v := range ulMapAny {
				if vStr, okStr := v.(string); okStr {
					ul[k] = vStr
				} else {
					return nil, fmt.Errorf("userlist contains non-string password for user %s", k)
				}
			}
		} else {
			return nil, fmt.Errorf("userlist is required and must be a map[string]string or map[string]any (with string values)")
		}
	}
	if len(ul) == 0 {
		return nil, fmt.Errorf("userlist cannot be empty")
	}
	p.userlist = ul

	// Return Swagger security definition for Basic Auth
	return map[string]any{
		"type":   "http",
		"scheme": "basic",
	}, nil
}

// Authenticate validates the Authorization header for Basic authentication.
func (p *BasicAuthPlugin) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("missing headers")
	}
	authHeader, ok := headers["authorization"] // Header names are typically lowercase
	if !ok {
		authHeader, ok = headers["Authorization"] // Check original casing as a fallback
	}

	if !ok || authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return nil, fmt.Errorf("invalid authorization header format, expected Basic token")
	}
	credentialsBase64 := parts[1]

	credsBytes, err := base64.StdEncoding.DecodeString(credentialsBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding in authorization header: %w", err)
	}

	creds := string(credsBytes)
	userPass := strings.SplitN(creds, ":", 2)
	if len(userPass) != 2 {
		return nil, fmt.Errorf("invalid username:password format in authorization header")
	}

	username := userPass[0]
	password := userPass[1]

	expectedPassword, userExists := p.userlist[username]
	if !userExists || expectedPassword != password {
		return nil, fmt.Errorf("invalid username or password")
	}

	claims := map[string]any{
		"sub":   username,
		"scope": "read write",
	}
	return claims, nil
}
