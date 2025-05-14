package jwt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthPlugin implements the AuthPlugin interface for JWT authentication.
type JWTAuthPlugin struct {
	jwt_secret             string
	open_id_connect_url    string
	userinfo_endpoint      string // Populated from discovery or can be set directly if open_id_connect_url is not used (though spec implies it comes from discovery)
	token_endpoint         string // Populated from discovery
	authorization_endpoint string // Populated from discovery
	token_type             string // Renamed from tokenType
}

// OpenIDConfiguration represents a subset of the OpenID Connect discovery document.
// All field names are expected to be snake_case as per typical OIDC discovery docs.
type OpenIDConfiguration struct {
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// Add other fields as needed, e.g., jwks_uri
}

// Init initializes the plugin with the given settings and returns a Swagger security definition.
func (p *JWTAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	if s, ok := settings["jwt_secret"].(string); ok {
		p.jwt_secret = s
	}
	if tt, ok := settings["token_type"].(string); ok {
		p.token_type = tt
	} else {
		p.token_type = "Bearer" // Default token type
	}
	if token_endpoint, ok := settings["token_endpoint"].(string); !ok || token_endpoint == "" {
		settings["token_endpoint"] = os.Getenv("ER_TOKEN_AUTHURL")
	}

	if oidcURL, ok := settings["open_id_connect_url"].(string); ok && oidcURL != "" {
		p.open_id_connect_url = oidcURL
		client := &http.Client{}
		req, err := http.NewRequest("GET", p.open_id_connect_url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request to open_id_connect_url %s: %w", p.open_id_connect_url, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error fetching OpenID configuration from %s: %w", p.open_id_connect_url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("OpenID configuration request to %s failed with status %d: %s", p.open_id_connect_url, resp.StatusCode, string(bodyBytes))
		}

		var oidcConfig OpenIDConfiguration
		if err := json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
			return nil, fmt.Errorf("error decoding OpenID configuration from %s: %w", p.open_id_connect_url, err)
		}

		p.userinfo_endpoint = oidcConfig.UserinfoEndpoint
		p.token_endpoint = oidcConfig.TokenEndpoint
		p.authorization_endpoint = oidcConfig.AuthorizationEndpoint

		if p.authorization_endpoint == "" {
			return nil, fmt.Errorf("authorization_endpoint not found in OpenID configuration from %s", p.open_id_connect_url)
		}

		// Generate OAuth2 Swagger Security Definition
		schema := map[string]any{
			"type":             "oauth2",
			"flow":             "implicit", // or "accessCode" if token_endpoint is also present and desired
			"authorizationUrl": p.authorization_endpoint,
			"scopes": map[string]string{
				"openid": "OpenID Connect discovery",
			},
		}
		if p.token_endpoint != "" {
			// If we have a token endpoint, we can potentially support authorization_code or password flow.
			// For simplicity, sticking to implicit or common flows. If using authorization_code, flow should be "accessCode".
			schema["tokenUrl"] = p.token_endpoint
			// If both auth and token URLs are present, typically "accessCode" (authorization code) flow is used.
			// Or, if only tokenUrl, it could be "password" or "clientCredentials".
			// Let's assume "implicit" if only auth URL, can refine to "accessCode" if both present and that's the desired grant type.
			if schema["flow"] == "implicit" && p.token_endpoint != "" { // common to switch to accessCode if both available
				flow := settings["flow"]
				if flow != "" {
					schema["flow"] = flow
				} else {
					schema["flow"] = "accessCode"
				}
			}
		}
		return schema, nil
	} else if token_endpoint, ok := settings["token_endpoint"].(string); ok && token_endpoint != "" {
		schema := map[string]any{
			"type":     "oauth2",
			"flow":     "accessCode",
			"tokenUrl": token_endpoint,
			"scopes": map[string]string{
				"openid": "OpenID Connect discovery",
			},
		}
		flow := settings["flow"]
		if flow != "" {
			schema["flow"] = flow
		} else {
			schema["flow"] = "password"
		}
		return schema, nil
	} else {
		// Fallback to apiKey if open_id_connect_url is not provided
		schema := map[string]any{
			"type": "apiKey",
			"name": "Authorization", // Standard header name for API keys
			"in":   "header",
		}
		return schema, nil
	}
}

// Authenticate validates the Authorization header.
func (p *JWTAuthPlugin) Authenticate(authHeader string) (map[string]any, error) {
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], p.token_type) {
		return nil, fmt.Errorf("invalid authorization header format, expected %s token", p.token_type)
	}
	tokenStr := parts[1]

	if strings.TrimSpace(tokenStr) == "" {
		return nil, fmt.Errorf("invalid authorization header: token is empty after type %s", p.token_type)
	}

	if p.userinfo_endpoint != "" {
		// Pass the full original authHeader because userinfo endpoint might want the "Bearer" prefix too
		return p.authenticateViaUserinfoEndpoint(authHeader)
	}

	return p.parseToken(tokenStr)
}

// authenticateViaUserinfoEndpoint uses the already stored p.userinfo_endpoint
func (p *JWTAuthPlugin) authenticateViaUserinfoEndpoint(originalAuthHeader string) (map[string]any, error) {
	req, err := http.NewRequest("GET", p.userinfo_endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
	}
	req.Header.Set("Authorization", originalAuthHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo_endpoint %s returned non-OK status %d: %s", p.userinfo_endpoint, resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/json") {
		var claims map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			return nil, fmt.Errorf("error decoding JSON from userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
		}
		return claims, nil
	} else if strings.HasPrefix(contentType, "application/jwt") {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading JWT response body from userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
		}
		return p.parseToken(string(bodyBytes))
	}

	return nil, fmt.Errorf("unsupported content type from userinfo_endpoint %s: %s", p.userinfo_endpoint, contentType)
}

// parseToken parses a JWT string using p.jwt_secret.
func (p *JWTAuthPlugin) parseToken(tokenStr string) (map[string]any, error) {
	if p.jwt_secret != "" {
		parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(p.jwt_secret), nil
		})

		if err != nil {
			// Check for specific expiration error
			if errors.Is(err, jwt.ErrTokenExpired) {
				return nil, fmt.Errorf("token has invalid claims: token is expired")
			}
			// For other jwt.ValidationError types, the error message from the library is usually descriptive enough.
			// e.g., "token is not valid yet", "signature is invalid", "token is malformed"
			return nil, fmt.Errorf("invalid token: %w", err)
		}
		// No need to check parsedToken.Valid if err is nil, as jwt.Parse only returns err != nil if validation fails.
		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			return claims, nil
		}
		return nil, fmt.Errorf("invalid token claims type")
	}

	// Decode without validation
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format (expected 3 parts for unsigned JWT)")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding token payload: %w", err)
	}

	var claims jwt.MapClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("error unmarshalling token payload: %w", err)
	}

	expTime, err := claims.GetExpirationTime()
	if err == nil && expTime != nil && expTime.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}
