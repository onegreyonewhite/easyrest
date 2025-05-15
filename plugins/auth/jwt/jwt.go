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

// --- JWTAuthPlugin: Handles direct JWT validation or apiKey flow ---

// JWTAuthPlugin implements the AuthPlugin interface for direct JWT authentication or API Key style.
type JWTAuthPlugin struct {
	jwt_secret             string
	token_type             string
	token_endpoint         string // Optional: For OAuth2 password/client_credentials flow without OIDC
	authorization_endpoint string // Optional: For OAuth2 authorization_code flow without OIDC
	flow                   string // Optional: OAuth2 flow type if token_endpoint/authorization_endpoint are set
}

// Init initializes the JWTAuthPlugin.
// If token_endpoint is provided, it generates an oauth2 security definition.
// Otherwise, it generates an apiKey security definition.
func (p *JWTAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	if s, ok := settings["jwt_secret"].(string); ok {
		p.jwt_secret = s
	}
	if tt, ok := settings["token_type"].(string); ok {
		p.token_type = tt
	} else {
		p.token_type = "Bearer" // Default token type
	}

	if _, ok := settings["token_endpoint"].(string); !ok {
		settings["token_endpoint"] = os.Getenv("ER_TOKEN_AUTHURL")
	}

	// Check for OAuth2 configuration (non-OIDC)
	if te, ok := settings["token_endpoint"].(string); ok && te != "" {
		p.token_endpoint = te
		if ae, okAE := settings["authorization_endpoint"].(string); okAE {
			p.authorization_endpoint = ae
		}
		if f, okF := settings["flow"].(string); okF {
			p.flow = f
		} else {
			// Default flow based on provided endpoints
			if p.authorization_endpoint != "" && p.token_endpoint != "" {
				p.flow = "accessCode" // Typically authorization code flow
			} else if p.token_endpoint != "" {
				p.flow = "password" // Or client_credentials, default to password
			} else {
				// This case should ideally not be hit if token_endpoint is set, but as a fallback:
				return p.getAPIKeySchema(), nil
			}
		}

		schema := map[string]any{
			"type":   "oauth2",
			"flow":   p.flow,
			"scopes": map[string]string{
				// Define scopes relevant to this JWT/OAuth2 setup if any
				// "api:read": "Read access to the API",
			},
		}
		if p.token_endpoint != "" {
			schema["tokenUrl"] = p.token_endpoint
		}
		if p.authorization_endpoint != "" {
			schema["authorizationUrl"] = p.authorization_endpoint
		}
		return schema, nil

	} else {
		// Fallback to apiKey if no specific OAuth2 endpoints are provided
		return p.getAPIKeySchema(), nil
	}
}

func (p *JWTAuthPlugin) getAPIKeySchema() map[string]any {
	return map[string]any{
		"type": "apiKey",
		"name": "Authorization",
		"in":   "header",
	}
}

// Authenticate validates the Authorization header using the JWT secret or decodes an unsigned token.
func (p *JWTAuthPlugin) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	if len(headers) == 0 {
		return nil, fmt.Errorf("missing headers")
	}
	authHeader, ok := headers["authorization"] // Header names are typically lowercase in practice when accessed via map
	if !ok {
		authHeader, ok = headers["Authorization"] // Check original casing as a fallback
	}

	if !ok || authHeader == "" {
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

	return p.parseToken(tokenStr)
}

// parseToken parses a JWT string. If p.jwt_secret is set, it validates the signature. Otherwise, it decodes without validation.
func (p *JWTAuthPlugin) parseToken(tokenStr string) (map[string]any, error) {
	if p.jwt_secret != "" {
		parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { // Assuming HMAC, adjust if other methods are primary
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(p.jwt_secret), nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				return nil, fmt.Errorf("token has invalid claims: token is expired")
			}
			return nil, err
		}
		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
			return claims, nil
		}
		return nil, fmt.Errorf("invalid token or claims type after parsing with secret")
	}

	// Decode without validation if no secret
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 { // Allow tokens with or without signature part if no secret
		return nil, fmt.Errorf("invalid token format (expected at least 2 parts for unsigned JWT)")
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

	// Check expiration for unsigned tokens too
	expTime, errExp := claims.GetExpirationTime()
	if errExp == nil && expTime != nil && expTime.Before(time.Now()) {
		return nil, errors.New("token expired")
	}
	// Allow if no expiration or not yet expired
	return claims, nil
}

// --- OIDCAuthPlugin: Handles OpenID Connect based authentication ---

// OIDCAuthPlugin implements the AuthPlugin interface for OpenID Connect authentication.
type OIDCAuthPlugin struct {
	open_id_connect_url    string
	userinfo_endpoint      string // Populated from discovery
	token_endpoint         string // Populated from discovery
	authorization_endpoint string // Populated from discovery
	token_type             string // Typically "Bearer"
	request_timeout        int16
}

// OpenIDConfiguration represents a subset of the OpenID Connect discovery document.
type OpenIDConfiguration struct {
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// Add other fields as needed, e.g., jwks_uri, scopes_supported
}

// Init initializes the OIDCAuthPlugin, performs OIDC discovery, and returns an OAuth2 Swagger security definition.
func (p *OIDCAuthPlugin) Init(settings map[string]any) (map[string]any, error) {
	oidcURL, ok := settings["open_id_connect_url"].(string)
	if !ok || oidcURL == "" {
		return nil, errors.New("open_id_connect_url is required for OIDCAuthPlugin")
	}
	p.open_id_connect_url = oidcURL

	if tt, ok := settings["token_type"].(string); ok {
		p.token_type = tt
	} else {
		p.token_type = "Bearer" // Default for OIDC
	}

	// Perform OIDC Discovery
	client := &http.Client{Timeout: time.Duration(p.request_timeout) * time.Second} // Add a timeout
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

	if p.userinfo_endpoint == "" { // Userinfo endpoint is crucial for this plugin's Authenticate method
		return nil, fmt.Errorf("userinfo_endpoint not found in OpenID configuration from %s (required for OIDCAuthPlugin)", p.open_id_connect_url)
	}
	if p.authorization_endpoint == "" {
		// While userinfo_endpoint is key for Authenticate, authorization_endpoint is key for a common OIDC flow schema.
		return nil, fmt.Errorf("authorization_endpoint not found in OpenID configuration from %s (required for OAuth2 schema)", p.open_id_connect_url)
	}

	// Generate OAuth2 Swagger Security Definition
	schema := map[string]any{
		"type":             "oauth2",
		"authorizationUrl": p.authorization_endpoint,
		"scopes":           map[string]string{},
	}

	// Determine flow based on available endpoints and settings
	flow := "implicit" // Default if only authorizationUrl
	if p.token_endpoint != "" {
		schema["tokenUrl"] = p.token_endpoint
		flow = "accessCode" // Common default if both auth and token URLs are present
	}
	// Allow override from settings
	if f, ok := settings["flow"].(string); ok && f != "" {
		flow = f
	}
	schema["flow"] = flow

	// Add ER_TOKEN_AUTHURL as a fallback for token_endpoint if not discovered and flow needs it
	if p.token_endpoint == "" && (flow == "accessCode" || flow == "password" || flow == "clientCredentials") {
		if erTokenURL := os.Getenv("ER_TOKEN_AUTHURL"); erTokenURL != "" {
			p.token_endpoint = erTokenURL
			schema["tokenUrl"] = p.token_endpoint
		}
	}

	return schema, nil
}

// Authenticate uses the userinfo_endpoint (discovered via OIDC) to validate the token.
func (p *OIDCAuthPlugin) Authenticate(headers map[string]string, method string, path string, query string) (map[string]any, error) {
	// Prioritize checking if the plugin is configured for authentication.
	if p.userinfo_endpoint == "" {
		return nil, errors.New("userinfo_endpoint not configured or not found during OIDC discovery, cannot authenticate")
	}

	if len(headers) == 0 {
		return nil, fmt.Errorf("missing headers")
	}
	authHeader, ok := headers["authorization"] // Header names are typically lowercase in practice
	if !ok {
		authHeader, ok = headers["Authorization"] // Check original casing as a fallback
	}
	if !ok || authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], p.token_type) {
		return nil, fmt.Errorf("invalid authorization header format, expected %s token", p.token_type)
	}

	return p.authenticateViaUserinfoEndpoint(authHeader)
}

// authenticateViaUserinfoEndpoint uses the OIDCAuthPlugin's userinfo_endpoint.
func (p *OIDCAuthPlugin) authenticateViaUserinfoEndpoint(originalAuthHeader string) (map[string]any, error) {
	req, err := http.NewRequest("GET", p.userinfo_endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
	}
	req.Header.Set("Authorization", originalAuthHeader) // Send the original "Bearer <token>"

	client := &http.Client{Timeout: 10 * time.Second} // Add a timeout
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
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body from userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
	}

	if strings.HasPrefix(contentType, "application/json") {
		var claims map[string]any
		if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&claims); err != nil {
			return nil, fmt.Errorf("error decoding JSON from userinfo_endpoint %s: %w", p.userinfo_endpoint, err)
		}
		return claims, nil
	} else if strings.HasPrefix(contentType, "application/jwt") {
		// If userinfo returns a JWT, this JWT plugin does not re-validate it with a secret by default.
		// It decodes it. If validation is needed, specific OIDC/JWT validation (e.g. with JWKS) would be required.
		// For now, mirror existing simple parseToken logic for unsigned.
		parts := strings.Split(string(bodyBytes), ".")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid JWT format from userinfo (expected at least 2 parts)")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("error decoding JWT payload from userinfo: %w", err)
		}
		var claims jwt.MapClaims
		if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&claims); err != nil {
			return nil, fmt.Errorf("error unmarshalling JWT payload from userinfo: %w", err)
		}
		// Optionally check expiration from this JWT
		expTime, errExp := claims.GetExpirationTime()
		if errExp == nil && expTime != nil && expTime.Before(time.Now()) {
			return nil, errors.New("JWT from userinfo_endpoint is expired")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("unsupported content type from userinfo_endpoint %s: %s. Body: %s", p.userinfo_endpoint, contentType, string(bodyBytes))
}
