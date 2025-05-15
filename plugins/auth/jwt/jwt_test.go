package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSecret    = "test-secret-key"
	altTestSecret = "alternative-test-secret-key"
)

// Helper function to create a signed JWT token
func createSignedToken(claims jwt.MapClaims, secret string, method jwt.SigningMethod) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString([]byte(secret))
}

// Helper function to create a malformed signed token (structurally valid, but crypto signature is wrong)
func createCryptoMalformedSignedToken(claims jwt.MapClaims, signingSecretToMakeItInvalid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString([]byte(signingSecretToMakeItInvalid)) // Sign with a different secret
	return ss
}

// Helper function to create an unsigned token string (header.payload.signature)
func createUnsignedToken(header, payload string) string {
	return fmt.Sprintf("%s.%s.", // Empty signature part
		base64.RawURLEncoding.EncodeToString([]byte(header)),
		base64.RawURLEncoding.EncodeToString([]byte(payload)),
	)
}

func TestJWTAuthPlugin_Init(t *testing.T) {
	t.Run("APIKey Flow (default)", func(t *testing.T) {
		plugin := &JWTAuthPlugin{}
		settings := map[string]any{
			"jwt_secret": "mysecret",
			"token_type": "CustomAuth",
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "mysecret", plugin.jwt_secret)
		assert.Equal(t, "CustomAuth", plugin.token_type)

		assert.Equal(t, "apiKey", schema["type"])
		assert.Equal(t, "Authorization", schema["name"])
		assert.Equal(t, "header", schema["in"])
	})

	t.Run("OAuth2 Flow with token_endpoint", func(t *testing.T) {
		plugin := &JWTAuthPlugin{}
		settings := map[string]any{
			"token_endpoint": "http://localhost/token",
			"token_type":     "Bearer",
			"flow":           "password", // Explicitly set flow
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "http://localhost/token", plugin.token_endpoint)
		assert.Equal(t, "password", plugin.flow)

		assert.Equal(t, "oauth2", schema["type"])
		assert.Equal(t, "password", schema["flow"])
		assert.Equal(t, "http://localhost/token", schema["tokenUrl"])
		assert.Nil(t, schema["authorizationUrl"]) // Should not be set if not provided
	})

	t.Run("OAuth2 Flow with token_endpoint and authorization_endpoint (default to accessCode)", func(t *testing.T) {
		plugin := &JWTAuthPlugin{}
		settings := map[string]any{
			"token_endpoint":         "http://localhost/token",
			"authorization_endpoint": "http://localhost/auth",
			"token_type":             "Bearer",
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "http://localhost/token", plugin.token_endpoint)
		assert.Equal(t, "http://localhost/auth", plugin.authorization_endpoint)
		assert.Equal(t, "accessCode", plugin.flow)

		assert.Equal(t, "oauth2", schema["type"])
		assert.Equal(t, "accessCode", schema["flow"])
		assert.Equal(t, "http://localhost/token", schema["tokenUrl"])
		assert.Equal(t, "http://localhost/auth", schema["authorizationUrl"])
	})

	t.Run("OAuth2 Flow with only authorization_endpoint (should fallback to apiKey)", func(t *testing.T) {
		// This scenario is a bit odd for OAuth2, usually tokenUrl is key for server-side flows.
		// Current JWTAuthPlugin.Init logic falls back to apiKey if token_endpoint is missing for an oauth2 setup.
		plugin := &JWTAuthPlugin{}
		settings := map[string]any{
			"authorization_endpoint": "http://localhost/auth", // No token_endpoint
			"flow":                   "implicit",              // User might try to force implicit
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		assert.Equal(t, "apiKey", schema["type"]) // Fallback because token_endpoint is primary trigger for oauth2 in JWTAuthPlugin
	})
}

func TestOIDCAuthPlugin_Init(t *testing.T) {
	var mockOIDCServer *httptest.Server
	setupMockOIDCServer := func(handler http.HandlerFunc) string {
		if mockOIDCServer != nil {
			mockOIDCServer.Close()
		}
		mockOIDCServer = httptest.NewServer(http.HandlerFunc(handler)) // Ensure http.HandlerFunc is used
		return mockOIDCServer.URL
	}
	t.Cleanup(func() {
		if mockOIDCServer != nil {
			mockOIDCServer.Close()
		}
	})

	t.Run("Successful discovery", func(t *testing.T) {
		discoveryDoc := OpenIDConfiguration{
			UserinfoEndpoint:      "http://localhost/userinfo_discovered",
			TokenEndpoint:         "http://localhost/token_discovered",
			AuthorizationEndpoint: "http://localhost/auth_discovered",
		}
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discoveryDoc)
		})

		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{
			"open_id_connect_url": oidcURL,
			"token_type":          "OIDCBearer",
			"flow":                "accessCode", // Explicit flow
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)

		assert.Equal(t, "OIDCBearer", plugin.token_type)
		assert.Equal(t, oidcURL, plugin.open_id_connect_url)
		assert.Equal(t, discoveryDoc.UserinfoEndpoint, plugin.userinfo_endpoint)
		assert.Equal(t, discoveryDoc.TokenEndpoint, plugin.token_endpoint)
		assert.Equal(t, discoveryDoc.AuthorizationEndpoint, plugin.authorization_endpoint)

		assert.Equal(t, "oauth2", schema["type"])
		assert.Equal(t, "accessCode", schema["flow"])
		assert.Equal(t, discoveryDoc.AuthorizationEndpoint, schema["authorizationUrl"])
		assert.Equal(t, discoveryDoc.TokenEndpoint, schema["tokenUrl"])
		assert.NotNil(t, schema["scopes"])
	})

	t.Run("Successful discovery - default flow (implicit if only auth_url)", func(t *testing.T) {
		discoveryDoc := OpenIDConfiguration{
			UserinfoEndpoint:      "http://localhost/userinfo_implicit",
			AuthorizationEndpoint: "http://localhost/auth_implicit", // No TokenEndpoint
		}
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discoveryDoc)
		})
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{"open_id_connect_url": oidcURL}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		assert.Equal(t, "implicit", schema["flow"])
		assert.Equal(t, discoveryDoc.AuthorizationEndpoint, schema["authorizationUrl"])
		assert.Nil(t, schema["tokenUrl"])
	})

	t.Run("Successful discovery - with ER_TOKEN_AUTHURL fallback", func(t *testing.T) {
		discoveryDoc := OpenIDConfiguration{
			UserinfoEndpoint:      "http://localhost/userinfo_er_fallback",
			AuthorizationEndpoint: "http://localhost/auth_er_fallback", // No TokenEndpoint from discovery
		}
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discoveryDoc)
		})

		// Set env var for fallback
		testTokenURL := "http://envvar.com/token"
		os.Setenv("ER_TOKEN_AUTHURL", testTokenURL)
		t.Cleanup(func() { os.Unsetenv("ER_TOKEN_AUTHURL") })

		plugin := &OIDCAuthPlugin{}
		// Explicitly ask for a flow that needs tokenUrl to trigger fallback logic
		settings := map[string]any{"open_id_connect_url": oidcURL, "flow": "accessCode"}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		assert.Equal(t, "accessCode", schema["flow"])
		assert.Equal(t, testTokenURL, schema["tokenUrl"])
		assert.Equal(t, testTokenURL, plugin.token_endpoint) // Check if plugin field also updated
	})

	t.Run("Discovery HTTP error", func(t *testing.T) {
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{"open_id_connect_url": oidcURL}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OpenID configuration request to")
		assert.Contains(t, err.Error(), "failed with status 500")
	})

	t.Run("Discovery invalid JSON", func(t *testing.T) {
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "not valid json")
		})
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{"open_id_connect_url": oidcURL}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decoding OpenID configuration")
	})

	t.Run("Discovery missing authorization_endpoint", func(t *testing.T) {
		discoveryDoc := OpenIDConfiguration{
			UserinfoEndpoint: "http://localhost/userinfo_discovered",
			// AuthorizationEndpoint is missing
		}
		oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discoveryDoc)
		})
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{"open_id_connect_url": oidcURL}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization_endpoint not found")
	})

	t.Run("Discovery request creation error", func(t *testing.T) {
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{"open_id_connect_url": ":::invalid-url"}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error creating request to open_id_connect_url")
	})

	t.Run("Missing open_id_connect_url setting", func(t *testing.T) {
		plugin := &OIDCAuthPlugin{}
		settings := map[string]any{}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "open_id_connect_url is required for OIDCAuthPlugin")
	})
}

func TestJWTAuthPlugin_Authenticate(t *testing.T) {
	validClaims := jwt.MapClaims{"user_id": "123", "exp": time.Now().Add(time.Hour * 1).Unix()}
	expiredClaims := jwt.MapClaims{"user_id": "123", "exp": time.Now().Add(-time.Hour * 1).Unix()}

	validSignedToken, _ := createSignedToken(validClaims, testSecret, jwt.SigningMethodHS256)
	expiredSignedToken, _ := createSignedToken(expiredClaims, testSecret, jwt.SigningMethodHS256)

	unsignedTokenValid := createUnsignedToken(`{"alg":"none"}`, `{"user_id":"789","role":"guest"}`)

	t.Run("Header Parsing", func(t *testing.T) {
		plugin := &JWTAuthPlugin{}
		plugin.Init(map[string]any{"token_type": "TestBearer"})

		tests := []struct {
			name          string
			authHeaderVal string
			tokenType     string
			expectedError string
		}{
			{"missing header", "", "TestBearer", "missing headers"},
			{"nil headers map", "", "TestBearer", "missing headers"},
			{"malformed header - no space", "TestBearertoken", "TestBearer", "invalid authorization header format, expected TestBearer token"},
			{"malformed header - token part has space", "TestBearer token extra", "TestBearer", "invalid token format (expected at least 2 parts for unsigned JWT)"},
			{"wrong token type", "Basic sometoken", "TestBearer", "invalid authorization header format, expected TestBearer token"},
			{"empty token string after type", "TestBearer ", "TestBearer", "invalid authorization header: token is empty after type TestBearer"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := &JWTAuthPlugin{}
				p.Init(map[string]any{"token_type": tt.tokenType})

				headersMap := map[string]string{}
				if tt.name == "nil headers map" {
					headersMap = nil
				} else if tt.authHeaderVal != "" {
					headersMap["Authorization"] = tt.authHeaderVal
				}

				// Pass dummy values for method, path, query as they are ignored by current plugin logic
				_, err := p.Authenticate(headersMap, "GET", "/test", "param=val")
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			})
		}
		t.Run("empty token with default Bearer", func(t *testing.T) {
			p := &JWTAuthPlugin{}
			p.Init(map[string]any{})
			_, err := p.Authenticate(map[string]string{"Authorization": "Bearer "}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid authorization header: token is empty after type Bearer")
		})
	})

	t.Run("Direct Token Parsing", func(t *testing.T) {
		t.Run("Signed Token - HS256", func(t *testing.T) {
			plugin := &JWTAuthPlugin{}
			plugin.Init(map[string]any{"jwt_secret": testSecret, "token_type": "Bearer"})

			claims, err := plugin.Authenticate(map[string]string{"Authorization": "Bearer " + validSignedToken}, "GET", "/test", "param=val")
			require.NoError(t, err)
			assert.Equal(t, "123", claims["user_id"])

			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + expiredSignedToken}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token has invalid claims: token is expired")

			pluginWrongSecret := &JWTAuthPlugin{}
			pluginWrongSecret.Init(map[string]any{"jwt_secret": "wrong-secret", "token_type": "Bearer"})
			_, err = pluginWrongSecret.Authenticate(map[string]string{"Authorization": "Bearer " + validSignedToken}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token signature is invalid: signature is invalid")

			cryptoMalformedToken := createCryptoMalformedSignedToken(validClaims, altTestSecret)
			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + cryptoMalformedToken}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token signature is invalid: signature is invalid")

			parts := strings.Split(validSignedToken, ".")
			require.Len(t, parts, 3)
			structurallyMalformedToken := parts[0] + "." + parts[1] + ".not-base64-sig%"
			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + structurallyMalformedToken}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token is malformed: could not base64 decode signature: illegal base64 data at input byte 14")

			rs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
			rs256Payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"rs256user"}`))
			rs256TokenString := rs256Header + "." + rs256Payload + ".fakesig"
			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + rs256TokenString}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected signing method: RS256")
		})

		t.Run("Unsigned Token (no jwt_secret in plugin)", func(t *testing.T) {
			plugin := &JWTAuthPlugin{}
			plugin.Init(map[string]any{"token_type": "Bearer"})

			claims, err := plugin.Authenticate(map[string]string{"Authorization": "Bearer " + unsignedTokenValid}, "GET", "/test", "param=val")
			require.NoError(t, err)
			assert.Equal(t, "789", claims["user_id"])
			assert.Equal(t, "guest", claims["role"])

			_, _ = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + "part1.part2"}, "GET", "/test", "param=val")

			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + "onlyonepart"}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid token format (expected at least 2 parts for unsigned JWT)")

			badBase64PayloadToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + ".%%payload%%."
			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + badBase64PayloadToken}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error decoding token payload: illegal base64 data at input byte 0")

			nonJSONPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-json-at-all")) + "."
			_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer " + nonJSONPayload}, "GET", "/test", "param=val")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error unmarshalling token payload")
		})
	})
}

func TestOIDCAuthPlugin_Authenticate(t *testing.T) {
	var mockUserInfoServer *httptest.Server
	var mockOIDCServer *httptest.Server

	setupMockUserInfoServer := func(handler http.HandlerFunc) string {
		if mockUserInfoServer != nil {
			mockUserInfoServer.Close()
		}
		mockUserInfoServer = httptest.NewServer(http.HandlerFunc(handler))
		return mockUserInfoServer.URL
	}

	setupMockOIDCServer := func(oidcDoc OpenIDConfiguration) string {
		if mockOIDCServer != nil {
			mockOIDCServer.Close()
		}
		mockOIDCServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(oidcDoc)
		}))
		return mockOIDCServer.URL
	}

	t.Cleanup(func() {
		if mockUserInfoServer != nil {
			mockUserInfoServer.Close()
		}
		if mockOIDCServer != nil {
			mockOIDCServer.Close()
		}
	})

	t.Run("Header Parsing", func(t *testing.T) {
		plugin := &OIDCAuthPlugin{}
		mockOIDCURL := setupMockOIDCServer(OpenIDConfiguration{UserinfoEndpoint: "http://dummy", AuthorizationEndpoint: "http://dummy/auth"})
		plugin.Init(map[string]any{"open_id_connect_url": mockOIDCURL, "token_type": "OidcBearer"})

		tests := []struct {
			name          string
			authHeaderVal string
			tokenType     string
			expectedError string
		}{
			{"missing header", "", "OidcBearer", "missing headers"},
			{"nil headers map", "", "OidcBearer", "missing headers"},
			{"malformed header - no space", "OidcBearertoken", "OidcBearer", "invalid authorization header format, expected OidcBearer token"},
			{"wrong token type", "Basic sometoken", "OidcBearer", "invalid authorization header format, expected OidcBearer token"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				headersMap := map[string]string{}
				if tt.name == "nil headers map" {
					headersMap = nil
				} else if tt.authHeaderVal != "" {
					headersMap["Authorization"] = tt.authHeaderVal
				}
				// Pass dummy values for method, path, query
				_, err := plugin.Authenticate(headersMap, "GET", "/test", "param=val")
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			})
		}
	})

	t.Run("Userinfo returns JSON valid", func(t *testing.T) {
		mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			require.Equal(t, "Bearer user-token", auth)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"user_id":"json_user","scope":"read"}`)
		})
		discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
		mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

		plugin := &OIDCAuthPlugin{}
		_, err := plugin.Init(map[string]any{"open_id_connect_url": mockedOIDCURL, "token_type": "Bearer"})
		require.NoError(t, err)

		claims, err := plugin.Authenticate(map[string]string{"Authorization": "Bearer user-token"}, "GET", "/test", "param=val")
		require.NoError(t, err)
		assert.Equal(t, "json_user", claims["user_id"])
	})

	t.Run("Userinfo returns JWT (unsigned, plugin does not have jwt_secret)", func(t *testing.T) {
		returnedTokenPayload := `{"sub":"jwt_from_endpoint_unsigned","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`
		returnedToken := createUnsignedToken(`{"alg":"none"}`, returnedTokenPayload)

		mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/jwt")
			fmt.Fprint(w, returnedToken)
		})
		discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
		mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

		plugin := &OIDCAuthPlugin{}
		_, err := plugin.Init(map[string]any{
			"open_id_connect_url": mockedOIDCURL,
			"token_type":          "Bearer",
		})
		require.NoError(t, err)

		claims, err := plugin.Authenticate(map[string]string{"Authorization": "Bearer user-token-for-jwt-response"}, "GET", "/test", "param=val")
		require.NoError(t, err)
		assert.Equal(t, "jwt_from_endpoint_unsigned", claims["sub"])
	})

	t.Run("Userinfo returns non-OK status from userinfo_endpoint", func(t *testing.T) {
		mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Auth failed at actual userinfo endpoint")
		})
		discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
		mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

		plugin := &OIDCAuthPlugin{}
		_, err := plugin.Init(map[string]any{"open_id_connect_url": mockedOIDCURL, "token_type": "Bearer"})
		require.NoError(t, err)

		_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer user-token"}, "GET", "/test", "param=val")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "userinfo_endpoint")
		assert.Contains(t, err.Error(), "returned non-OK status 401: Auth failed at actual userinfo endpoint")
	})

	t.Run("Authenticate called before successful Init (missing userinfo_endpoint)", func(t *testing.T) {
		plugin := &OIDCAuthPlugin{} // Not initialized, so userinfo_endpoint is empty
		// Pass dummy headers, method, path, query. Error should be due to missing userinfo_endpoint.
		_, err := plugin.Authenticate(map[string]string{"Authorization": "Bearer some-token"}, "GET", "/test", "param=val")
		require.Error(t, err)
		assert.EqualError(t, err, "userinfo_endpoint not configured or not found during OIDC discovery, cannot authenticate")
	})

	t.Run("Userinfo returns unsupported content type", func(t *testing.T) {
		mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "this is plain text")
		})
		discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
		mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

		plugin := &OIDCAuthPlugin{}
		_, err := plugin.Init(map[string]any{"open_id_connect_url": mockedOIDCURL})
		require.NoError(t, err)

		_, err = plugin.Authenticate(map[string]string{"Authorization": "Bearer user-token"}, "GET", "/test", "param=val")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported content type from userinfo_endpoint")
		assert.Contains(t, err.Error(), "text/plain")
	})
}
