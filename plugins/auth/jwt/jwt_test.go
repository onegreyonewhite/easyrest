package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
func createCryptoMalformedSignedToken(claims jwt.MapClaims, correctSecret string, signingSecretToMakeItInvalid string) string {
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
	t.Run("APIKey Flow (no open_id_connect_url)", func(t *testing.T) {
		plugin := &JWTAuthPlugin{}
		settings := map[string]any{
			"jwt_secret": "mysecret",
			"token_type": "CustomAuth",
			// "userinfo_endpoint": "http://direct.com/userinfo", // Test direct userinfo if apiKey is fallback
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "mysecret", plugin.jwt_secret)
		assert.Equal(t, "CustomAuth", plugin.token_type)
		// assert.Equal(t, "http://direct.com/userinfo", plugin.userinfo_endpoint) // Check if direct userinfo is picked up

		assert.Equal(t, "apiKey", schema["type"])
		assert.Equal(t, "Authorization", schema["name"])
		assert.Equal(t, "header", schema["in"])
	})

	t.Run("OpenID Connect Flow", func(t *testing.T) {
		var mockOIDCServer *httptest.Server
		setupMockOIDCServer := func(handler http.HandlerFunc) string {
			if mockOIDCServer != nil {
				mockOIDCServer.Close()
			}
			mockOIDCServer = httptest.NewServer(handler)
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

			plugin := &JWTAuthPlugin{}
			settings := map[string]any{
				"open_id_connect_url": oidcURL,
				"jwt_secret":          "oidc_secret",
				"token_type":          "OIDCBearer",
				"flow":                "accessCode",
			}
			schema, err := plugin.Init(settings)
			require.NoError(t, err)
			require.NotNil(t, schema)

			assert.Equal(t, "oidc_secret", plugin.jwt_secret)
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

		t.Run("Discovery HTTP error", func(t *testing.T) {
			oidcURL := setupMockOIDCServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			plugin := &JWTAuthPlugin{}
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
			plugin := &JWTAuthPlugin{}
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
			plugin := &JWTAuthPlugin{}
			settings := map[string]any{"open_id_connect_url": oidcURL}
			_, err := plugin.Init(settings)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "authorization_endpoint not found")
		})

		t.Run("Discovery request creation error", func(t *testing.T) {
			plugin := &JWTAuthPlugin{}
			settings := map[string]any{"open_id_connect_url": ":::invalid-url"}
			_, err := plugin.Init(settings)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error creating request to open_id_connect_url")
		})

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
		// Initialize with snake_case setting
		plugin.Init(map[string]any{"token_type": "TestBearer"})

		tests := []struct {
			name          string
			authHeader    string
			expectedError string
		}{
			{"missing header", "", "missing authorization header"},
			{"malformed header - no space", "TestBearertoken", "invalid authorization header format, expected TestBearer token"},
			{"malformed header - token part has space", "TestBearer token extra", "invalid token format (expected 3 parts for unsigned JWT)"},
			{"wrong token type", "Basic sometoken", "invalid authorization header format, expected TestBearer token"},
			{"empty token string after type", "TestBearer ", "invalid authorization header: token is empty after type TestBearer"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := plugin.Authenticate(tt.authHeader)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			})
		}
		t.Run("empty token with default Bearer", func(t *testing.T) {
			p := &JWTAuthPlugin{}
			p.Init(map[string]any{}) // uses default "Bearer"
			_, err := p.Authenticate("Bearer ")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid authorization header: token is empty after type Bearer")
		})
	})

	t.Run("Direct Token Parsing (no open_id_connect_url)", func(t *testing.T) {
		t.Run("Signed Token - HS256", func(t *testing.T) {
			plugin := &JWTAuthPlugin{}
			plugin.Init(map[string]any{"jwt_secret": testSecret, "token_type": "Bearer"})

			claims, err := plugin.Authenticate("Bearer " + validSignedToken)
			require.NoError(t, err)
			assert.Equal(t, "123", claims["user_id"])

			_, err = plugin.Authenticate("Bearer " + expiredSignedToken)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token has invalid claims: token is expired")

			pluginWrongSecret := &JWTAuthPlugin{}
			pluginWrongSecret.Init(map[string]any{"jwt_secret": "wrong-secret", "token_type": "Bearer"})
			_, err = pluginWrongSecret.Authenticate("Bearer " + validSignedToken)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signature is invalid")

			cryptoMalformedToken := createCryptoMalformedSignedToken(validClaims, testSecret, altTestSecret)
			_, err = plugin.Authenticate("Bearer " + cryptoMalformedToken)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signature is invalid")

			parts := strings.Split(validSignedToken, ".")
			require.Len(t, parts, 3)
			structurallyMalformedToken := parts[0] + "." + parts[1] + ".not-base64-sig%"
			_, err = plugin.Authenticate("Bearer " + structurallyMalformedToken)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "illegal base64 data")

			rs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
			rs256Payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"rs256user"}`))
			rs256TokenString := rs256Header + "." + rs256Payload + ".fakesig"
			_, err = plugin.Authenticate("Bearer " + rs256TokenString)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected signing method: RS256")
		})

		t.Run("Unsigned Token (no jwt_secret in plugin)", func(t *testing.T) {
			plugin := &JWTAuthPlugin{}
			plugin.Init(map[string]any{"token_type": "Bearer"})

			claims, err := plugin.Authenticate("Bearer " + unsignedTokenValid)
			require.NoError(t, err)
			assert.Equal(t, "789", claims["user_id"])
			assert.Equal(t, "guest", claims["role"])

			_, err = plugin.Authenticate("Bearer " + "part1.part2")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid token format (expected 3 parts for unsigned JWT)")

			badBase64PayloadToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + ".%%payload%%."
			_, err = plugin.Authenticate("Bearer " + badBase64PayloadToken)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error decoding token payload: illegal base64 data")

			nonJSONPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-json-at-all")) + "."
			_, err = plugin.Authenticate("Bearer " + nonJSONPayload)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error unmarshalling token payload")
		})
	})

	t.Run("Userinfo Endpoint Flow (via OpenID Discovery)", func(t *testing.T) {
		var mockUserInfoServer *httptest.Server
		var mockOIDCServer *httptest.Server

		// Mock for the actual userinfo endpoint
		setupMockUserInfoServer := func(handler http.HandlerFunc) string {
			if mockUserInfoServer != nil {
				mockUserInfoServer.Close()
			}
			mockUserInfoServer = httptest.NewServer(handler)
			return mockUserInfoServer.URL
		}

		// Mock for the OIDC discovery endpoint
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

		t.Run("Userinfo returns JSON valid", func(t *testing.T) {
			mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				require.Equal(t, "Bearer user-token", auth)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintln(w, `{"user_id":"json_user","scope":"read"}`)
			})
			discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
			mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

			plugin := &JWTAuthPlugin{}
			_, err := plugin.Init(map[string]any{"open_id_connect_url": mockedOIDCURL, "token_type": "Bearer"})
			require.NoError(t, err)

			claims, err := plugin.Authenticate("Bearer user-token")
			require.NoError(t, err)
			assert.Equal(t, "json_user", claims["user_id"])
		})

		// Add more tests for userinfo flow: invalid JSON, JWT from userinfo, non-OK status, etc.
		// These would be similar to the previous Userinfo Endpoint Flow tests, but the plugin
		// is initialized via open_id_connect_url which then points to the userinfo mock.

		t.Run("Userinfo returns JWT (signed, plugin has jwt_secret)", func(t *testing.T) {
			returnedToken, _ := createSignedToken(jwt.MapClaims{"sub": "jwt_from_endpoint_signed", "exp": time.Now().Add(time.Hour).Unix()}, testSecret, jwt.SigningMethodHS256)
			mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/jwt")
				fmt.Fprint(w, returnedToken)
			})
			discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
			mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

			plugin := &JWTAuthPlugin{}
			_, err := plugin.Init(map[string]any{
				"open_id_connect_url": mockedOIDCURL,
				"jwt_secret":          testSecret,
				"token_type":          "Bearer",
			})
			require.NoError(t, err)

			claims, err := plugin.Authenticate("Bearer user-token-for-jwt-response")
			require.NoError(t, err)
			assert.Equal(t, "jwt_from_endpoint_signed", claims["sub"])
		})

		t.Run("Userinfo returns non-OK status from userinfo_endpoint", func(t *testing.T) {
			mockedUserinfoURL := setupMockUserInfoServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Auth failed at actual userinfo endpoint")
			})
			discoveryDoc := OpenIDConfiguration{UserinfoEndpoint: mockedUserinfoURL, AuthorizationEndpoint: "http://dummy/auth"}
			mockedOIDCURL := setupMockOIDCServer(discoveryDoc)

			plugin := &JWTAuthPlugin{}
			_, err := plugin.Init(map[string]any{"open_id_connect_url": mockedOIDCURL, "token_type": "Bearer"})
			require.NoError(t, err)

			_, err = plugin.Authenticate("Bearer user-token")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "userinfo_endpoint")
			assert.Contains(t, err.Error(), "returned non-OK status 401: Auth failed at actual userinfo endpoint")
		})

	})
}
