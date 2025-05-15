package basic

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicAuthPlugin_Init(t *testing.T) {
	t.Run("Successful initialization", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{
			"userlist": map[string]string{
				"user1": "pass1",
				"user2": "pass2",
			},
		}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "http", schema["type"])
		assert.Equal(t, "basic", schema["scheme"])
		assert.Equal(t, settings["userlist"], plugin.userlist)
	})

	t.Run("Successful initialization with map[string]any userlist", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{
			"userlist": map[string]any{
				"user1": "pass1",
				"user2": "pass2",
			},
		}
		expectedUserlist := map[string]string{"user1": "pass1", "user2": "pass2"}
		schema, err := plugin.Init(settings)
		require.NoError(t, err)
		require.NotNil(t, schema)
		assert.Equal(t, "http", schema["type"])
		assert.Equal(t, "basic", schema["scheme"])
		assert.Equal(t, expectedUserlist, plugin.userlist)
	})

	t.Run("Initialization with non-string password in map[string]any userlist", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{
			"userlist": map[string]any{
				"user1": 123, // Non-string password
			},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "userlist contains non-string password for user user1")
	})

	t.Run("Initialization with missing userlist", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "userlist is required and must be a map[string]string or map[string]any (with string values)")
	})

	t.Run("Initialization with invalid userlist type", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{
			"userlist": "not-a-map",
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "userlist is required and must be a map[string]string or map[string]any (with string values)")
	})

	t.Run("Initialization with empty userlist", func(t *testing.T) {
		plugin := &BasicAuthPlugin{}
		settings := map[string]any{
			"userlist": map[string]string{},
		}
		_, err := plugin.Init(settings)
		require.Error(t, err)
		assert.EqualError(t, err, "userlist cannot be empty")
	})
}

func TestBasicAuthPlugin_Authenticate(t *testing.T) {
	plugin := &BasicAuthPlugin{}
	userlist := map[string]string{
		"testuser":  "testpass",
		"testuser2": "anotherpass",
	}
	_, err := plugin.Init(map[string]any{"userlist": userlist})
	require.NoError(t, err)

	validCreds := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))

	t.Run("Successful authentication", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Basic " + validCreds,
		}
		claims, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "testuser", claims["sub"])
		assert.Equal(t, "read write", claims["scope"])
	})

	t.Run("Successful authentication - lowercase header", func(t *testing.T) {
		headers := map[string]string{
			"authorization": "Basic " + validCreds,
		}
		claims, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "testuser", claims["sub"])
		assert.Equal(t, "read write", claims["scope"])
	})

	t.Run("Missing headers", func(t *testing.T) {
		_, err := plugin.Authenticate(nil, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "missing headers")

		_, err = plugin.Authenticate(map[string]string{"X-API-Key": ""}, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "missing authorization header")
	})

	t.Run("Missing Authorization header", func(t *testing.T) {
		headers := map[string]string{
			"OtherHeader": "value",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "missing authorization header")
	})

	t.Run("Empty Authorization header", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "missing authorization header")
	})

	t.Run("Invalid Authorization header format - not Basic", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Bearer " + validCreds,
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid authorization header format, expected Basic token")
	})

	t.Run("Invalid Authorization header format - no space", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Basic" + validCreds,
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid authorization header format, expected Basic token")
	})

	t.Run("Invalid base64 encoding", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": "Basic notbase64!@#",
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64 encoding in authorization header")
	})

	t.Run("Invalid username:password format - no colon", func(t *testing.T) {
		noColonCreds := base64.StdEncoding.EncodeToString([]byte("testuserpass"))
		headers := map[string]string{
			"Authorization": "Basic " + noColonCreds,
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid username:password format in authorization header")
	})

	t.Run("Invalid username", func(t *testing.T) {
		invalidUserCreds := base64.StdEncoding.EncodeToString([]byte("wronguser:testpass"))
		headers := map[string]string{
			"Authorization": "Basic " + invalidUserCreds,
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("Invalid password", func(t *testing.T) {
		invalidPassCreds := base64.StdEncoding.EncodeToString([]byte("testuser:wrongpass"))
		headers := map[string]string{
			"Authorization": "Basic " + invalidPassCreds,
		}
		_, err := plugin.Authenticate(headers, "GET", "/path", "query=param")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("Password with colon in it", func(t *testing.T) {
		// Let's add a user with a colon in the password
		pluginWithColonPass := &BasicAuthPlugin{}
		colonPassList := map[string]string{
			"usercolpass": "pass:word",
		}
		_, initErr := pluginWithColonPass.Init(map[string]any{"userlist": colonPassList})
		require.NoError(t, initErr)

		credsWithColonInPass := base64.StdEncoding.EncodeToString([]byte("usercolpass:pass:word"))
		headers := map[string]string{
			"Authorization": "Basic " + credsWithColonInPass,
		}
		claims, err := pluginWithColonPass.Authenticate(headers, "GET", "/path", "query")
		require.NoError(t, err)
		assert.Equal(t, "usercolpass", claims["sub"])
	})
}
